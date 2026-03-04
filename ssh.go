// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/creack/pty"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"tailscale.com/tsnet"
)

// sshServer runs an SSH server on the tsnet interface, allowing tailnet
// peers to open shells inside the container via nsenter.
type sshServer struct {
	tsnetSrv *tsnet.Server
	hostKey  gossh.Signer
	pid      int // container init PID for nsenter
}

// newSSHServer creates an SSH server that will listen on the tsnet interface.
// It derives the container PID from nsPath and loads or generates an ED25519
// host key in stateDir.
func newSSHServer(srv *tsnet.Server, nsPath string, stateDir string) (*sshServer, error) {
	pid, err := containerPIDFromNSPath(nsPath)
	if err != nil {
		return nil, fmt.Errorf("resolving container PID: %w", err)
	}

	hostKey, err := loadOrGenerateHostKey(stateDir)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}

	return &sshServer{
		tsnetSrv: srv,
		hostKey:  hostKey,
		pid:      pid,
	}, nil
}

// run starts the SSH server, listening on :22 of the tsnet interface.
// It blocks until ctx is cancelled.
func (s *sshServer) run(ctx context.Context) error {
	ln, err := s.tsnetSrv.Listen("tcp", ":22")
	if err != nil {
		return fmt.Errorf("listen :22: %w", err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConn(ctx, nc)
	}
}

// handleConn performs the SSH handshake, identifies the peer via WhoIs,
// and dispatches session channels.
func (s *sshServer) handleConn(ctx context.Context, nc net.Conn) {
	defer nc.Close()

	config := &gossh.ServerConfig{
		NoClientAuth: true,
	}
	config.AddHostKey(s.hostKey)

	sconn, chans, reqs, err := gossh.NewServerConn(nc, config)
	if err != nil {
		log.Printf("SSH handshake failed from %s: %v", nc.RemoteAddr(), err)
		return
	}
	defer sconn.Close()

	// Identify the tailnet peer.
	lc, err := s.tsnetSrv.LocalClient()
	if err != nil {
		log.Printf("SSH: failed to get local client: %v", err)
		return
	}
	who, err := lc.WhoIs(ctx, nc.RemoteAddr().String())
	if err != nil {
		log.Printf("SSH: WhoIs failed for %s: %v", nc.RemoteAddr(), err)
		return
	}
	peerLogin := who.UserProfile.LoginName
	peerNode := who.Node.Name
	log.Printf("SSH session from %s (%s)", peerLogin, peerNode)

	// Discard global requests (keepalives, etc).
	go gossh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(gossh.UnknownChannelType, "only session channels are supported")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			log.Printf("SSH: failed to accept channel: %v", err)
			continue
		}
		go s.handleSession(ctx, ch, reqs)
	}
}

// handleSession processes requests on an SSH session channel: pty-req,
// window-change, env, shell, and exec. Commands are run via nsenter into
// the container's namespaces.
func (s *sshServer) handleSession(ctx context.Context, ch gossh.Channel, reqs <-chan *gossh.Request) {
	defer ch.Close()

	var (
		ptmx     *os.File
		winSize  *pty.Winsize
		envVars  []string
	)

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			p, err := parsePtyReq(req.Payload)
			if err != nil {
				log.Printf("SSH: invalid pty-req: %v", err)
				req.Reply(false, nil)
				continue
			}
			winSize = &pty.Winsize{
				Cols: uint16(p.Width),
				Rows: uint16(p.Height),
			}
			req.Reply(true, nil)

		case "window-change":
			wc, err := parseWindowChange(req.Payload)
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			if ptmx != nil {
				_ = setWinsize(ptmx, wc.Width, wc.Height)
			}
			req.Reply(true, nil)

		case "env":
			e, err := parseEnvReq(req.Payload)
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			envVars = append(envVars, e.Name+"="+e.Value)
			req.Reply(true, nil)

		case "shell":
			req.Reply(true, nil)
			exitCode := s.execInContainer(ctx, ch, nil, envVars, winSize, &ptmx)
			sendExitStatus(ch, exitCode)
			return

		case "exec":
			e, err := parseExecReq(req.Payload)
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			cmdArgs := []string{"/bin/sh", "-c", e.Command}
			exitCode := s.execInContainer(ctx, ch, cmdArgs, envVars, winSize, &ptmx)
			sendExitStatus(ch, exitCode)
			return

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// execInContainer runs a command inside the container's namespaces via
// nsenter. If cmdArgs is nil, it runs an interactive login shell.
// Returns the process exit code.
func (s *sshServer) execInContainer(ctx context.Context, ch gossh.Channel, cmdArgs []string, envVars []string, winSize *pty.Winsize, ptmx **os.File) int {
	args := []string{
		"-t", strconv.Itoa(s.pid),
		"-m", "-u", "-i", "-n", "-p", "-C",
		"--",
	}
	if cmdArgs == nil {
		args = append(args, "/bin/sh", "-l")
	} else {
		args = append(args, cmdArgs...)
	}

	cmd := exec.CommandContext(ctx, "nsenter", args...)
	cmd.Env = envVars

	if winSize != nil {
		// Allocate a PTY.
		ptm, err := pty.StartWithSize(cmd, winSize)
		if err != nil {
			log.Printf("SSH: pty start failed: %v", err)
			fmt.Fprintf(ch, "failed to start shell: %v\r\n", err)
			return 1
		}
		*ptmx = ptm
		defer ptm.Close()

		// Bridge PTY ↔ SSH channel.
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			io.Copy(ch, ptm)
		}()
		go func() {
			defer wg.Done()
			io.Copy(ptm, ch)
		}()

		err = cmd.Wait()
		// Close the PTY to unblock the copy goroutines.
		ptm.Close()
		wg.Wait()
		return exitCodeFromErr(err)
	}

	// No PTY — pipe stdin/stdout/stderr directly.
	cmd.Stdin = ch
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()
	if err := cmd.Start(); err != nil {
		log.Printf("SSH: exec failed: %v", err)
		fmt.Fprintf(ch, "failed to start command: %v\n", err)
		return 1
	}
	return exitCodeFromErr(cmd.Wait())
}

// exitCodeFromErr extracts the exit code from an exec error.
func exitCodeFromErr(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 1
}

// sendExitStatus sends an "exit-status" request on the SSH channel.
func sendExitStatus(ch gossh.Channel, code int) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(code))
	ch.SendRequest("exit-status", false, payload)
	ch.CloseWrite()
}

// setWinsize sets the terminal window size on the PTY master.
func setWinsize(f *os.File, width, height uint32) error {
	ws := &unix.Winsize{
		Col: uint16(width),
		Row: uint16(height),
	}
	return unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ, ws)
}

// --- SSH payload parsing ---

// ptyReqPayload holds parsed pty-req data.
type ptyReqPayload struct {
	Term   string
	Width  uint32
	Height uint32
}

// parsePtyReq parses the pty-req SSH payload:
// term(string) + width(uint32) + height(uint32) + pixel_w(uint32) + pixel_h(uint32) + modes(string)
func parsePtyReq(data []byte) (ptyReqPayload, error) {
	var p struct {
		Term    string
		Width   uint32
		Height  uint32
		PixelW  uint32
		PixelH  uint32
		Modes   string
	}
	if err := gossh.Unmarshal(data, &p); err != nil {
		return ptyReqPayload{}, fmt.Errorf("unmarshal pty-req: %w", err)
	}
	return ptyReqPayload{Term: p.Term, Width: p.Width, Height: p.Height}, nil
}

// windowChangePayload holds parsed window-change data.
type windowChangePayload struct {
	Width  uint32
	Height uint32
}

// parseWindowChange parses the window-change SSH payload:
// width(uint32) + height(uint32) + pixel_w(uint32) + pixel_h(uint32)
func parseWindowChange(data []byte) (windowChangePayload, error) {
	var p struct {
		Width  uint32
		Height uint32
		PixelW uint32
		PixelH uint32
	}
	if err := gossh.Unmarshal(data, &p); err != nil {
		return windowChangePayload{}, fmt.Errorf("unmarshal window-change: %w", err)
	}
	return windowChangePayload{Width: p.Width, Height: p.Height}, nil
}

// envReqPayload holds parsed env data.
type envReqPayload struct {
	Name  string
	Value string
}

// parseEnvReq parses the env SSH payload: name(string) + value(string)
func parseEnvReq(data []byte) (envReqPayload, error) {
	var p struct {
		Name  string
		Value string
	}
	if err := gossh.Unmarshal(data, &p); err != nil {
		return envReqPayload{}, fmt.Errorf("unmarshal env: %w", err)
	}
	return envReqPayload{Name: p.Name, Value: p.Value}, nil
}

// execReqPayload holds parsed exec data.
type execReqPayload struct {
	Command string
}

// parseExecReq parses the exec SSH payload: command(string)
func parseExecReq(data []byte) (execReqPayload, error) {
	var p struct {
		Command string
	}
	if err := gossh.Unmarshal(data, &p); err != nil {
		return execReqPayload{}, fmt.Errorf("unmarshal exec: %w", err)
	}
	return execReqPayload{Command: p.Command}, nil
}

// --- Host key management ---

// loadOrGenerateHostKey loads an ED25519 host key from stateDir, or
// generates a new one if it doesn't exist.
func loadOrGenerateHostKey(stateDir string) (gossh.Signer, error) {
	keyPath := filepath.Join(stateDir, "ssh_host_ed25519_key")

	// Try loading existing key.
	keyData, err := os.ReadFile(keyPath)
	if err == nil {
		signer, err := gossh.ParsePrivateKey(keyData)
		if err == nil {
			return signer, nil
		}
		log.Printf("SSH: corrupt host key at %s, regenerating: %v", keyPath, err)
	}

	// Generate new key.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	// Marshal to PEM and persist.
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	pemData := pem.EncodeToMemory(block)
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		// Non-fatal: we can still use the key, just won't persist it.
		log.Printf("SSH: warning: failed to save host key: %v", err)
	}

	return signer, nil
}

// containerPIDFromNSPath extracts the container PID from a /proc/PID/ns/net
// path. Falls back to the TS_SSH_PID environment variable for named netns
// paths like /run/netns/NAME.
func containerPIDFromNSPath(nsPath string) (int, error) {
	// Try TS_SSH_PID override first.
	if pidStr := os.Getenv("TS_SSH_PID"); pidStr != "" {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return 0, fmt.Errorf("invalid TS_SSH_PID %q: %w", pidStr, err)
		}
		if pid <= 0 {
			return 0, fmt.Errorf("TS_SSH_PID must be positive, got %d", pid)
		}
		return pid, nil
	}

	// Parse /proc/PID/ns/net format.
	if !strings.HasPrefix(nsPath, "/proc/") {
		return 0, fmt.Errorf("cannot derive PID from namespace path %q (set TS_SSH_PID)", nsPath)
	}
	parts := strings.SplitN(nsPath, "/", 5) // ["", "proc", "PID", "ns", "net"]
	if len(parts) < 4 {
		return 0, fmt.Errorf("cannot parse PID from %q", nsPath)
	}
	pid, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, fmt.Errorf("invalid PID in path %q: %w", nsPath, err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("PID must be positive, got %d from %q", pid, nsPath)
	}
	return pid, nil
}
