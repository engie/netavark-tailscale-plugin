// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"bufio"
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
	"syscall"

	"github.com/creack/pty"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"tailscale.com/tsnet"
)

// sshServer runs an SSH server on the tsnet interface, allowing tailnet
// peers to open shells inside the container via nsenter.
type sshServer struct {
	tsnetSrv    *tsnet.Server
	hostKey     gossh.Signer
	nsPath      string            // network namespace path for PID resolution
	pidfilePath string            // path to podman's --pidfile (from TS_PIDFILE)
	allow       map[string]string // tailnet login → container user (empty = deny all)
	acceptEnv   []string          // additional env var patterns to accept (from TS_SSH_ACCEPT_ENV)
}

// newSSHServer creates an SSH server that will listen on the tsnet interface.
// allow maps tailnet login names to container usernames. Only peers whose
// UserProfile.LoginName appears in the map (or "*" wildcard) are permitted.
func newSSHServer(srv *tsnet.Server, nsPath string, pidfilePath string, stateDir string, allow map[string]string, acceptEnv []string) (*sshServer, error) {
	hostKey, err := loadOrGenerateHostKey(stateDir)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}

	return &sshServer{
		tsnetSrv:    srv,
		hostKey:     hostKey,
		nsPath:      nsPath,
		pidfilePath: pidfilePath,
		allow:       allow,
		acceptEnv:   acceptEnv,
	}, nil
}

// parseSSHAllow parses a comma-separated list of identity:user pairs into a
// map from tailnet login name to container username. Each entry must be in
// the form "identity:user" (e.g. "alice@example.com:root" or "*:dave").
func parseSSHAllow(s string) (map[string]string, error) {
	m := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		identity, user, ok := strings.Cut(part, ":")
		if !ok || identity == "" || user == "" {
			return nil, fmt.Errorf("invalid TS_SSH_ALLOW entry %q: expected identity:user", part)
		}
		m[identity] = user
	}
	return m, nil
}

// isAllowed reports whether the given login name is permitted by the
// allowlist. Returns the container username to use and whether access is
// granted. If the allowlist contains a "*" key, it matches any peer not
// explicitly listed. An empty allowlist denies all peers.
func (s *sshServer) isAllowed(loginName string) (string, bool) {
	if user, ok := s.allow[loginName]; ok {
		return user, true
	}
	if user, ok := s.allow["*"]; ok {
		return user, true
	}
	return "", false
}

// acceptEnvPair reports whether the env var name is unconditionally safe
// to pass through to the container shell. Matches OpenSSH's default
// AcceptEnv and Tailscale's hardcoded acceptEnvPair: TERM, LANG, LC_*.
func acceptEnvPair(name string) bool {
	return name == "TERM" || name == "LANG" || strings.HasPrefix(name, "LC_")
}

// matchAcceptEnvPattern matches a name against a pattern containing
// '*' (zero or more chars) and '?' (exactly one char) wildcards.
// Mirrors Tailscale's matchAcceptEnvPattern algorithm.
func matchAcceptEnvPattern(pattern, name string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// Skip repeated asterisks.
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true // trailing * matches everything
			}
			// Try matching rest of pattern at every position.
			for i := 0; i <= len(name); i++ {
				if matchAcceptEnvPattern(pattern, name[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(name) == 0 {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]
		default:
			if len(name) == 0 || pattern[0] != name[0] {
				return false
			}
			pattern = pattern[1:]
			name = name[1:]
		}
	}
	return len(name) == 0
}

// parseAcceptEnv splits a comma-separated list of env var patterns
// (with optional * and ? wildcards) into trimmed, non-empty entries.
func parseAcceptEnv(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// isAllowedEnv reports whether the given env var name should be passed
// through to the container. A name is allowed if it matches the
// hardcoded baseline (TERM, LANG, LC_*) or any pattern in acceptEnv.
func (s *sshServer) isAllowedEnv(name string) bool {
	if acceptEnvPair(name) {
		return true
	}
	for _, pattern := range s.acceptEnv {
		if matchAcceptEnvPattern(pattern, name) {
			return true
		}
	}
	return false
}

// passwdEntry holds parsed /etc/passwd fields for a user.
type passwdEntry struct {
	Username string
	UID      int
	GID      int
	Home     string
	Shell    string
}

// parsePasswdUser reads /etc/passwd-formatted lines from r and returns
// the entry for the given username. Returns false if the user is not found.
func parsePasswdUser(r io.Reader, username string) (passwdEntry, bool) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 7 && fields[0] == username {
			entry := passwdEntry{Username: username, Shell: "/bin/sh", Home: "/"}
			if uid, err := strconv.Atoi(fields[2]); err == nil {
				entry.UID = uid
			}
			if gid, err := strconv.Atoi(fields[3]); err == nil {
				entry.GID = gid
			}
			if fields[5] != "" {
				entry.Home = fields[5]
			}
			if fields[6] != "" {
				entry.Shell = fields[6]
			}
			return entry, true
		}
	}
	return passwdEntry{}, false
}

// lookupUserInContainer reads the container's /etc/passwd by entering its
// mount namespace via nsenter, avoiding symlink traversal attacks that are
// possible when reading via /proc/<pid>/root/etc/passwd from the host.
// Falls back to sensible defaults for root; returns an error for other users
// not found in passwd.
func lookupUserInContainer(pid int, username string) (passwdEntry, error) {
	cmd := exec.Command("nsenter", "-t", strconv.Itoa(pid), "-m", "--", "cat", "/etc/passwd")
	cmd.Env = []string{}
	out, err := cmd.Output()
	if err != nil {
		if username == "root" {
			log.Printf("SSH: cannot read container passwd (nsenter pid %d): %v; using defaults for root", pid, err)
			return passwdEntry{Username: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/sh"}, nil
		}
		return passwdEntry{}, fmt.Errorf("cannot read container passwd: %w", err)
	}
	entry, found := parsePasswdUser(strings.NewReader(string(out)), username)
	if !found {
		if username == "root" {
			return passwdEntry{Username: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/sh"}, nil
		}
		return passwdEntry{}, fmt.Errorf("user %q not found in container /etc/passwd", username)
	}
	return entry, nil
}

// baseEnvForUser returns the standard environment variables for a login
// shell inside the container for the given user.
func baseEnvForUser(entry passwdEntry) []string {
	return []string{
		"HOME=" + entry.Home,
		"USER=" + entry.Username,
		"LOGNAME=" + entry.Username,
		"SHELL=" + entry.Shell,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
}

// readPidfile reads a PID from a file written by podman's --pidfile flag.
func readPidfile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading pidfile: %w", err)
	}
	pidStr := strings.TrimSpace(string(data))
	if pidStr == "" {
		return 0, fmt.Errorf("pidfile %s is empty", path)
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("pidfile %s: invalid PID %q: %w", path, pidStr, err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("pidfile %s: PID must be positive, got %d", path, pid)
	}
	return pid, nil
}

// validatePIDNetNS checks that the given PID is in the expected network
// namespace by comparing stat(2) device+inode of /proc/<pid>/ns/net and
// nsPath. This guards against PID reuse after container restart.
func validatePIDNetNS(pid int, nsPath string) error {
	pidNS := fmt.Sprintf("/proc/%d/ns/net", pid)
	fi1, err := os.Stat(pidNS)
	if err != nil {
		return fmt.Errorf("stat %s: %w", pidNS, err)
	}
	fi2, err := os.Stat(nsPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", nsPath, err)
	}
	st1, ok := fi1.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot get stat_t for %s", pidNS)
	}
	st2, ok := fi2.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot get stat_t for %s", nsPath)
	}
	if st1.Dev != st2.Dev || st1.Ino != st2.Ino {
		return fmt.Errorf("PID %d is not in expected netns (PID reuse detected)", pid)
	}
	return nil
}

// discoverContainers scans the directory containing pidfilePath for *.pid
// files, reads each PID, and returns those sharing our network namespace.
// The map keys are pidfile basenames without the .pid extension.
func (s *sshServer) discoverContainers() (map[string]int, error) {
	if s.pidfilePath == "" {
		return nil, fmt.Errorf("TS_PIDFILE not set; required for SSH container PID resolution")
	}
	dir := filepath.Dir(s.pidfilePath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading pidfile directory %s: %w", dir, err)
	}
	result := make(map[string]int)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pid") {
			continue
		}
		pidPath := filepath.Join(dir, e.Name())
		pid, err := readPidfile(pidPath)
		if err != nil {
			continue // stale or unreadable pidfile
		}
		if err := validatePIDNetNS(pid, s.nsPath); err != nil {
			continue // different netns, not part of this pod
		}
		name := strings.TrimSuffix(e.Name(), ".pid")
		result[name] = pid
	}
	return result, nil
}

// containerPID resolves the container init PID for the given container name
// (SSH username). It discovers all containers sharing our network namespace
// by scanning pidfiles, then looks up the requested name.
func (s *sshServer) containerPID(name string) (int, error) {
	if s.pidfilePath == "" {
		return 0, fmt.Errorf("TS_PIDFILE not set; required for SSH container PID resolution")
	}
	containers, err := s.discoverContainers()
	if err != nil {
		return 0, err
	}
	if len(containers) == 0 {
		return 0, fmt.Errorf("no containers found sharing network namespace")
	}
	if pid, ok := containers[name]; ok {
		return pid, nil
	}
	available := make([]string, 0, len(containers))
	for k := range containers {
		available = append(available, k)
	}
	return 0, fmt.Errorf("container %q not found; available: %s", name, strings.Join(available, ", "))
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

	localUser, ok := s.isAllowed(peerLogin)
	if !ok {
		log.Printf("SSH: rejected %s (%s): not in allowlist", peerLogin, peerNode)
		return
	}

	// The SSH username selects which container to enter (pidfile basename).
	containerName := sconn.User()
	log.Printf("SSH session from %s (%s) as %s in container %q", peerLogin, peerNode, localUser, containerName)

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
		go s.handleSession(ctx, ch, reqs, localUser, containerName)
	}
}

// handleSession processes requests on an SSH session channel: pty-req,
// window-change, env, shell, and exec. Commands are run via nsenter into
// the container's namespaces as localUser.
func (s *sshServer) handleSession(ctx context.Context, ch gossh.Channel, reqs <-chan *gossh.Request, localUser string, containerName string) {
	// Session-scoped context: cancelled when this handler returns or when
	// drainReqs detects the SSH channel closing during command execution.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer ch.Close()

	var (
		ptmx    *os.File
		winSize *pty.Winsize
		envVars []string // client-sent env vars (filtered by allowlist)
		term    string   // TERM value from pty-req payload
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
			term = p.Term
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
			if !s.isAllowedEnv(e.Name) {
				req.Reply(false, nil)
				continue
			}
			envVars = append(envVars, e.Name+"="+e.Value)
			req.Reply(true, nil)

		case "shell":
			req.Reply(true, nil)
			pid, err := s.containerPID(containerName)
			if err != nil {
				log.Printf("SSH: failed to resolve container PID: %v", err)
				fmt.Fprintf(ch, "failed to resolve container PID: %v\r\n", err)
				sendExitStatus(ch, 1)
				return
			}
			entry, err := lookupUserInContainer(pid, localUser)
			if err != nil {
				log.Printf("SSH: failed to resolve user %q: %v", localUser, err)
				fmt.Fprintf(ch, "failed to resolve user %q: %v\r\n", localUser, err)
				sendExitStatus(ch, 1)
				return
			}
			env := s.buildEnv(entry, term, envVars)
			// Drain remaining requests in background; cancel ctx on channel close.
			go drainReqs(reqs, cancel)
			exitCode := s.execInContainer(ctx, ch, pid, nil, entry, env, winSize, &ptmx)
			sendExitStatus(ch, exitCode)
			return

		case "exec":
			e, err := parseExecReq(req.Payload)
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			pid, err := s.containerPID(containerName)
			if err != nil {
				log.Printf("SSH: failed to resolve container PID: %v", err)
				fmt.Fprintf(ch, "failed to resolve container PID: %v\r\n", err)
				sendExitStatus(ch, 1)
				return
			}
			entry, err := lookupUserInContainer(pid, localUser)
			if err != nil {
				log.Printf("SSH: failed to resolve user %q: %v", localUser, err)
				fmt.Fprintf(ch, "failed to resolve user %q: %v\r\n", localUser, err)
				sendExitStatus(ch, 1)
				return
			}
			env := s.buildEnv(entry, term, envVars)
			cmdArgs := []string{"/bin/sh", "-c", `cd "$HOME" 2>/dev/null; ` + e.Command}
			// Drain remaining requests in background; cancel ctx on channel close.
			go drainReqs(reqs, cancel)
			exitCode := s.execInContainer(ctx, ch, pid, cmdArgs, entry, env, winSize, &ptmx)
			sendExitStatus(ch, exitCode)
			return

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// drainReqs consumes remaining SSH channel requests (e.g. window-change)
// and calls onClose when the channel closes (peer disconnect). This allows
// the session context to be cancelled when the SSH client disconnects while
// a command is running.
func drainReqs(reqs <-chan *gossh.Request, onClose context.CancelFunc) {
	for req := range reqs {
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
	onClose()
}

// buildEnv constructs the full environment for the container process.
// Base env (HOME, USER, etc.) is set first, then TERM from pty-req,
// then client-sent env vars (which can override base values).
func (s *sshServer) buildEnv(entry passwdEntry, term string, clientEnv []string) []string {
	env := baseEnvForUser(entry)
	if term != "" {
		env = append(env, "TERM="+term)
	}
	env = append(env, clientEnv...)
	return env
}

// execInContainer runs a command inside the container's namespaces via
// nsenter. If cmdArgs is nil, it runs an interactive login shell using
// the user's shell with -l. Returns the process exit code.
func (s *sshServer) execInContainer(ctx context.Context, ch gossh.Channel, pid int, cmdArgs []string, entry passwdEntry, envVars []string, winSize *pty.Winsize, ptmx **os.File) int {
	args := []string{
		"-t", strconv.Itoa(pid),
		"-m", "-u", "-i", "-n", "-p", "-C", "-F",
	}
	// Only use setuid/setgid for non-root users. In rootless podman,
	// we already enter as UID 0 inside the user namespace, and -S/-G
	// would require CAP_SETUID/CAP_SETGID which we don't have.
	if entry.UID != 0 || entry.GID != 0 {
		args = append(args, "-S", strconv.Itoa(entry.UID), "-G", strconv.Itoa(entry.GID))
	}
	args = append(args, "--")
	// Pass environment via /usr/bin/env inside the namespace, not via
	// cmd.Env on the host side. This prevents client-controlled env vars
	// (e.g. LD_PRELOAD) from affecting nsenter's own dynamic linker.
	args = append(args, "/usr/bin/env", "-i")
	args = append(args, envVars...)
	if cmdArgs == nil {
		// Use sh to cd to $HOME before exec'ing the login shell.
		// nsenter's --wd resolves on the host filesystem, which fails
		// in rootless podman where the host user can't access /root.
		args = append(args, "/bin/sh", "-c", `cd "$HOME" 2>/dev/null; exec `+entry.Shell+` -l`)
	} else {
		args = append(args, cmdArgs...)
	}

	cmd := exec.CommandContext(ctx, "nsenter", args...)
	cmd.Env = []string{}

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
	// Use a process group so we can kill all children on disconnect.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = ch
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()
	if err := cmd.Start(); err != nil {
		log.Printf("SSH: exec failed: %v", err)
		fmt.Fprintf(ch, "failed to start command: %v\n", err)
		return 1
	}
	// Kill the entire process group when the context is cancelled
	// (SSH disconnect detected by drainReqs, or daemon shutdown).
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		case <-done:
		}
	}()
	err := cmd.Wait()
	close(done)
	return exitCodeFromErr(err)
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

