// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
)

// --- Tier 1: Unit tests (no root, no network) ---

func TestContainerPIDFromNSPath(t *testing.T) {
	tests := []struct {
		name    string
		nsPath  string
		sshPID  string // TS_SSH_PID env override
		want    int
		wantErr bool
	}{
		{
			name:   "proc path",
			nsPath: "/proc/12345/ns/net",
			want:   12345,
		},
		{
			name:   "proc path single digit",
			nsPath: "/proc/1/ns/net",
			want:   1,
		},
		{
			name:    "named netns without override falls through to proc scan",
			nsPath:  "/run/netns/mycontainer",
			wantErr: false, // findPIDInNetNS finds a process in our own netns
		},
		{
			name:   "named netns with TS_SSH_PID",
			nsPath: "/run/netns/mycontainer",
			sshPID: "42",
			want:   42,
		},
		{
			name:    "TS_SSH_PID invalid",
			nsPath:  "/run/netns/mycontainer",
			sshPID:  "notanumber",
			wantErr: true,
		},
		{
			name:    "TS_SSH_PID zero",
			nsPath:  "/run/netns/mycontainer",
			sshPID:  "0",
			wantErr: true,
		},
		{
			name:    "TS_SSH_PID negative",
			nsPath:  "/run/netns/mycontainer",
			sshPID:  "-1",
			wantErr: true,
		},
		{
			name:    "empty path falls through to proc scan",
			nsPath:  "",
			wantErr: false, // findPIDInNetNS finds a process in our own netns
		},
		{
			name:   "TS_SSH_PID takes precedence over proc path",
			nsPath: "/proc/999/ns/net",
			sshPID: "42",
			want:   42,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sshPID != "" {
				t.Setenv("TS_SSH_PID", tt.sshPID)
			} else {
				t.Setenv("TS_SSH_PID", "")
			}
			got, err := containerPIDFromNSPath(tt.nsPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("containerPIDFromNSPath(%q) error = %v, wantErr %v", tt.nsPath, err, tt.wantErr)
				return
			}
			if tt.want != 0 && got != tt.want {
				t.Errorf("containerPIDFromNSPath(%q) = %d, want %d", tt.nsPath, got, tt.want)
			}
		})
	}
}

func TestSSHPayloadParsing(t *testing.T) {
	t.Run("pty-req", func(t *testing.T) {
		// Build a pty-req payload: term(string) + width + height + pixelW + pixelH + modes(string)
		payload := gossh.Marshal(struct {
			Term   string
			Width  uint32
			Height uint32
			PixelW uint32
			PixelH uint32
			Modes  string
		}{
			Term:   "xterm-256color",
			Width:  80,
			Height: 24,
			PixelW: 640,
			PixelH: 480,
			Modes:  "",
		})
		p, err := parsePtyReq(payload)
		if err != nil {
			t.Fatalf("parsePtyReq: %v", err)
		}
		if p.Term != "xterm-256color" {
			t.Errorf("Term = %q, want %q", p.Term, "xterm-256color")
		}
		if p.Width != 80 {
			t.Errorf("Width = %d, want 80", p.Width)
		}
		if p.Height != 24 {
			t.Errorf("Height = %d, want 24", p.Height)
		}
	})

	t.Run("window-change", func(t *testing.T) {
		payload := gossh.Marshal(struct {
			Width  uint32
			Height uint32
			PixelW uint32
			PixelH uint32
		}{
			Width:  120,
			Height: 40,
			PixelW: 960,
			PixelH: 800,
		})
		wc, err := parseWindowChange(payload)
		if err != nil {
			t.Fatalf("parseWindowChange: %v", err)
		}
		if wc.Width != 120 {
			t.Errorf("Width = %d, want 120", wc.Width)
		}
		if wc.Height != 40 {
			t.Errorf("Height = %d, want 40", wc.Height)
		}
	})

	t.Run("env", func(t *testing.T) {
		payload := gossh.Marshal(struct {
			Name  string
			Value string
		}{
			Name:  "LANG",
			Value: "en_US.UTF-8",
		})
		e, err := parseEnvReq(payload)
		if err != nil {
			t.Fatalf("parseEnvReq: %v", err)
		}
		if e.Name != "LANG" {
			t.Errorf("Name = %q, want %q", e.Name, "LANG")
		}
		if e.Value != "en_US.UTF-8" {
			t.Errorf("Value = %q, want %q", e.Value, "en_US.UTF-8")
		}
	})

	t.Run("exec", func(t *testing.T) {
		payload := gossh.Marshal(struct {
			Command string
		}{
			Command: "hostname",
		})
		e, err := parseExecReq(payload)
		if err != nil {
			t.Fatalf("parseExecReq: %v", err)
		}
		if e.Command != "hostname" {
			t.Errorf("Command = %q, want %q", e.Command, "hostname")
		}
	})

	t.Run("invalid payloads", func(t *testing.T) {
		if _, err := parsePtyReq([]byte{0x01}); err == nil {
			t.Error("expected error for invalid pty-req payload")
		}
		if _, err := parseWindowChange([]byte{0x01}); err == nil {
			t.Error("expected error for invalid window-change payload")
		}
		if _, err := parseEnvReq([]byte{0x01}); err == nil {
			t.Error("expected error for invalid env payload")
		}
		if _, err := parseExecReq([]byte{0x01}); err == nil {
			t.Error("expected error for invalid exec payload")
		}
	})
}

// --- Tier 2: Integration test (no root, fake control + chanTUN) ---

func TestSSHServerConnects(t *testing.T) {
	controlURL, _ := startTestControl(t)

	// Node 1: SSH server
	tun1 := newChanTUN()
	srv1 := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: controlURL,
		Hostname:   "ssh-server",
		Store:      new(mem.Store),
		Ephemeral:  true,
		Tun:        tun1,
	}
	t.Cleanup(func() { srv1.Close() })

	// Node 2: SSH client
	tun2 := newChanTUN()
	srv2 := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: controlURL,
		Hostname:   "ssh-client",
		Store:      new(mem.Store),
		Ephemeral:  true,
		Tun:        tun2,
	}
	t.Cleanup(func() { srv2.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := srv1.Up(ctx)
	if err != nil {
		t.Fatalf("srv1.Up: %v", err)
	}
	_, err = srv2.Up(ctx)
	if err != nil {
		t.Fatalf("srv2.Up: %v", err)
	}

	// Start SSH server on node 1.
	stateDir := t.TempDir()
	sshSrv := &sshServer{
		tsnetSrv: srv1,
		nsPath:   "/proc/1/ns/net", // won't nsenter in this test
	}
	hostKey, err := loadOrGenerateHostKey(stateDir)
	if err != nil {
		t.Fatalf("loadOrGenerateHostKey: %v", err)
	}
	sshSrv.hostKey = hostKey

	sshCtx, sshCancel := context.WithCancel(ctx)
	defer sshCancel()
	go sshSrv.run(sshCtx)

	// Give the listener a moment to start.
	time.Sleep(100 * time.Millisecond)

	// Connect from node 2 to node 1's SSH server via tsnet dial.
	nc, err := srv2.Dial(ctx, "tcp", "ssh-server:22")
	if err != nil {
		t.Fatalf("dial ssh-server:22: %v", err)
	}
	defer nc.Close()

	// Perform SSH handshake as client.
	clientConfig := &gossh.ClientConfig{
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, chans, reqs, err := gossh.NewClientConn(nc, "ssh-server:22", clientConfig)
	if err != nil {
		t.Fatalf("SSH client handshake: %v", err)
	}
	defer conn.Close()
	go gossh.DiscardRequests(reqs)

	// Open a session channel.
	ch, requests, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session channel: %v", err)
	}
	defer ch.Close()
	go gossh.DiscardRequests(requests)
	_ = chans // client-side new channels (unused)

	t.Logf("SSH session channel opened successfully to ssh-server via tsnet")
}

// TestSSHHostKeyPersistence verifies that host keys are persisted and reloaded.
func TestSSHHostKeyPersistence(t *testing.T) {
	dir := t.TempDir()

	// Generate a key.
	signer1, err := loadOrGenerateHostKey(dir)
	if err != nil {
		t.Fatalf("first loadOrGenerateHostKey: %v", err)
	}

	// Reload — should get the same key.
	signer2, err := loadOrGenerateHostKey(dir)
	if err != nil {
		t.Fatalf("second loadOrGenerateHostKey: %v", err)
	}

	pub1 := signer1.PublicKey().Marshal()
	pub2 := signer2.PublicKey().Marshal()
	if string(pub1) != string(pub2) {
		t.Error("reloaded host key differs from original")
	}
}

