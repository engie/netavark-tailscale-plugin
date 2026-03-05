// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"strings"
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
			name:    "named netns without override errors if path missing",
			nsPath:  "/run/netns/mycontainer",
			wantErr: true,
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
			name:    "empty path errors",
			nsPath:  "",
			wantErr: true,
		},
		{
			name:   "TS_SSH_PID takes precedence over proc path",
			nsPath: "/proc/999/ns/net",
			sshPID: "42",
			want:   42,
		},
		{
			name:   "real ns path via proc self finds a process",
			nsPath: "/proc/self/ns/net",
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

func TestParseSSHAllow(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"alice@example.com", []string{"alice@example.com"}},
		{"alice@example.com,bob@example.com", []string{"alice@example.com", "bob@example.com"}},
		{" alice@example.com , bob@example.com ", []string{"alice@example.com", "bob@example.com"}},
		{"alice@example.com,,bob@example.com", []string{"alice@example.com", "bob@example.com"}},
		{",,,", nil},
	}
	for _, tt := range tests {
		got := parseSSHAllow(tt.input)
		if len(got) == 0 && len(tt.want) == 0 {
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("parseSSHAllow(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseSSHAllow(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestSSHAllowlist(t *testing.T) {
	tests := []struct {
		name  string
		allow []string
		login string
		want  bool
	}{
		{"empty denies all", nil, "anyone@example.com", false},
		{"match", []string{"alice@example.com"}, "alice@example.com", true},
		{"no match", []string{"alice@example.com"}, "bob@example.com", false},
		{"multiple entries match second", []string{"alice@example.com", "bob@example.com"}, "bob@example.com", true},
		{"multiple entries no match", []string{"alice@example.com", "bob@example.com"}, "eve@example.com", false},
		{"case sensitive", []string{"Alice@example.com"}, "alice@example.com", false},
		{"wildcard allows all", []string{"*"}, "anyone@example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &sshServer{allow: tt.allow}
			if got := s.isAllowed(tt.login); got != tt.want {
				t.Errorf("isAllowed(%q) = %v, want %v", tt.login, got, tt.want)
			}
		})
	}
}

func TestAcceptEnvPair(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"TERM", true},
		{"LANG", true},
		{"LC_ALL", true},
		{"LC_CTYPE", true},
		{"LC_MESSAGES", true},
		{"PATH", false},
		{"HOME", false},
		{"LD_PRELOAD", false},
		{"LD_LIBRARY_PATH", false},
		{"BASH_ENV", false},
		{"ENV", false},
		{"PYTHONPATH", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := acceptEnvPair(tt.name); got != tt.want {
				t.Errorf("acceptEnvPair(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestMatchAcceptEnvPattern(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"TERM", "TERM", true},
		{"TERM", "LANG", false},
		{"GIT_*", "GIT_AUTHOR_NAME", true},
		{"GIT_*", "GIT_", true},
		{"GIT_*", "GIT", false},
		{"*", "ANYTHING", true},
		{"*", "", true},
		{"MY_?", "MY_A", true},
		{"MY_?", "MY_AB", false},
		{"MY_?", "MY_", false},
		{"FOO_*_BAR", "FOO_X_BAR", true},
		{"FOO_*_BAR", "FOO_XYZ_BAR", true},
		{"FOO_*_BAR", "FOO__BAR", true},
		{"FOO_*_BAR", "FOO_BAR", false},
		{"**", "X", true},
		{"", "", true},
		{"", "X", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.name, func(t *testing.T) {
			if got := matchAcceptEnvPattern(tt.pattern, tt.name); got != tt.want {
				t.Errorf("matchAcceptEnvPattern(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
			}
		})
	}
}

func TestParseAcceptEnv(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"GIT_*", []string{"GIT_*"}},
		{"GIT_*,MY_VAR", []string{"GIT_*", "MY_VAR"}},
		{" GIT_* , MY_VAR ", []string{"GIT_*", "MY_VAR"}},
		{",,,", nil},
	}
	for _, tt := range tests {
		got := parseAcceptEnv(tt.input)
		if len(got) == 0 && len(tt.want) == 0 {
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("parseAcceptEnv(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseAcceptEnv(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestIsAllowedEnv(t *testing.T) {
	tests := []struct {
		name      string
		acceptEnv []string
		envName   string
		want      bool
	}{
		{"baseline TERM", nil, "TERM", true},
		{"baseline LANG", nil, "LANG", true},
		{"baseline LC_ALL", nil, "LC_ALL", true},
		{"blocked LD_PRELOAD", nil, "LD_PRELOAD", false},
		{"blocked PATH", nil, "PATH", false},
		{"pattern match", []string{"GIT_*"}, "GIT_AUTHOR_NAME", true},
		{"pattern no match", []string{"GIT_*"}, "PATH", false},
		{"pattern plus baseline", []string{"GIT_*"}, "TERM", true},
		{"exact pattern", []string{"MY_VAR"}, "MY_VAR", true},
		{"exact pattern miss", []string{"MY_VAR"}, "MY_OTHER", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &sshServer{acceptEnv: tt.acceptEnv}
			if got := s.isAllowedEnv(tt.envName); got != tt.want {
				t.Errorf("isAllowedEnv(%q) = %v, want %v", tt.envName, got, tt.want)
			}
		})
	}
}

func TestParsePasswdShell(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		username string
		want     string
	}{
		{
			name:     "normal root entry",
			content:  "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:Nobody:/:/usr/bin/nologin\n",
			username: "root",
			want:     "/bin/bash",
		},
		{
			name:     "root with zsh",
			content:  "root:x:0:0:root:/root:/bin/zsh\n",
			username: "root",
			want:     "/bin/zsh",
		},
		{
			name:     "root not present",
			content:  "nobody:x:65534:65534:Nobody:/:/usr/bin/nologin\n",
			username: "root",
			want:     "/bin/sh",
		},
		{
			name:     "empty file",
			content:  "",
			username: "root",
			want:     "/bin/sh",
		},
		{
			name:     "malformed lines",
			content:  "garbage\nroot:x:0:0\nmore garbage\n",
			username: "root",
			want:     "/bin/sh",
		},
		{
			name:     "root with empty shell field",
			content:  "root:x:0:0:root:/root:\n",
			username: "root",
			want:     "/bin/sh",
		},
		{
			name:     "comment lines skipped",
			content:  "# comment\nroot:x:0:0:root:/root:/bin/bash\n",
			username: "root",
			want:     "/bin/bash",
		},
		{
			name:     "lookup non-root user",
			content:  "root:x:0:0:root:/root:/bin/bash\nstephen:x:1000:1000:Stephen:/home/stephen:/bin/fish\n",
			username: "stephen",
			want:     "/bin/fish",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePasswdShell(strings.NewReader(tt.content), tt.username)
			if got != tt.want {
				t.Errorf("parsePasswdShell(%q) = %q, want %q", tt.username, got, tt.want)
			}
		})
	}
}

func TestBaseEnvForRoot(t *testing.T) {
	env := baseEnvForRoot("/bin/bash")
	want := map[string]string{
		"HOME":    "/root",
		"USER":    "root",
		"LOGNAME": "root",
		"SHELL":   "/bin/bash",
		"PATH":    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	got := make(map[string]string)
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			t.Errorf("malformed env entry: %q", e)
			continue
		}
		got[k] = v
	}
	for k, wantV := range want {
		if gotV, ok := got[k]; !ok {
			t.Errorf("missing env var %s", k)
		} else if gotV != wantV {
			t.Errorf("%s = %q, want %q", k, gotV, wantV)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d env vars, want %d", len(got), len(want))
	}

	// Verify shell is passed through correctly.
	env2 := baseEnvForRoot("/bin/sh")
	for _, e := range env2 {
		if strings.HasPrefix(e, "SHELL=") {
			if e != "SHELL=/bin/sh" {
				t.Errorf("SHELL = %q, want SHELL=/bin/sh", e)
			}
			break
		}
	}
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
	sshSrv, err := newSSHServer(srv1, "/proc/1/ns/net", stateDir, []string{"*"}, nil)
	if err != nil {
		t.Fatalf("newSSHServer: %v", err)
	}

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

