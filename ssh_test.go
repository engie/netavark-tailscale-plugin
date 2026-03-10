// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
)

// --- Tier 1: Unit tests (no root, no network) ---

func TestReadPidfile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		create  bool // whether to create the file
		want    int
		wantErr bool
	}{
		{"valid PID", "42", true, 42, false},
		{"trailing newline", "42\n", true, 42, false},
		{"whitespace", "  42  \n", true, 42, false},
		{"empty file", "", true, 0, true},
		{"non-numeric", "notapid", true, 0, true},
		{"zero", "0", true, 0, true},
		{"negative", "-1", true, 0, true},
		{"missing file", "", false, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.create {
				path = filepath.Join(t.TempDir(), "pidfile")
				if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
					t.Fatal(err)
				}
			} else {
				path = filepath.Join(t.TempDir(), "nonexistent")
			}
			got, err := readPidfile(path)
			if (err != nil) != tt.wantErr {
				t.Errorf("readPidfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("readPidfile() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestValidatePIDNetNS(t *testing.T) {
	myPID := os.Getpid()
	myNS := fmt.Sprintf("/proc/%d/ns/net", myPID)

	t.Run("own PID matches own netns", func(t *testing.T) {
		if err := validatePIDNetNS(myPID, myNS); err != nil {
			t.Errorf("validatePIDNetNS(self, self) = %v, want nil", err)
		}
	})

	t.Run("non-existent PID", func(t *testing.T) {
		if err := validatePIDNetNS(999999999, myNS); err == nil {
			t.Error("validatePIDNetNS(bogus, self) = nil, want error")
		}
	})

	t.Run("non-existent nsPath", func(t *testing.T) {
		if err := validatePIDNetNS(myPID, "/run/netns/nonexistent"); err == nil {
			t.Error("validatePIDNetNS(self, bogus) = nil, want error")
		}
	})
}

func TestContainerPID(t *testing.T) {
	myPID := os.Getpid()
	myNS := fmt.Sprintf("/proc/%d/ns/net", myPID)

	t.Run("pidfile with matching netns", func(t *testing.T) {
		dir := t.TempDir()
		pidfile := filepath.Join(dir, "test.pid")
		if err := os.WriteFile(pidfile, []byte(fmt.Sprintf("%d\n", myPID)), 0644); err != nil {
			t.Fatal(err)
		}
		s := &sshServer{nsPath: myNS, pidfilePath: pidfile}
		got, err := s.containerPID("test")
		if err != nil {
			t.Fatalf("containerPID() error = %v", err)
		}
		if got != myPID {
			t.Errorf("containerPID() = %d, want %d", got, myPID)
		}
	})

	t.Run("missing pidfilePath errors", func(t *testing.T) {
		s := &sshServer{nsPath: myNS}
		_, err := s.containerPID("test")
		if err == nil {
			t.Error("containerPID() = nil, want error for missing pidfilePath")
		}
	})

	t.Run("missing pidfile errors", func(t *testing.T) {
		s := &sshServer{nsPath: myNS, pidfilePath: "/tmp/nonexistent-pidfile/x.pid"}
		_, err := s.containerPID("x")
		if err == nil {
			t.Error("containerPID() = nil, want error for missing pidfile directory")
		}
	})

	t.Run("netns mismatch errors", func(t *testing.T) {
		// PID 1 (init) is almost certainly in a different netns than us
		dir := t.TempDir()
		pidfile := filepath.Join(dir, "test.pid")
		if err := os.WriteFile(pidfile, []byte("1\n"), 0644); err != nil {
			t.Fatal(err)
		}
		s := &sshServer{nsPath: myNS, pidfilePath: pidfile}
		_, err := s.containerPID("test")
		// This may error with permission denied (reading /proc/1/ns/net)
		// or netns mismatch — either way it should error (no containers found
		// or container not found).
		if err == nil {
			t.Error("containerPID() = nil, want error for netns mismatch")
		}
	})

	t.Run("wrong container name errors", func(t *testing.T) {
		dir := t.TempDir()
		pidfile := filepath.Join(dir, "web.pid")
		if err := os.WriteFile(pidfile, []byte(fmt.Sprintf("%d\n", myPID)), 0644); err != nil {
			t.Fatal(err)
		}
		s := &sshServer{nsPath: myNS, pidfilePath: pidfile}
		_, err := s.containerPID("api")
		if err == nil {
			t.Error("containerPID(api) = nil, want error for wrong name")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error should mention 'not found', got: %v", err)
		}
		if !strings.Contains(err.Error(), "web") {
			t.Errorf("error should list available container 'web', got: %v", err)
		}
	})
}

func TestDiscoverContainers(t *testing.T) {
	myPID := os.Getpid()
	myNS := fmt.Sprintf("/proc/%d/ns/net", myPID)

	t.Run("discovers multiple pidfiles in same netns", func(t *testing.T) {
		dir := t.TempDir()
		// Write two pidfiles pointing to our own PID (same netns).
		for _, name := range []string{"web.pid", "api.pid"} {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(fmt.Sprintf("%d\n", myPID)), 0644); err != nil {
				t.Fatal(err)
			}
		}
		s := &sshServer{nsPath: myNS, pidfilePath: filepath.Join(dir, "web.pid")}
		got, err := s.discoverContainers()
		if err != nil {
			t.Fatalf("discoverContainers() error = %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("discoverContainers() returned %d containers, want 2", len(got))
		}
		if got["web"] != myPID {
			t.Errorf("web PID = %d, want %d", got["web"], myPID)
		}
		if got["api"] != myPID {
			t.Errorf("api PID = %d, want %d", got["api"], myPID)
		}
	})

	t.Run("skips non-pid files", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "web.pid"), []byte(fmt.Sprintf("%d\n", myPID)), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a pid"), 0644); err != nil {
			t.Fatal(err)
		}
		s := &sshServer{nsPath: myNS, pidfilePath: filepath.Join(dir, "web.pid")}
		got, err := s.discoverContainers()
		if err != nil {
			t.Fatalf("discoverContainers() error = %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("discoverContainers() returned %d containers, want 1", len(got))
		}
	})

	t.Run("skips pidfiles with wrong netns", func(t *testing.T) {
		dir := t.TempDir()
		// Our PID (same netns).
		if err := os.WriteFile(filepath.Join(dir, "web.pid"), []byte(fmt.Sprintf("%d\n", myPID)), 0644); err != nil {
			t.Fatal(err)
		}
		// PID 1 (different netns or unreadable).
		if err := os.WriteFile(filepath.Join(dir, "other.pid"), []byte("1\n"), 0644); err != nil {
			t.Fatal(err)
		}
		s := &sshServer{nsPath: myNS, pidfilePath: filepath.Join(dir, "web.pid")}
		got, err := s.discoverContainers()
		if err != nil {
			t.Fatalf("discoverContainers() error = %v", err)
		}
		if _, ok := got["other"]; ok {
			t.Error("discoverContainers() should not include 'other' (wrong netns)")
		}
		if len(got) != 1 {
			t.Fatalf("discoverContainers() returned %d containers, want 1", len(got))
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		dir := t.TempDir()
		s := &sshServer{nsPath: myNS, pidfilePath: filepath.Join(dir, "x.pid")}
		got, err := s.discoverContainers()
		if err != nil {
			t.Fatalf("discoverContainers() error = %v", err)
		}
		if len(got) != 0 {
			t.Errorf("discoverContainers() returned %d containers, want 0", len(got))
		}
	})
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
		input   string
		want    map[string]string
		wantErr bool
	}{
		{"", map[string]string{}, false},
		{"alice@example.com:root", map[string]string{"alice@example.com": "root"}, false},
		{"alice@example.com:root,bob@example.com:dave", map[string]string{"alice@example.com": "root", "bob@example.com": "dave"}, false},
		{" alice@example.com:root , bob@example.com:dave ", map[string]string{"alice@example.com": "root", "bob@example.com": "dave"}, false},
		{"*:root", map[string]string{"*": "root"}, false},
		{",,,", map[string]string{}, false},
		// Errors: missing user part.
		{"alice@example.com", nil, true},
		{"alice@example.com:", nil, true},
		{":root", nil, true},
	}
	for _, tt := range tests {
		got, err := parseSSHAllow(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseSSHAllow(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("parseSSHAllow(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for k, wantV := range tt.want {
			if gotV, ok := got[k]; !ok || gotV != wantV {
				t.Errorf("parseSSHAllow(%q)[%q] = %q, want %q", tt.input, k, gotV, wantV)
			}
		}
	}
}

func TestSSHAllowlist(t *testing.T) {
	tests := []struct {
		name     string
		allow    map[string]string
		login    string
		wantUser string
		wantOK   bool
	}{
		{"empty denies all", nil, "anyone@example.com", "", false},
		{"match returns user", map[string]string{"alice@example.com": "root"}, "alice@example.com", "root", true},
		{"no match", map[string]string{"alice@example.com": "root"}, "bob@example.com", "", false},
		{"multiple entries match second", map[string]string{"alice@example.com": "root", "bob@example.com": "dave"}, "bob@example.com", "dave", true},
		{"multiple entries no match", map[string]string{"alice@example.com": "root", "bob@example.com": "dave"}, "eve@example.com", "", false},
		{"case sensitive", map[string]string{"Alice@example.com": "root"}, "alice@example.com", "", false},
		{"wildcard allows all", map[string]string{"*": "guest"}, "anyone@example.com", "guest", true},
		{"exact match takes precedence over wildcard", map[string]string{"alice@example.com": "alice", "*": "guest"}, "alice@example.com", "alice", true},
		{"wildcard used for non-exact", map[string]string{"alice@example.com": "alice", "*": "guest"}, "bob@example.com", "guest", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &sshServer{allow: tt.allow}
			gotUser, gotOK := s.isAllowed(tt.login)
			if gotOK != tt.wantOK {
				t.Errorf("isAllowed(%q) ok = %v, want %v", tt.login, gotOK, tt.wantOK)
			}
			if gotUser != tt.wantUser {
				t.Errorf("isAllowed(%q) user = %q, want %q", tt.login, gotUser, tt.wantUser)
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

func TestParsePasswdUser(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		username  string
		wantFound bool
		wantEntry passwdEntry
	}{
		{
			name:      "normal root entry",
			content:   "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:Nobody:/:/usr/bin/nologin\n",
			username:  "root",
			wantFound: true,
			wantEntry: passwdEntry{Username: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"},
		},
		{
			name:      "root with zsh",
			content:   "root:x:0:0:root:/root:/bin/zsh\n",
			username:  "root",
			wantFound: true,
			wantEntry: passwdEntry{Username: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/zsh"},
		},
		{
			name:      "root not present",
			content:   "nobody:x:65534:65534:Nobody:/:/usr/bin/nologin\n",
			username:  "root",
			wantFound: false,
		},
		{
			name:      "empty file",
			content:   "",
			username:  "root",
			wantFound: false,
		},
		{
			name:      "malformed lines",
			content:   "garbage\nroot:x:0:0\nmore garbage\n",
			username:  "root",
			wantFound: false,
		},
		{
			name:      "root with empty shell field",
			content:   "root:x:0:0:root:/root:\n",
			username:  "root",
			wantFound: true,
			wantEntry: passwdEntry{Username: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/sh"},
		},
		{
			name:      "comment lines skipped",
			content:   "# comment\nroot:x:0:0:root:/root:/bin/bash\n",
			username:  "root",
			wantFound: true,
			wantEntry: passwdEntry{Username: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"},
		},
		{
			name:      "lookup non-root user",
			content:   "root:x:0:0:root:/root:/bin/bash\nstephen:x:1000:1000:Stephen:/home/stephen:/bin/fish\n",
			username:  "stephen",
			wantFound: true,
			wantEntry: passwdEntry{Username: "stephen", UID: 1000, GID: 1000, Home: "/home/stephen", Shell: "/bin/fish"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := parsePasswdUser(strings.NewReader(tt.content), tt.username)
			if found != tt.wantFound {
				t.Errorf("parsePasswdUser(%q) found = %v, want %v", tt.username, found, tt.wantFound)
				return
			}
			if found && got != tt.wantEntry {
				t.Errorf("parsePasswdUser(%q) = %+v, want %+v", tt.username, got, tt.wantEntry)
			}
		})
	}
}

func TestBaseEnvForUser(t *testing.T) {
	entry := passwdEntry{Username: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"}
	env := baseEnvForUser(entry)
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

	// Verify non-root user env.
	entry2 := passwdEntry{Username: "dave", UID: 1000, GID: 1000, Home: "/home/dave", Shell: "/bin/zsh"}
	env2 := baseEnvForUser(entry2)
	got2 := make(map[string]string)
	for _, e := range env2 {
		k, v, _ := strings.Cut(e, "=")
		got2[k] = v
	}
	if got2["HOME"] != "/home/dave" {
		t.Errorf("HOME = %q, want /home/dave", got2["HOME"])
	}
	if got2["USER"] != "dave" {
		t.Errorf("USER = %q, want dave", got2["USER"])
	}
	if got2["SHELL"] != "/bin/zsh" {
		t.Errorf("SHELL = %q, want /bin/zsh", got2["SHELL"])
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
	// Write a pidfile for the test — PID 1 won't be validated since we
	// can't stat /proc/1/ns/net reliably, but the SSH server just needs
	// a valid pidfilePath to construct; containerPID() isn't called in
	// this test (nsenter would fail anyway without a real container).
	pidfile := filepath.Join(stateDir, "test.pid")
	if err := os.WriteFile(pidfile, []byte("1\n"), 0644); err != nil {
		t.Fatalf("writing pidfile: %v", err)
	}
	sshSrv, err := newSSHServer(srv1, "/proc/1/ns/net", pidfile, stateDir, map[string]string{"*": "root"}, nil)
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

