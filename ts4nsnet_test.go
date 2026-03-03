// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// --- Layer 1: Unit tests (no root, no network) ---

func TestResolveNSPath(t *testing.T) {
	tests := []struct {
		nsArg     string
		netnsType string
		want      string
		wantErr   bool
	}{
		{"/run/netns/test", "path", "/run/netns/test", false},
		{"12345", "pid", "/proc/12345/ns/net", false},
		{"/some/path", "path", "/some/path", false},
		{"1", "", "/proc/1/ns/net", false},
		{"../../etc", "pid", "", true},
		{"notanumber", "", "", true},
		{"12345", "paht", "", true},
		{"12345", "unknown", "", true},
	}
	for _, tt := range tests {
		got, err := resolveNSPath(tt.nsArg, tt.netnsType)
		if (err != nil) != tt.wantErr {
			t.Errorf("resolveNSPath(%q, %q) error = %v, wantErr %v", tt.nsArg, tt.netnsType, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("resolveNSPath(%q, %q) = %q, want %q", tt.nsArg, tt.netnsType, got, tt.want)
		}
	}
}

func TestParseEnvConfig(t *testing.T) {
	// Missing authkey.
	t.Setenv("TS_AUTHKEY", "")
	t.Setenv("TS_HOSTNAME", "test")
	t.Setenv("TS_EXIT_NODE", "")
	t.Setenv("TS_CONTROL_URL", "")
	_, err := parseEnvConfig()
	if err == nil {
		t.Fatal("expected error for missing TS_AUTHKEY")
	}

	// Missing hostname.
	t.Setenv("TS_AUTHKEY", "tskey-auth-test")
	t.Setenv("TS_HOSTNAME", "")
	_, err = parseEnvConfig()
	if err == nil {
		t.Fatal("expected error for missing TS_HOSTNAME")
	}

	// Valid config.
	t.Setenv("TS_AUTHKEY", "tskey-auth-test")
	t.Setenv("TS_HOSTNAME", "myhost")
	t.Setenv("TS_EXIT_NODE", "100.64.1.1")
	t.Setenv("TS_CONTROL_URL", "https://control.example.com")
	t.Setenv("TS_STATE_DIR", "/tmp/ts4nsnet-test")
	cfg, err := parseEnvConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AuthKey != "tskey-auth-test" {
		t.Errorf("AuthKey = %q, want %q", cfg.AuthKey, "tskey-auth-test")
	}
	if cfg.Hostname != "myhost" {
		t.Errorf("Hostname = %q, want %q", cfg.Hostname, "myhost")
	}
	if cfg.ExitNode != "100.64.1.1" {
		t.Errorf("ExitNode = %q, want %q", cfg.ExitNode, "100.64.1.1")
	}
	if cfg.ControlURL != "https://control.example.com" {
		t.Errorf("ControlURL = %q, want %q", cfg.ControlURL, "https://control.example.com")
	}
	if cfg.StateDir != "/tmp/ts4nsnet-test" {
		t.Errorf("StateDir = %q, want %q", cfg.StateDir, "/tmp/ts4nsnet-test")
	}

	// StateDir defaults to empty when not set.
	t.Setenv("TS_STATE_DIR", "")
	cfg, err = parseEnvConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.StateDir != "" {
		t.Errorf("StateDir = %q, want empty", cfg.StateDir)
	}

	// Invalid hostnames.
	for _, bad := range []string{
		"../etc/passwd",
		"-leading-hyphen",
		"trailing-hyphen-",
		"has spaces",
		"UPPERCASE",
		"has.dots",
		"has/slash",
		"",
	} {
		t.Setenv("TS_HOSTNAME", bad)
		if bad == "" {
			// Empty hostname is caught by the earlier check.
			continue
		}
		_, err = parseEnvConfig()
		if err == nil {
			t.Errorf("expected error for hostname %q, got nil", bad)
		}
	}

	// Valid hostnames.
	for _, good := range []string{
		"a",
		"myhost",
		"my-container-1",
		"x" + string(make([]byte, 0)), // single char
	} {
		t.Setenv("TS_HOSTNAME", good)
		_, err = parseEnvConfig()
		if err != nil {
			t.Errorf("unexpected error for hostname %q: %v", good, err)
		}
	}
}

func TestValidateMTU(t *testing.T) {
	tests := []struct {
		mtu     int
		wantErr bool
	}{
		{1500, false},
		{1280, false},
		{65535, false},
		{1279, true},
		{65536, true},
		{0, true},
		{-1, true},
	}
	for _, tt := range tests {
		err := validateMTU(tt.mtu)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateMTU(%d) error = %v, wantErr %v", tt.mtu, err, tt.wantErr)
		}
	}
}

func TestFdTUNCloseEvents(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer w.Close()

	dev := newFDTUN(r, "test0", 1500)

	// Drain the initial EventUp.
	ev := <-dev.Events()
	if ev != tun.EventUp {
		t.Fatalf("expected EventUp, got %v", ev)
	}

	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Should receive EventDown.
	ev = <-dev.Events()
	if ev != tun.EventDown {
		t.Fatalf("expected EventDown, got %v", ev)
	}

	// Channel should be closed.
	_, ok := <-dev.Events()
	if ok {
		t.Fatal("expected events channel to be closed")
	}
}

func TestIgnoredFlags(t *testing.T) {
	args := []string{
		"-c",
		"-r", "3",
		"-e", "4",
		"--mtu=1500",
		"--netns-type=path",
		"--cidr=10.0.2.0/24",
		"--disable-host-loopback",
		"--enable-sandbox",
		"--enable-seccomp",
		"--enable-ipv6",
		"--api-socket=/tmp/test.sock",
		"/run/netns/test",
		"tap0",
	}

	fs := newTestFlagSet()
	if err := fs.Parse(args); err != nil {
		t.Fatalf("flag parsing failed: %v", err)
	}
	positional := fs.Args()
	if len(positional) != 2 {
		t.Fatalf("expected 2 positional args, got %d: %v", len(positional), positional)
	}
	if positional[0] != "/run/netns/test" {
		t.Errorf("nsPath = %q, want /run/netns/test", positional[0])
	}
	if positional[1] != "tap0" {
		t.Errorf("tunName = %q, want tap0", positional[1])
	}
}

// newTestFlagSet creates a flag.FlagSet with the same flags as main().
func newTestFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("ts4nsnet-test", flag.ContinueOnError)
	fs.Bool("c", false, "configure interface")
	fs.Int("r", -1, "ready fd")
	fs.Int("e", -1, "exit fd")
	fs.Int("mtu", 1500, "MTU")
	fs.String("netns-type", "path", "namespace type")
	fs.String("cidr", "", "ignored")
	fs.Bool("disable-host-loopback", false, "ignored")
	fs.Bool("enable-sandbox", false, "ignored")
	fs.Bool("enable-seccomp", false, "ignored")
	fs.Bool("enable-ipv6", false, "ignored")
	fs.String("api-socket", "", "ignored")
	return fs
}

// --- Layer 2: tsnet integration tests (no root, fake control + chanTUN) ---

// chanTUN is a tun.Device backed by channels for packet I/O in tests.
type chanTUN struct {
	Inbound  chan []byte // packets written to TUN
	Outbound chan []byte // packets to read from TUN
	closed   chan struct{}
	events   chan tun.Event
}

func newChanTUN() *chanTUN {
	ct := &chanTUN{
		Inbound:  make(chan []byte, 10),
		Outbound: make(chan []byte, 10),
		closed:   make(chan struct{}),
		events:   make(chan tun.Event, 1),
	}
	ct.events <- tun.EventUp
	return ct
}

func (ct *chanTUN) File() *os.File { panic("not implemented") }

func (ct *chanTUN) Close() error {
	select {
	case <-ct.closed:
	default:
		close(ct.closed)
		close(ct.Inbound)
	}
	return nil
}

func (ct *chanTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-ct.closed:
		return 0, io.EOF
	case pkt := <-ct.Outbound:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	}
}

func (ct *chanTUN) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		select {
		case <-ct.closed:
			return written, errors.New("closed")
		case ct.Inbound <- slices.Clone(pkt):
		}
		written++
	}
	return written, nil
}

func (ct *chanTUN) MTU() (int, error)        { return 1280, nil }
func (ct *chanTUN) Name() (string, error)    { return "chantun", nil }
func (ct *chanTUN) Events() <-chan tun.Event { return ct.events }
func (ct *chanTUN) BatchSize() int           { return 1 }

// startTestControl sets up a fake DERP + control server for testing.
func startTestControl(t *testing.T) (controlURL string, control *testcontrol.Server) {
	t.Helper()
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control = &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "ts4nsnet-test.ts.net",
		Logf:           t.Logf,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	controlURL = control.HTTPTestServer.URL
	t.Logf("testcontrol listening on %s", controlURL)
	return controlURL, control
}

func TestTsnetConnectsToControl(t *testing.T) {
	controlURL, _ := startTestControl(t)

	fakeTun := newChanTUN()
	srv := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: controlURL,
		Hostname:   "test-container",
		Store:      new(mem.Store),
		Ephemeral:  true,
		Tun:        fakeTun,
	}
	t.Cleanup(func() { srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := srv.Up(ctx)
	if err != nil {
		t.Fatalf("srv.Up: %v", err)
	}
	if len(status.TailscaleIPs) == 0 {
		t.Fatal("no TailscaleIPs assigned")
	}
	t.Logf("assigned IPs: %v", status.TailscaleIPs)
}

func TestTwoNodesCanCommunicate(t *testing.T) {
	controlURL, _ := startTestControl(t)

	tun1 := newChanTUN()
	srv1 := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: controlURL,
		Hostname:   "node1",
		Store:      new(mem.Store),
		Ephemeral:  true,
		Tun:        tun1,
	}
	t.Cleanup(func() { srv1.Close() })

	tun2 := newChanTUN()
	srv2 := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: controlURL,
		Hostname:   "node2",
		Store:      new(mem.Store),
		Ephemeral:  true,
		Tun:        tun2,
	}
	t.Cleanup(func() { srv2.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	status1, err := srv1.Up(ctx)
	if err != nil {
		t.Fatalf("srv1.Up: %v", err)
	}
	status2, err := srv2.Up(ctx)
	if err != nil {
		t.Fatalf("srv2.Up: %v", err)
	}

	t.Logf("node1 IPs: %v", status1.TailscaleIPs)
	t.Logf("node2 IPs: %v", status2.TailscaleIPs)

	if len(status1.TailscaleIPs) == 0 || len(status2.TailscaleIPs) == 0 {
		t.Fatal("one or both nodes have no IPs")
	}
}

func TestExitNodeConfig(t *testing.T) {
	controlURL, _ := startTestControl(t)

	fakeTun := newChanTUN()
	srv := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: controlURL,
		Hostname:   "test-exitnode",
		Store:      new(mem.Store),
		Ephemeral:  true,
		Tun:        fakeTun,
	}
	t.Cleanup(func() { srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := srv.Up(ctx)
	if err != nil {
		t.Fatalf("srv.Up: %v", err)
	}

	lc, err := srv.LocalClient()
	if err != nil {
		t.Fatalf("LocalClient: %v", err)
	}

	prefs, err := lc.GetPrefs(ctx)
	if err != nil {
		t.Fatalf("GetPrefs: %v", err)
	}
	if prefs.ExitNodeIP.IsValid() {
		t.Fatalf("exit node IP should not be set initially, got %v", prefs.ExitNodeIP)
	}
}

// --- Layer 3: Namespace + TUN creation (requires root) ---

func TestCreateTUNInNamespace(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for network namespace operations")
	}

	nsName := "ts4nsnet-test-tun"

	if out, err := exec.Command("ip", "netns", "add", nsName).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() {
		exec.Command("ip", "netns", "del", nsName).Run()
	})

	nsPath := "/run/netns/" + nsName
	tunDev, err := createTUNInNamespace(nsPath, "tun0", 1500)
	if err != nil {
		t.Fatalf("createTUNInNamespace: %v", err)
	}
	defer tunDev.Close()

	name, err := tunDev.Name()
	if err != nil {
		t.Fatalf("tunDev.Name: %v", err)
	}
	t.Logf("TUN device name: %s", name)

	gotMTU, err := tunDev.MTU()
	if err != nil {
		t.Fatalf("tunDev.MTU: %v", err)
	}
	t.Logf("TUN device MTU: %d", gotMTU)
}

func TestConfigureInterface(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for network namespace operations")
	}

	nsName := "ts4nsnet-test-cfg"

	if out, err := exec.Command("ip", "netns", "add", nsName).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() {
		exec.Command("ip", "netns", "del", nsName).Run()
	})

	nsPath := "/run/netns/" + nsName
	tunDev, err := createTUNInNamespace(nsPath, "tun0", 1500)
	if err != nil {
		t.Fatalf("createTUNInNamespace: %v", err)
	}
	defer tunDev.Close()

	ip4 := netip.MustParseAddr("100.64.0.1")
	ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1")

	if err := configureInterface(nsPath, "tun0", ip4, ip6, 1500); err != nil {
		t.Fatalf("configureInterface: %v", err)
	}

	// Verify IP is assigned.
	out, err := exec.Command("ip", "netns", "exec", nsName, "ip", "addr", "show", "tun0").CombinedOutput()
	if err != nil {
		t.Fatalf("ip addr show: %v: %s", err, out)
	}
	t.Logf("interface config:\n%s", out)

	if !strings.Contains(string(out), "100.64.0.1") {
		t.Error("IPv4 address not found in interface config")
	}

	// Verify default route.
	out, err = exec.Command("ip", "netns", "exec", nsName, "ip", "route", "show", "default").CombinedOutput()
	if err != nil {
		t.Fatalf("ip route show: %v: %s", err, out)
	}
	t.Logf("routes:\n%s", out)
	if !strings.Contains(string(out), "default") {
		t.Error("default route not found")
	}
}

// --- Layer 4: Full end-to-end (requires root) ---

func TestFullFlow(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	controlURL, _ := startTestControl(t)
	nsName := "ts4nsnet-test-full"

	if out, err := exec.Command("ip", "netns", "add", nsName).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() {
		exec.Command("ip", "netns", "del", nsName).Run()
	})

	nsPath := "/run/netns/" + nsName

	tunDev, err := createTUNInNamespace(nsPath, "tun0", 1500)
	if err != nil {
		t.Fatalf("createTUNInNamespace: %v", err)
	}

	srv := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: controlURL,
		Hostname:   "full-test",
		Store:      new(mem.Store),
		Ephemeral:  true,
		Tun:        tunDev,
	}
	t.Cleanup(func() { srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	status, err := srv.Up(ctx)
	if err != nil {
		t.Fatalf("srv.Up: %v", err)
	}
	if len(status.TailscaleIPs) == 0 {
		t.Fatal("no IPs assigned")
	}
	t.Logf("assigned IPs: %v", status.TailscaleIPs)

	var ip4, ip6 netip.Addr
	for _, ip := range status.TailscaleIPs {
		if ip.Is4() {
			ip4 = ip
		}
		if ip.Is6() {
			ip6 = ip
		}
	}

	if err := configureInterface(nsPath, "tun0", ip4, ip6, 1500); err != nil {
		t.Fatalf("configureInterface: %v", err)
	}

	out, err := exec.Command("ip", "netns", "exec", nsName, "ip", "addr", "show", "tun0").CombinedOutput()
	if err != nil {
		t.Fatalf("ip addr show: %v: %s", err, out)
	}
	t.Logf("interface:\n%s", out)

	if ip4.IsValid() && !strings.Contains(string(out), ip4.String()) {
		t.Errorf("assigned IPv4 %v not found in interface config", ip4)
	}
}
