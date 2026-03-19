// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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

// --- Tier 1: Unit tests (no root, no network) ---

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

// --- Daemon PID identity tests ---

func TestProcessStarttime(t *testing.T) {
	// Our own PID should have a readable starttime.
	st, err := processStarttime(os.Getpid())
	if err != nil {
		t.Fatalf("processStarttime(self) error = %v", err)
	}
	if st == "" {
		t.Error("processStarttime(self) returned empty string")
	}
	// Starttime should be a numeric value.
	for _, c := range st {
		if c < '0' || c > '9' {
			t.Errorf("processStarttime(self) = %q, contains non-digit", st)
			break
		}
	}
}

func TestDaemonPIDRoundTrip(t *testing.T) {
	dir := t.TempDir()
	myPID := os.Getpid()

	t.Run("write and read back", func(t *testing.T) {
		if err := writeDaemonPID(dir, myPID); err != nil {
			t.Fatalf("writeDaemonPID() error = %v", err)
		}
		info, err := readDaemonPID(dir)
		if err != nil {
			t.Fatalf("readDaemonPID() error = %v", err)
		}
		if info.PID != myPID {
			t.Errorf("PID = %d, want %d", info.PID, myPID)
		}
		if info.Starttime == "" {
			t.Error("Starttime is empty")
		}
	})

	t.Run("rejects bare PID format", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "daemon.pid"), []byte("42\n"), 0600)
		_, err := readDaemonPID(dir)
		if err == nil {
			t.Error("readDaemonPID(bare PID) = nil, want error")
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		_, err := readDaemonPID(t.TempDir())
		if err == nil {
			t.Error("readDaemonPID(missing) = nil, want error")
		}
	})
}

// --- Plugin JSON tests ---

func TestPluginJSON(t *testing.T) {
	t.Run("PluginInfo round-trip", func(t *testing.T) {
		info := PluginInfo{Version: "0.1.0", APIVersion: "1.0.0"}
		data, err := json.Marshal(info)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got PluginInfo
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got != info {
			t.Errorf("round-trip: got %+v, want %+v", got, info)
		}
	})

	t.Run("NetworkPluginExec decode", func(t *testing.T) {
		input := `{
			"container_id": "abc123",
			"container_name": "nginx-demo",
			"network": {
				"name": "tailscale-net",
				"id": "def456",
				"driver": "netavark-tailscale-plugin",
				"dns_enabled": false,
				"internal": false,
				"ipv6_enabled": false,
				"options": {"control_url": "https://control.example.com"}
			},
			"network_options": {
				"interface_name": "eth0",
				"options": {"ts_hostname": "nginx-demo"}
			}
		}`
		var exec NetworkPluginExec
		if err := json.Unmarshal([]byte(input), &exec); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if exec.ContainerID != "abc123" {
			t.Errorf("ContainerID = %q, want %q", exec.ContainerID, "abc123")
		}
		if exec.Network.Options["control_url"] != "https://control.example.com" {
			t.Errorf("network option control_url = %q", exec.Network.Options["control_url"])
		}
		if exec.NetworkOptions.Options["ts_hostname"] != "nginx-demo" {
			t.Errorf("per-container option ts_hostname = %q", exec.NetworkOptions.Options["ts_hostname"])
		}
	})

	t.Run("StatusBlock encode", func(t *testing.T) {
		status := StatusBlock{
			DNSServerIPs:     []string{"100.100.100.100"},
			DNSSearchDomains: []string{},
			Interfaces: map[string]NetInterface{
				"tailscale0": {
					MacAddress: "02:00:64:40:00:01",
					Subnets: []NetAddress{
						{IPNet: "100.64.0.1/32"},
					},
				},
			},
		}
		data, err := json.Marshal(status)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		// Verify it round-trips.
		var got StatusBlock
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got.Interfaces) != 1 {
			t.Errorf("expected 1 interface, got %d", len(got.Interfaces))
		}
		if iface, ok := got.Interfaces["tailscale0"]; !ok {
			t.Error("missing tailscale0 interface")
		} else if len(iface.Subnets) != 1 || iface.Subnets[0].IPNet != "100.64.0.1/32" {
			t.Errorf("unexpected subnets: %+v", iface.Subnets)
		}
	})
}

func TestStatusBlock(t *testing.T) {
	ready := &DaemonReady{
		IPv4: "100.64.0.1",
		IPv6: "fd7a:115c:a1e0::1",
		MAC:  "02:00:64:40:00:01",
	}
	status := buildStatusBlock(ready)

	if len(status.DNSServerIPs) != 1 || status.DNSServerIPs[0] != "100.100.100.100" {
		t.Errorf("DNSServerIPs = %v, want [100.100.100.100]", status.DNSServerIPs)
	}

	iface, ok := status.Interfaces["tailscale0"]
	if !ok {
		t.Fatal("missing tailscale0 interface")
	}
	if iface.MacAddress != "02:00:64:40:00:01" {
		t.Errorf("MAC = %q", iface.MacAddress)
	}
	if len(iface.Subnets) != 2 {
		t.Fatalf("expected 2 subnets, got %d", len(iface.Subnets))
	}
	if iface.Subnets[0].IPNet != "100.64.0.1/32" {
		t.Errorf("IPv4 subnet = %q", iface.Subnets[0].IPNet)
	}
	if iface.Subnets[1].IPNet != "fd7a:115c:a1e0::1/128" {
		t.Errorf("IPv6 subnet = %q", iface.Subnets[1].IPNet)
	}
}

func TestConfigMerge(t *testing.T) {
	t.Run("env vars override options", func(t *testing.T) {
		t.Setenv("TS_AUTHKEY", "tskey-from-env")
		t.Setenv("TS_HOSTNAME", "env-host")
		t.Setenv("TS_CONTROL_URL", "")
		t.Setenv("TS_EXIT_NODE", "")
		t.Setenv("TS_SSH_ALLOW", "")
		t.Setenv("TS_PIDFILE", "")
		t.Setenv("TS_SSH_ACCEPT_ENV", "")

		input := &NetworkPluginExec{
			ContainerID:   "abc123",
			ContainerName: "test-ctr",
			Network: Network{
				Options: map[string]string{
					"hostname":    "net-host",
					"control_url": "https://net-control.example.com",
				},
			},
			NetworkOptions: PerNetworkOptions{
				Options: map[string]string{
					"ts_hostname": "ctr-host",
				},
			},
		}

		cfg, err := buildDaemonConfig("/run/netns/test", input)
		if err != nil {
			t.Fatalf("buildDaemonConfig: %v", err)
		}
		// Env TS_HOSTNAME overrides per-container ts_hostname which overrides network hostname.
		if cfg.Hostname != "env-host" {
			t.Errorf("Hostname = %q, want %q", cfg.Hostname, "env-host")
		}
		if cfg.AuthKey != "tskey-from-env" {
			t.Errorf("AuthKey = %q, want %q", cfg.AuthKey, "tskey-from-env")
		}
		// ControlURL from network option (env is empty).
		if cfg.ControlURL != "https://net-control.example.com" {
			t.Errorf("ControlURL = %q, want %q", cfg.ControlURL, "https://net-control.example.com")
		}
	})

	t.Run("per-container overrides network", func(t *testing.T) {
		t.Setenv("TS_AUTHKEY", "tskey-test")
		t.Setenv("TS_HOSTNAME", "")
		t.Setenv("TS_CONTROL_URL", "")
		t.Setenv("TS_EXIT_NODE", "")
		t.Setenv("TS_SSH_ALLOW", "")
		t.Setenv("TS_PIDFILE", "")
		t.Setenv("TS_SSH_ACCEPT_ENV", "")

		input := &NetworkPluginExec{
			ContainerID:   "abc123",
			ContainerName: "test-ctr",
			Network: Network{
				Options: map[string]string{
					"hostname": "net-host",
				},
			},
			NetworkOptions: PerNetworkOptions{
				Options: map[string]string{
					"ts_hostname": "ctr-host",
				},
			},
		}

		cfg, err := buildDaemonConfig("/run/netns/test", input)
		if err != nil {
			t.Fatalf("buildDaemonConfig: %v", err)
		}
		if cfg.Hostname != "ctr-host" {
			t.Errorf("Hostname = %q, want %q", cfg.Hostname, "ctr-host")
		}
	})

	t.Run("defaults to container name", func(t *testing.T) {
		t.Setenv("TS_AUTHKEY", "tskey-test")
		t.Setenv("TS_HOSTNAME", "")
		t.Setenv("TS_CONTROL_URL", "")
		t.Setenv("TS_EXIT_NODE", "")
		t.Setenv("TS_SSH_ALLOW", "")
		t.Setenv("TS_PIDFILE", "")
		t.Setenv("TS_SSH_ACCEPT_ENV", "")

		input := &NetworkPluginExec{
			ContainerID:   "abc123",
			ContainerName: "my-container",
		}

		cfg, err := buildDaemonConfig("/run/netns/test", input)
		if err != nil {
			t.Fatalf("buildDaemonConfig: %v", err)
		}
		if cfg.Hostname != "my-container" {
			t.Errorf("Hostname = %q, want %q", cfg.Hostname, "my-container")
		}
	})

	t.Run("missing authkey errors", func(t *testing.T) {
		t.Setenv("TS_AUTHKEY", "")
		t.Setenv("TS_HOSTNAME", "")
		t.Setenv("TS_CONTROL_URL", "")
		t.Setenv("TS_EXIT_NODE", "")
		t.Setenv("TS_SSH_ALLOW", "")
		t.Setenv("TS_PIDFILE", "")
		t.Setenv("TS_SSH_ACCEPT_ENV", "")

		input := &NetworkPluginExec{
			ContainerID:   "abc123",
			ContainerName: "test-ctr",
		}

		_, err := buildDaemonConfig("/run/netns/test", input)
		if err == nil {
			t.Fatal("expected error for missing auth key")
		}
		if !strings.Contains(err.Error(), "TS_AUTHKEY") {
			t.Errorf("error should mention TS_AUTHKEY, got: %v", err)
		}
	})

	t.Run("invalid hostname errors", func(t *testing.T) {
		t.Setenv("TS_AUTHKEY", "tskey-test")
		t.Setenv("TS_HOSTNAME", "UPPERCASE")
		t.Setenv("TS_CONTROL_URL", "")
		t.Setenv("TS_EXIT_NODE", "")
		t.Setenv("TS_SSH_ALLOW", "")
		t.Setenv("TS_PIDFILE", "")
		t.Setenv("TS_SSH_ACCEPT_ENV", "")

		input := &NetworkPluginExec{
			ContainerID:   "abc123",
			ContainerName: "test-ctr",
		}

		_, err := buildDaemonConfig("/run/netns/test", input)
		if err == nil {
			t.Fatal("expected error for invalid hostname")
		}
	})

	t.Run("ssh without pidfile errors", func(t *testing.T) {
		t.Setenv("TS_AUTHKEY", "tskey-test")
		t.Setenv("TS_HOSTNAME", "test-host")
		t.Setenv("TS_CONTROL_URL", "")
		t.Setenv("TS_EXIT_NODE", "")
		t.Setenv("TS_SSH_ALLOW", "*:root")
		t.Setenv("TS_PIDFILE", "")
		t.Setenv("TS_SSH_ACCEPT_ENV", "")

		input := &NetworkPluginExec{
			ContainerID:   "abc123",
			ContainerName: "test-ctr",
		}

		_, err := buildDaemonConfig("/run/netns/test", input)
		if err == nil {
			t.Fatal("expected error for SSH without pidfile")
		}
	})
}

// --- Tier 2: tsnet integration tests (no root, fake control + chanTUN) ---

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
		MagicDNSDomain: "netavark-tailscale-plugin-test.ts.net",
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

// --- Tier 3: Namespace + TUN creation (requires root) ---

func TestCreateTUNInNamespace(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for network namespace operations")
	}

	nsName := "netavark-tailscale-plugin-test-tun"

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

	nsName := "netavark-tailscale-plugin-test-cfg"

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

// --- Tier 4: Full end-to-end (requires root) ---

func TestFullFlow(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	controlURL, _ := startTestControl(t)
	nsName := "netavark-tailscale-plugin-test-full"

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
