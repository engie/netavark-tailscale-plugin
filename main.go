// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// ts4nsnet is a rootless container networking tool that acts as a drop-in
// replacement for slirp4netns. It creates a TUN device inside a container's
// network namespace and bridges traffic onto the tailnet via tsnet, making
// the container appear as its own ephemeral Tailscale node.
//
// Usage (via podman):
//
//	TS_AUTHKEY=tskey-auth-... TS_HOSTNAME=mycontainer \
//	  podman run --rm -it --network-cmd-path=/path/to/ts4nsnet --network slirp4netns alpine sh
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
)

// envConfig holds configuration read from environment variables.
type envConfig struct {
	AuthKey    string
	Hostname   string
	ExitNode   string
	ControlURL string
	StateDir   string
	SSHAllow   []string // login names allowed to SSH; non-empty enables SSH
}

// validHostname matches a Tailscale hostname: lowercase alphanumeric and
// hyphens, no leading/trailing hyphen, 1-63 characters (DNS label rules).
// This also guarantees the value is a safe single path element, since the
// hostname is used to construct the temp state directory path.
var validHostname = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// parseEnvConfig reads and validates ts4nsnet configuration from environment
// variables. Returns an error if required variables are missing.
func parseEnvConfig() (envConfig, error) {
	c := envConfig{
		AuthKey:    os.Getenv("TS_AUTHKEY"),
		Hostname:   os.Getenv("TS_HOSTNAME"),
		ExitNode:   os.Getenv("TS_EXIT_NODE"),
		ControlURL: os.Getenv("TS_CONTROL_URL"),
		StateDir:   os.Getenv("TS_STATE_DIR"),
	}
	if c.AuthKey == "" {
		return c, fmt.Errorf("TS_AUTHKEY environment variable is required")
	}
	if c.Hostname == "" {
		return c, fmt.Errorf("TS_HOSTNAME environment variable is required")
	}
	if !validHostname.MatchString(c.Hostname) {
		return c, fmt.Errorf("TS_HOSTNAME %q is not a valid hostname (lowercase alphanumeric and hyphens, 1-63 chars)", c.Hostname)
	}
	if allow := os.Getenv("TS_SSH_ALLOW"); allow != "" {
		c.SSHAllow = parseSSHAllow(allow)
	}
	return c, nil
}

// warnUnsupportedFlags logs warnings for security flags that are accepted
// for slirp4netns compatibility but cannot be implemented in ts4nsnet.
// The Go runtime's syscall requirements conflict with slirp4netns's
// seccomp policy, and ts4nsnet's use of setns prevents mount sandboxing.
func warnUnsupportedFlags(enableSandbox, enableSeccomp bool) {
	if enableSandbox {
		log.Printf("warning: --enable-sandbox is not supported by ts4nsnet and will be ignored")
	}
	if enableSeccomp {
		log.Printf("warning: --enable-seccomp is not supported by ts4nsnet and will be ignored")
	}
}

// validateMTU checks that the MTU is within a usable range.
// The minimum is 1280 (required by IPv6) and the maximum is 65535.
func validateMTU(mtu int) error {
	if mtu < 1280 || mtu > 65535 {
		return fmt.Errorf("MTU %d is out of range [1280, 65535]", mtu)
	}
	return nil
}

// resolveNSPath returns the network namespace path. If netnsType is "path",
// nsArg is returned as-is. Otherwise it is treated as a PID and resolved to
// /proc/<pid>/ns/net.
func resolveNSPath(nsArg, netnsType string) (string, error) {
	switch netnsType {
	case "path":
		return nsArg, nil
	case "pid", "":
		if _, err := strconv.Atoi(nsArg); err != nil {
			return "", fmt.Errorf("invalid PID %q: %w", nsArg, err)
		}
		return "/proc/" + nsArg + "/ns/net", nil
	default:
		return "", fmt.Errorf("unknown --netns-type %q (expected \"path\" or \"pid\")", netnsType)
	}
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("ts4nsnet: ")

	// Handle --help before normal flag parsing.
	for _, arg := range os.Args[1:] {
		if arg == "--help" || arg == "-h" {
			// Podman calls the binary with --help to verify it's a valid
			// slirp4netns replacement. It checks for "slirp4netns" in the output.
			fmt.Println("slirp4netns (ts4nsnet - tailscale container networking)")
			fmt.Println("Usage: ts4nsnet [OPTIONS] NSPATH TUNNAME")
			fmt.Println()
			fmt.Println("Options:")
			fmt.Println("  -c                  configure interface")
			fmt.Println("  -r FD               ready fd")
			fmt.Println("  -e FD               exit fd")
			fmt.Println("  --mtu MTU           MTU (default 1500)")
			fmt.Println("  --netns-type TYPE   namespace type (default path)")
			fmt.Println("  --cidr CIDR         CIDR (ignored)")
			fmt.Println("  --disable-host-loopback  disable host loopback (ignored)")
			fmt.Println("  --enable-sandbox    enable sandbox (ignored)")
			fmt.Println("  --enable-seccomp    enable seccomp (ignored)")
			fmt.Println("  --enable-ipv6       enable IPv6 (ignored, always enabled)")
			fmt.Println("  --api-socket PATH   API socket (ignored)")
			fmt.Println()
			fmt.Println("Environment:")
			fmt.Println("  TS_AUTHKEY          Tailscale auth key (required)")
			fmt.Println("  TS_HOSTNAME         Tailscale hostname (required)")
			fmt.Println("  TS_EXIT_NODE        Exit node IP")
			fmt.Println("  TS_CONTROL_URL      Custom control server URL")
			fmt.Println("  TS_STATE_DIR        Persistent state directory")
			fmt.Println("  TS_SSH_ALLOW        Comma-separated allowlist of login names (* for all); enables SSH")
			fmt.Println("  TS_SSH_PID          Override container PID for nsenter")
			os.Exit(0)
		}
	}

	if err := run(); err != nil {
		log.Fatalf("%v", err)
	}
}

// run contains the main logic, separated from main() so that defers
// (particularly temp dir cleanup) execute even on error paths.
func run() error {
	// Slirp4netns-compatible flags. Podman constructs these.
	configure := flag.Bool("c", false, "configure interface")
	readyFD := flag.Int("r", -1, "ready fd")
	exitFD := flag.Int("e", -1, "exit fd")
	mtu := flag.Int("mtu", 1500, "MTU")
	netnsType := flag.String("netns-type", "path", "namespace type")

	// Ignored slirp4netns flags (accepted for compatibility).
	flag.String("cidr", "", "ignored")
	flag.Bool("disable-host-loopback", false, "ignored")
	enableSandbox := flag.Bool("enable-sandbox", false, "ignored")
	enableSeccomp := flag.Bool("enable-seccomp", false, "ignored")
	flag.Bool("enable-ipv6", false, "ignored")
	flag.String("api-socket", "", "ignored")

	flag.Parse()

	warnUnsupportedFlags(*enableSandbox, *enableSeccomp)

	if err := validateMTU(*mtu); err != nil {
		return err
	}

	args := flag.Args()
	if len(args) < 2 {
		return fmt.Errorf("usage: ts4nsnet [OPTIONS] NSPATH TUNNAME")
	}
	nsPath, err := resolveNSPath(args[0], *netnsType)
	if err != nil {
		return fmt.Errorf("resolving namespace path: %v", err)
	}
	tunName := args[1]

	cfg, err := parseEnvConfig()
	if err != nil {
		return err
	}
	// Clear sensitive env vars so they aren't exposed via /proc/<pid>/environ.
	os.Unsetenv("TS_AUTHKEY")

	// Create TUN device inside the container's network namespace.
	tunDev, err := createTUNInNamespace(nsPath, tunName, *mtu)
	if err != nil {
		return fmt.Errorf("creating TUN in namespace: %v", err)
	}

	// Set up a state directory for tsnet. If TS_STATE_DIR is set, use it
	// directly. Otherwise use a hostname-keyed directory under os.TempDir.
	// Using the hostname makes the path stable across container restarts
	// (so state doesn't accumulate) and unique across concurrent instances
	// (each container has a distinct tailnet hostname). The directory is
	// cleaned up on shutdown; if a previous instance was killed abruptly,
	// the surviving directory is simply reused on next start.
	stateDir := cfg.StateDir
	if stateDir == "" {
		stateDir = filepath.Join(os.TempDir(), "ts4nsnet-"+cfg.Hostname)
		if err := os.MkdirAll(stateDir, 0700); err != nil {
			return fmt.Errorf("creating state directory: %v", err)
		}
		defer os.RemoveAll(stateDir)
	}

	// Build tsnet server with the real TUN device.
	srv := &tsnet.Server{
		Hostname:  cfg.Hostname,
		AuthKey:   cfg.AuthKey,
		Ephemeral: true,
		Store:     new(mem.Store),
		Tun:       tunDev,
		Dir:       stateDir,
	}
	if cfg.ControlURL != "" {
		srv.ControlURL = cfg.ControlURL
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	status, err := srv.Up(ctx)
	if err != nil {
		return fmt.Errorf("tsnet.Up: %v", err)
	}

	// Extract assigned tailnet IPs.
	var ip4, ip6 netip.Addr
	for _, ip := range status.TailscaleIPs {
		if ip.Is4() && !ip4.IsValid() {
			ip4 = ip
		}
		if ip.Is6() && !ip6.IsValid() {
			ip6 = ip
		}
	}
	log.Printf("tailnet IPs: v4=%v v6=%v", ip4, ip6)

	// Set exit node if requested.
	if cfg.ExitNode != "" {
		exitIP, err := netip.ParseAddr(cfg.ExitNode)
		if err != nil {
			return fmt.Errorf("parsing TS_EXIT_NODE %q: %v", cfg.ExitNode, err)
		}
		lc, err := srv.LocalClient()
		if err != nil {
			return fmt.Errorf("getting local client: %v", err)
		}
		_, err = lc.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs: ipn.Prefs{
				ExitNodeIP: exitIP,
			},
			ExitNodeIPSet: true,
		})
		if err != nil {
			return fmt.Errorf("setting exit node: %v", err)
		}
		log.Printf("exit node set to %v", exitIP)
	}

	// Configure the interface inside the container namespace.
	if *configure {
		if err := configureInterface(nsPath, tunName, ip4, ip6, *mtu); err != nil {
			return fmt.Errorf("configuring interface: %v", err)
		}
		log.Printf("interface %s configured", tunName)
	}

	// Verify DNS readiness before signaling to podman. srv.Up() waits
	// for ipn.Running which includes NetMap delivery, but we confirm
	// DNS is configured to catch any regressions early.
	// See: https://github.com/tailscale/tailscale/issues/1889
	lc, err := srv.LocalClient()
	if err != nil {
		return fmt.Errorf("getting local client: %v", err)
	}
	st, err := lc.Status(ctx)
	if err != nil {
		return fmt.Errorf("getting status: %v", err)
	}
	if st.CurrentTailnet != nil && st.CurrentTailnet.MagicDNSSuffix != "" {
		log.Printf("DNS ready (MagicDNS suffix: %q)", st.CurrentTailnet.MagicDNSSuffix)
	} else {
		log.Printf("warning: MagicDNS not detected; container DNS may not resolve tailnet names")
	}

	// Start SSH server if allowlist is configured.
	if len(cfg.SSHAllow) > 0 {
		sshSrv, err := newSSHServer(srv, nsPath, stateDir, cfg.SSHAllow)
		if err != nil {
			log.Printf("SSH server disabled: %v", err)
		} else {
			go func() {
				if err := sshSrv.run(ctx); err != nil && ctx.Err() == nil {
					log.Printf("SSH server error: %v", err)
				}
			}()
			log.Printf("SSH server listening on :22 (allow: %s)", strings.Join(cfg.SSHAllow, ", "))
		}
	}

	// Signal readiness to podman.
	if *readyFD >= 0 {
		f := os.NewFile(uintptr(*readyFD), "ready-fd")
		if f != nil {
			if _, err := f.Write([]byte("1")); err != nil {
				return fmt.Errorf("writing to ready fd: %v", err)
			}
			f.Close()
		}
	}

	// Wait for exit signal: exit-fd HUP, SIGTERM, or SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	exitCh := make(chan struct{})
	if *exitFD >= 0 {
		f := os.NewFile(uintptr(*exitFD), "exit-fd")
		if f != nil {
			go func() {
				buf := make([]byte, 1)
				// Read blocks until HUP/EOF.
				if _, err := f.Read(buf); err != nil {
					log.Printf("exit fd read error: %v", err)
				}
				close(exitCh)
			}()
		}
	}

	select {
	case <-sigCh:
		log.Printf("received signal, shutting down")
	case <-exitCh:
		log.Printf("exit fd closed, shutting down")
	}

	srv.Close()
	return nil
}

