// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
)

func cmdDaemon() error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "state directory containing config.json")
	fs.Parse(os.Args[2:])

	if *stateDir == "" {
		return fmt.Errorf("--state-dir is required")
	}

	// Read daemon config.
	configPath := filepath.Join(*stateDir, "config.json")
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	var cfg DaemonConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

	// Remove config.json immediately after reading — it contains the auth
	// key in plaintext and is never re-read.
	os.Remove(configPath)

	return runDaemon(&cfg, *stateDir)
}

func runDaemon(cfg *DaemonConfig, stateDir string) error {
	// Redirect logging to syslog/journald so logs survive after the
	// plugin process exits and its stderr pipe closes.
	if w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "netavark-tailscale-plugin"); err == nil {
		log.SetOutput(w)
	}

	// Clear sensitive data from process environment.
	os.Unsetenv("TS_AUTHKEY")

	// Create TUN device inside the container's network namespace.
	tunDev, err := createTUNInNamespace(cfg.NetNSPath, cfg.TUNName, cfg.MTU)
	if err != nil {
		return fmt.Errorf("creating TUN in namespace: %v", err)
	}

	// Set up tsnet state directory within our state dir.
	tsnetDir := filepath.Join(stateDir, "tsnet")
	if err := os.MkdirAll(tsnetDir, 0700); err != nil {
		return fmt.Errorf("creating tsnet state dir: %v", err)
	}

	srv := &tsnet.Server{
		Hostname:  cfg.Hostname,
		AuthKey:   cfg.AuthKey,
		Ephemeral: true,
		Store:     new(mem.Store),
		Tun:       tunDev,
		Dir:       tsnetDir,
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
			return fmt.Errorf("parsing exit_node %q: %v", cfg.ExitNode, err)
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
	if err := configureInterface(cfg.NetNSPath, cfg.TUNName, ip4, ip6, cfg.MTU); err != nil {
		return fmt.Errorf("configuring interface: %v", err)
	}
	log.Printf("interface %s configured", cfg.TUNName)

	// Check DNS readiness.
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
		sshSrv, err := newSSHServer(srv, cfg.NetNSPath, cfg.PidfilePath, stateDir, cfg.SSHAllow, cfg.SSHAcceptEnv)
		if err != nil {
			log.Printf("SSH server disabled: %v", err)
		} else {
			go func() {
				if err := sshSrv.run(ctx); err != nil && ctx.Err() == nil {
					log.Printf("SSH server error: %v", err)
				}
			}()
			var allowPairs []string
			for identity, user := range cfg.SSHAllow {
				allowPairs = append(allowPairs, identity+":"+user)
			}
			log.Printf("SSH server listening on :22 (allow: %s)", strings.Join(allowPairs, ", "))
		}
	}

	// Write ready.json to signal the plugin.
	ready := DaemonReady{}
	if ip4.IsValid() {
		ready.IPv4 = ip4.String()
	}
	if ip6.IsValid() {
		ready.IPv6 = ip6.String()
	}
	// Generate a deterministic MAC from the IPv4 address.
	if ip4.IsValid() {
		a := ip4.As4()
		ready.MAC = fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3])
	}

	readyPath := filepath.Join(stateDir, "ready.json")
	readyData, err := json.Marshal(ready)
	if err != nil {
		return fmt.Errorf("marshaling ready.json: %v", err)
	}
	if err := os.WriteFile(readyPath, readyData, 0644); err != nil {
		return fmt.Errorf("writing ready.json: %v", err)
	}
	log.Printf("ready (state dir: %s)", stateDir)

	// Wait for shutdown signal or netns disappearance.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Monitor the network namespace — if the container is gone and teardown
	// never ran, self-terminate to avoid orphaned Tailscale nodes.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if _, err := os.Stat(cfg.NetNSPath); err != nil {
				log.Printf("network namespace %s gone, self-terminating", cfg.NetNSPath)
				sigCh <- syscall.SIGTERM
				return
			}
		}
	}()

	<-sigCh
	log.Printf("shutting down")

	srv.Close()
	return nil
}
