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
	"tailscale.com/ipn/store"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
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

	// Use a persistent FileStore if a state directory is configured,
	// otherwise fall back to in-memory store.
	var stateStore ipn.StateStore
	var persistedStatePath string
	if cfg.StateDir != "" {
		if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
			return fmt.Errorf("creating persistent state dir: %v", err)
		}
		persistedStatePath = filepath.Join(cfg.StateDir, "tailscaled.state")
		s, err := store.NewFileStore(log.Printf, persistedStatePath)
		if err != nil {
			return fmt.Errorf("creating file store: %v", err)
		}
		stateStore = s
		log.Printf("using persistent state: %s", persistedStatePath)
	} else {
		stateStore = new(mem.Store)
	}

	srv := &tsnet.Server{
		Hostname:  cfg.Hostname,
		AuthKey:   cfg.AuthKey,
		Ephemeral: true,
		Store:     stateStore,
		Tun:       tunDev,
		Dir:       tsnetDir,
	}
	if cfg.ControlURL != "" {
		srv.ControlURL = cfg.ControlURL
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	status, err := srv.Up(ctx)
	if err != nil && persistedStatePath != "" {
		// Persisted state may be stale or corrupted. Remove it and let
		// systemd restart us with a clean slate.
		log.Printf("tsnet.Up failed with persisted state, removing %s: %v", persistedStatePath, err)
		os.Remove(persistedStatePath)
		return fmt.Errorf("tsnet.Up: %v (cleared stale state, restart should succeed)", err)
	}
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

	lc, err := srv.LocalClient()
	if err != nil {
		return fmt.Errorf("getting local client: %v", err)
	}

	// Verify we got the correct hostname — reject names with a -1 suffix
	// from control plane collisions with stale nodes. We check DNSName
	// (the FQDN assigned by the control plane) rather than HostName (the
	// requested name), because MagicDNS appends -1, -2 etc. to DNSName
	// on collision while HostName stays as requested.
	st, err := lc.Status(ctx)
	if err != nil {
		return fmt.Errorf("getting status for hostname check: %v", err)
	}
	expectedPrefix := cfg.Hostname + "."
	if st.Self != nil && st.Self.DNSName != "" && !strings.HasPrefix(st.Self.DNSName, expectedPrefix) {
		srv.Close()
		if persistedStatePath != "" {
			os.Remove(persistedStatePath)
		}
		return fmt.Errorf("hostname mismatch: requested %q but got DNS name %q (stale node not cleaned up?)",
			cfg.Hostname, st.Self.DNSName)
	}

	// Set exit node if requested.
	if mp, err := exitNodePrefs(cfg.ExitNode); err != nil {
		return err
	} else if mp != nil {
		if _, err := lc.EditPrefs(ctx, mp); err != nil {
			return fmt.Errorf("setting exit node: %v", err)
		}
		if mp.AutoExitNodeSet {
			log.Printf("exit node set to auto:%s", mp.AutoExitNode)
		} else {
			log.Printf("exit node set to %v", mp.ExitNodeIP)
		}
	}

	// Configure the interface inside the container namespace.
	if err := configureInterface(cfg.NetNSPath, cfg.TUNName, ip4, ip6, cfg.MTU); err != nil {
		return fmt.Errorf("configuring interface: %v", err)
	}
	log.Printf("interface %s configured", cfg.TUNName)

	// Check DNS readiness.
	st, err = lc.Status(ctx)
	if err != nil {
		return fmt.Errorf("getting status: %v", err)
	}
	if st.CurrentTailnet != nil && st.CurrentTailnet.MagicDNSSuffix != "" {
		log.Printf("DNS ready (MagicDNS suffix: %q)", st.CurrentTailnet.MagicDNSSuffix)
	} else {
		log.Printf("warning: MagicDNS not detected; container DNS may not resolve tailnet names")
	}

	// Provision a TLS cert and start the renewal loop (opt-in via TS_TLS_CERTS_DIR).
	// Runs asynchronously: lc.CertPair can take tens of seconds against a busy
	// control plane, and blocking the daemon here means ready.json doesn't get
	// written until certs land, which can exceed the plugin's readyTimeout and
	// kill the container. App-side handles missing certs by serving plain HTTP
	// initially and exiting on cert mtime change so systemd restarts it.
	if cfg.TLSCertsDir != "" {
		if st.CurrentTailnet == nil || st.CurrentTailnet.MagicDNSSuffix == "" {
			log.Printf("tls: skipping cert provisioning — MagicDNS suffix not available")
		} else {
			fqdn := cfg.Hostname + "." + st.CurrentTailnet.MagicDNSSuffix
			go func() {
				// Reuse an existing cached cert if it's still well within its
				// validity window — saves a control-plane round-trip on every
				// restart/reboot/reimage when TLSCertsDir is persistent.
				if notAfter := loadLeafNotAfter(cfg.TLSCertsDir); !notAfter.IsZero() && time.Until(notAfter) > certRenewThreshold {
					log.Printf("tls: using cached cert at %s (expires %s)",
						cfg.TLSCertsDir, notAfter.Format(time.RFC3339))
				} else if err := writeCertPair(ctx, lc, fqdn, cfg.TLSCertsDir); err != nil {
					log.Printf("tls: initial cert provisioning failed (refresher will retry): %v", err)
				} else {
					log.Printf("tls: wrote cert pair to %s (expires %s)",
						cfg.TLSCertsDir, loadLeafNotAfter(cfg.TLSCertsDir).Format(time.RFC3339))
				}
				startCertRefresher(ctx, lc, fqdn, cfg.TLSCertsDir)
			}()
		}
	}

	// Keep DERP relay connection alive so inbound traffic always has a path.
	// Without this, idle nodes become unreachable when the DERP TCP
	// connection silently dies (tailscale/tailscale#15776).
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, err := lc.Ping(ctx, ip4, tailcfg.PingDisco)
				if err != nil && ctx.Err() == nil {
					log.Printf("keepalive ping failed: %v", err)
				}
			}
		}
	}()

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

// exitNodePrefs builds the MaskedPrefs needed to route container traffic
// through an exit node, from a user-supplied TS_EXIT_NODE value. It accepts
// either:
//
//   - a literal exit-node IP, e.g. "100.64.0.1", pinning that specific node; or
//   - an auto-selection expression using Tailscale's "auto:" syntax, e.g.
//     "auto:any", letting the backend pick the best available exit node and
//     re-pick if it goes offline.
//
// This mirrors `tailscale set --exit-node=<ip|auto:any>`. An empty string
// returns (nil, nil), meaning no exit node should be set.
func exitNodePrefs(exitNode string) (*ipn.MaskedPrefs, error) {
	if exitNode == "" {
		return nil, nil
	}
	mp := &ipn.MaskedPrefs{}
	if expr, isAuto := ipn.ParseAutoExitNodeString(exitNode); isAuto {
		mp.Prefs.AutoExitNode = expr
		mp.AutoExitNodeSet = true
		return mp, nil
	}
	ip, err := netip.ParseAddr(exitNode)
	if err != nil {
		return nil, fmt.Errorf("parsing exit_node %q: %v", exitNode, err)
	}
	mp.Prefs.ExitNodeIP = ip
	mp.ExitNodeIPSet = true
	return mp, nil
}
