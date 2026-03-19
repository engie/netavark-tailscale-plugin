// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	pluginVersion = "0.1.0"
	apiVersion    = "1.0.0"

	// defaultStateBaseDir is the fallback base directory for per-container daemon state.
	// Overridden by $XDG_RUNTIME_DIR/netavark-tailscale-plugin when available, which is
	// required for rootless podman (the daemon needs to see the state dir).
	defaultStateBaseDir = "/run/netavark-tailscale-plugin"

	// readyTimeout is how long setup waits for the daemon to write ready.json.
	readyTimeout = 60 * time.Second

	// readyPollInterval is how often setup polls for ready.json.
	readyPollInterval = 200 * time.Millisecond
)

// --- Netavark plugin JSON types ---

// PluginInfo is the response to the "info" subcommand.
type PluginInfo struct {
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
}

// Network represents a netavark network configuration.
type Network struct {
	Name             string            `json:"name"`
	ID               string            `json:"id"`
	Driver           string            `json:"driver"`
	NetworkInterface string            `json:"network_interface,omitempty"`
	Subnets          []Subnet          `json:"subnets,omitempty"`
	IPv6Enabled      bool              `json:"ipv6_enabled"`
	Internal         bool              `json:"internal"`
	DNSEnabled       bool              `json:"dns_enabled"`
	IPAMOptions      map[string]string `json:"ipam_options,omitempty"`
	Options          map[string]string `json:"options,omitempty"`
	Routes           json.RawMessage   `json:"routes,omitempty"`
	NetworkDNS       json.RawMessage   `json:"network_dns_servers,omitempty"`
}

// Subnet represents a network subnet with gateway.
type Subnet struct {
	Subnet     string `json:"subnet"`
	Gateway    string `json:"gateway,omitempty"`
	LeaseRange any    `json:"lease_range,omitempty"`
}

// PerNetworkOptions holds per-container network options.
type PerNetworkOptions struct {
	Aliases       []string          `json:"aliases,omitempty"`
	InterfaceName string            `json:"interface_name"`
	StaticIPs     []string          `json:"static_ips,omitempty"`
	StaticMAC     string            `json:"static_mac,omitempty"`
	Options       map[string]string `json:"options,omitempty"`
}

// PortMapping represents a port mapping entry.
type PortMapping struct {
	ContainerPort uint16 `json:"container_port"`
	HostIP        string `json:"host_ip"`
	HostPort      uint16 `json:"host_port"`
	Protocol      string `json:"protocol"`
	Range         uint16 `json:"range"`
}

// NetworkPluginExec is the JSON input for setup and teardown.
type NetworkPluginExec struct {
	ContainerID    string            `json:"container_id"`
	ContainerName  string            `json:"container_name"`
	PortMappings   []PortMapping     `json:"port_mappings,omitempty"`
	Network        Network           `json:"network"`
	NetworkOptions PerNetworkOptions `json:"network_options"`
}

// StatusBlock is the JSON output from setup.
type StatusBlock struct {
	DNSSearchDomains []string                `json:"dns_search_domains,omitempty"`
	DNSServerIPs     []string                `json:"dns_server_ips,omitempty"`
	Interfaces       map[string]NetInterface `json:"interfaces,omitempty"`
}

// NetInterface represents a configured network interface.
type NetInterface struct {
	MacAddress string       `json:"mac_address"`
	Subnets    []NetAddress `json:"subnets,omitempty"`
}

// NetAddress represents an IP address assigned to an interface.
type NetAddress struct {
	Gateway string `json:"gateway,omitempty"`
	IPNet   string `json:"ipnet"`
}

// PluginError is the JSON error format for netavark plugins.
type PluginError struct {
	Error string `json:"error"`
}

// DaemonConfig is written by the plugin to the state dir for the daemon to read.
type DaemonConfig struct {
	ContainerID   string            `json:"container_id"`
	ContainerName string            `json:"container_name"`
	NetNSPath     string            `json:"netns_path"`
	Hostname      string            `json:"hostname"`
	AuthKey       string            `json:"auth_key"`
	ControlURL    string            `json:"control_url,omitempty"`
	ExitNode      string            `json:"exit_node,omitempty"`
	MTU           int               `json:"mtu"`
	TUNName       string            `json:"tun_name"`
	SSHAllow      map[string]string `json:"ssh_allow,omitempty"`
	SSHAcceptEnv  []string          `json:"ssh_accept_env,omitempty"`
	PidfilePath   string            `json:"pidfile_path,omitempty"`
}

// DaemonReady is written by the daemon to signal readiness.
type DaemonReady struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
	MAC  string `json:"mac,omitempty"`
}

// validHostname matches a Tailscale hostname: lowercase alphanumeric and
// hyphens, no leading/trailing hyphen, 1-63 characters (DNS label rules).
var validHostname = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// stateBaseDir returns the base directory for daemon state.
// Uses $XDG_RUNTIME_DIR/netavark-tailscale-plugin in rootless mode, falling back to /run/netavark-tailscale-plugin.
func stateBaseDir() string {
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		return filepath.Join(xdg, "netavark-tailscale-plugin")
	}
	return defaultStateBaseDir
}

// --- Plugin subcommands ---

func cmdInfo() error {
	return json.NewEncoder(os.Stdout).Encode(PluginInfo{
		Version:    pluginVersion,
		APIVersion: apiVersion,
	})
}

func cmdCreate() error {
	var net Network
	if err := json.NewDecoder(os.Stdin).Decode(&net); err != nil {
		return fmt.Errorf("decoding network config: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(net)
}

func cmdSetup() error {
	if len(os.Args) < 3 {
		return writePluginError("setup requires netns path argument")
	}
	nsPath := os.Args[2]

	var input NetworkPluginExec
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return writePluginError("decoding setup input: %v", err)
	}
	if !validContainerID.MatchString(input.ContainerID) {
		return writePluginError("invalid container ID: %q", input.ContainerID)
	}

	cfg, err := buildDaemonConfig(nsPath, &input)
	if err != nil {
		return writePluginError("%v", err)
	}

	stateDir := filepath.Join(stateBaseDir(), input.ContainerID)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return writePluginError("creating state dir: %v", err)
	}

	// Write daemon config.
	configPath := filepath.Join(stateDir, "config.json")
	configData, err := json.Marshal(cfg)
	if err != nil {
		return writePluginError("marshaling daemon config: %v", err)
	}
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		return writePluginError("writing daemon config: %v", err)
	}

	// Kill any stale daemon from a previous run.
	killDaemon(stateDir)

	// Start daemon as a direct child process. The daemon inherits our
	// user namespace context, which is required for rootless podman —
	// setns(CLONE_NEWNET) into the container netns only works from within
	// the same user namespace that owns it. systemd-run --user would start
	// the daemon in the initial user namespace, breaking setns.
	selfPath, err := os.Executable()
	if err != nil {
		return writePluginError("resolving executable path: %v", err)
	}
	log.Printf("setup: starting daemon binary=%s state-dir=%s", selfPath, stateDir)
	cmd := exec.Command(selfPath, "daemon", "--state-dir="+stateDir)
	cmd.Stdout = os.Stderr // daemon stdout → plugin stderr (for logging)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // new session so daemon survives plugin exit
	}
	if err := cmd.Start(); err != nil {
		os.RemoveAll(stateDir)
		return writePluginError("starting daemon: %v", err)
	}

	// Write daemon PID + starttime for teardown identity verification.
	daemonPID := cmd.Process.Pid
	if err := writeDaemonPID(stateDir, daemonPID); err != nil {
		log.Printf("setup: warning: failed to write daemon.pid: %v", err)
	}
	log.Printf("setup: daemon pid=%d, polling for ready.json", daemonPID)

	// Release the child so we don't zombie-wait on it.
	cmd.Process.Release()

	// Poll for ready.json.
	readyPath := filepath.Join(stateDir, "ready.json")
	deadline := time.Now().Add(readyTimeout)
	var ready DaemonReady
	for {
		data, err := os.ReadFile(readyPath)
		if err == nil {
			if err := json.Unmarshal(data, &ready); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			log.Printf("setup: timeout waiting for ready.json")
			killDaemon(stateDir)
			os.RemoveAll(stateDir)
			return writePluginError("daemon failed to become ready within %s", readyTimeout)
		}
		time.Sleep(readyPollInterval)
	}

	// Build StatusBlock from ready.json.
	status := buildStatusBlock(&ready)
	return json.NewEncoder(os.Stdout).Encode(status)
}

func cmdTeardown() error {
	if len(os.Args) < 3 {
		return writePluginError("teardown requires netns path argument")
	}

	var input NetworkPluginExec
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return writePluginError("decoding teardown input: %v", err)
	}
	if !validContainerID.MatchString(input.ContainerID) {
		return writePluginError("invalid container ID: %q", input.ContainerID)
	}

	stateDir := filepath.Join(stateBaseDir(), input.ContainerID)
	killDaemon(stateDir)
	os.RemoveAll(stateDir)

	return nil
}

// validContainerID matches standard container IDs: 12-64 lowercase hex characters.
var validContainerID = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

// --- Helper functions ---

// buildDaemonConfig merges network options, per-container options, and env vars
// into a DaemonConfig. Priority: env vars > per-container options > network options.
func buildDaemonConfig(nsPath string, input *NetworkPluginExec) (*DaemonConfig, error) {
	cfg := &DaemonConfig{
		ContainerID:   input.ContainerID,
		ContainerName: input.ContainerName,
		NetNSPath:     nsPath,
		MTU:           1280,
		TUNName:       "tailscale0",
	}

	// Layer 1: network-level options (from podman network create --opt)
	if opts := input.Network.Options; opts != nil {
		if v, ok := opts["hostname"]; ok {
			cfg.Hostname = v
		}
		if v, ok := opts["control_url"]; ok {
			cfg.ControlURL = v
		}
		if v, ok := opts["exit_node"]; ok {
			cfg.ExitNode = v
		}
		if v, ok := opts["mtu"]; ok {
			fmt.Sscanf(v, "%d", &cfg.MTU)
		}
		if v, ok := opts["ssh_accept_env"]; ok {
			cfg.SSHAcceptEnv = parseAcceptEnv(v)
		}
	}

	// Layer 2: per-container options (from quadlet NetworkOptions=)
	if opts := input.NetworkOptions.Options; opts != nil {
		if v, ok := opts["ts_hostname"]; ok {
			cfg.Hostname = v
		}
		if v, ok := opts["control_url"]; ok {
			cfg.ControlURL = v
		}
		if v, ok := opts["exit_node"]; ok {
			cfg.ExitNode = v
		}
		if v, ok := opts["mtu"]; ok {
			fmt.Sscanf(v, "%d", &cfg.MTU)
		}
		if v, ok := opts["ssh_allow"]; ok {
			parsed, err := parseSSHAllow(v)
			if err != nil {
				return nil, fmt.Errorf("parsing ssh_allow option: %w", err)
			}
			cfg.SSHAllow = parsed
		}
		if v, ok := opts["pidfile"]; ok {
			cfg.PidfilePath = v
		}
		if v, ok := opts["ssh_accept_env"]; ok {
			cfg.SSHAcceptEnv = parseAcceptEnv(v)
		}
	}

	// Layer 3: environment variables (highest priority)
	if v := os.Getenv("TS_AUTHKEY"); v != "" {
		cfg.AuthKey = v
	}
	if v := os.Getenv("TS_HOSTNAME"); v != "" {
		cfg.Hostname = v
	}
	if v := os.Getenv("TS_CONTROL_URL"); v != "" {
		cfg.ControlURL = v
	}
	if v := os.Getenv("TS_EXIT_NODE"); v != "" {
		cfg.ExitNode = v
	}
	if v := os.Getenv("TS_SSH_ALLOW"); v != "" {
		parsed, err := parseSSHAllow(v)
		if err != nil {
			return nil, fmt.Errorf("parsing TS_SSH_ALLOW: %w", err)
		}
		cfg.SSHAllow = parsed
	}
	if v := os.Getenv("TS_PIDFILE"); v != "" {
		cfg.PidfilePath = v
	}
	if v := os.Getenv("TS_SSH_ACCEPT_ENV"); v != "" {
		cfg.SSHAcceptEnv = parseAcceptEnv(v)
	}

	// Validate required fields.
	if cfg.AuthKey == "" {
		return nil, fmt.Errorf("TS_AUTHKEY is required (set via env var or network option)")
	}
	if cfg.Hostname == "" {
		cfg.Hostname = input.ContainerName
	}
	if !validHostname.MatchString(cfg.Hostname) {
		return nil, fmt.Errorf("hostname %q is not valid (lowercase alphanumeric and hyphens, 1-63 chars)", cfg.Hostname)
	}
	if err := validateMTU(cfg.MTU); err != nil {
		return nil, err
	}
	if len(cfg.SSHAllow) > 0 && cfg.PidfilePath == "" {
		return nil, fmt.Errorf("pidfile path is required when SSH is enabled (set TS_PIDFILE or pidfile option)")
	}

	return cfg, nil
}

// validateMTU checks that the MTU is within a usable range.
func validateMTU(mtu int) error {
	if mtu < 1280 || mtu > 65535 {
		return fmt.Errorf("MTU %d is out of range [1280, 65535]", mtu)
	}
	return nil
}

// buildStatusBlock converts DaemonReady into a netavark StatusBlock.
func buildStatusBlock(ready *DaemonReady) StatusBlock {
	status := StatusBlock{
		DNSServerIPs:     []string{"100.100.100.100"},
		DNSSearchDomains: []string{},
	}

	iface := NetInterface{
		MacAddress: ready.MAC,
	}

	if ready.IPv4 != "" {
		iface.Subnets = append(iface.Subnets, NetAddress{
			IPNet: ready.IPv4 + "/32",
		})
	}
	if ready.IPv6 != "" {
		iface.Subnets = append(iface.Subnets, NetAddress{
			IPNet: ready.IPv6 + "/128",
		})
	}

	status.Interfaces = map[string]NetInterface{
		"tailscale0": iface,
	}
	return status
}

// daemonPIDInfo holds a daemon's PID and process starttime (field 22 from
// /proc/<pid>/stat, in clock ticks since boot). Together they form a unique
// process identifier that is immune to PID recycling.
type daemonPIDInfo struct {
	PID       int    `json:"pid"`
	Starttime string `json:"starttime"`
}

// processStarttime reads the starttime field (field 22, 0-indexed) from
// /proc/<pid>/stat. The comm field (field 2) may contain spaces and
// parentheses, so we find the last ')' to skip it reliably.
func processStarttime(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	// Fields after comm (which is in parens and may contain spaces).
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 {
		return "", fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	// Fields after ')' are space-separated, starting at field 3 (state).
	// Starttime is field 22, so it's at index 22-3 = 19 in the remaining fields.
	fields := strings.Fields(s[idx+1:])
	if len(fields) < 20 {
		return "", fmt.Errorf("/proc/%d/stat: too few fields", pid)
	}
	return fields[19], nil
}

// writeDaemonPID writes the daemon's PID and starttime to daemon.pid in JSON.
func writeDaemonPID(stateDir string, pid int) error {
	starttime, err := processStarttime(pid)
	if err != nil {
		// Fall back to PID-only if we can't read starttime.
		starttime = ""
		log.Printf("setup: warning: cannot read starttime for PID %d: %v", pid, err)
	}
	info := daemonPIDInfo{PID: pid, Starttime: starttime}
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDir, "daemon.pid"), data, 0600)
}

// readDaemonPID reads the daemon PID info from daemon.pid in the state dir.
func readDaemonPID(stateDir string) (daemonPIDInfo, error) {
	data, err := os.ReadFile(filepath.Join(stateDir, "daemon.pid"))
	if err != nil {
		return daemonPIDInfo{}, err
	}
	// Try JSON format first (new).
	var info daemonPIDInfo
	if err := json.Unmarshal(data, &info); err == nil && info.PID > 0 {
		return info, nil
	}
	// Fall back to bare PID (old format, for compatibility during rollout).
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return daemonPIDInfo{}, fmt.Errorf("invalid daemon.pid content")
	}
	return daemonPIDInfo{PID: pid}, nil
}

// killDaemon reads the daemon PID info from the state dir, verifies the
// process identity via starttime to guard against PID reuse, and sends
// SIGTERM (then SIGKILL if needed).
func killDaemon(stateDir string) {
	info, err := readDaemonPID(stateDir)
	if err != nil {
		return // no pidfile or unreadable, nothing to kill
	}

	// Verify process identity before signaling.
	if info.Starttime != "" {
		current, err := processStarttime(info.PID)
		if err != nil {
			return // process already gone
		}
		if current != info.Starttime {
			log.Printf("teardown: PID %d has different starttime (%s vs %s), skipping kill (PID was recycled)",
				info.PID, current, info.Starttime)
			return
		}
	}

	// Send SIGTERM. Ignore errors (process may already be dead).
	syscall.Kill(info.PID, syscall.SIGTERM)
	// Brief wait for clean shutdown.
	for i := 0; i < 10; i++ {
		if err := syscall.Kill(info.PID, 0); err != nil {
			return // process gone
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Force kill if still alive.
	syscall.Kill(info.PID, syscall.SIGKILL)
}

// writePluginError writes a JSON error to stdout (netavark plugin protocol)
// and returns nil so the process exits cleanly with code 0.
func writePluginError(format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	json.NewEncoder(os.Stdout).Encode(PluginError{Error: msg})
	os.Exit(1)
	return nil // unreachable
}

// parseAcceptEnv is defined in ssh.go.
