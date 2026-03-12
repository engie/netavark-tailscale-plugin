# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

netavark-tailscale-plugin is a netavark network plugin that bridges rootless container traffic onto a Tailscale network (tailnet) via the `tsnet` library. It creates a TUN device inside a container's network namespace and makes containers appear as ephemeral Tailscale nodes. Designed for use with podman.

The binary operates in two modes:
- **Plugin mode** (`info`, `create`, `setup`, `teardown`): short-lived netavark plugin protocol handlers (JSON stdin/stdout)
- **Daemon mode** (`daemon`): long-running tsnet process, managed by systemd via `systemd-run --user`

All source files are Linux-only (`//go:build linux`).

## Build & Test Commands

```bash
# Build
go build -o netavark-tailscale-plugin .

# Lint
go vet ./...

# Tier 1: Unit tests (no root, no network)
go test -run 'TestValidateMTU|TestFdTUNCloseEvents|TestPluginJSON|TestStatusBlock|TestConfigMerge|TestReadPidfile|TestValidatePIDNetNS|TestContainerPID|TestSSHPayloadParsing|TestSSHHostKeyPersistence|TestParseSSHAllow|TestSSHAllowlist|TestAcceptEnvPair|TestMatchAcceptEnvPattern|TestParseAcceptEnv|TestIsAllowedEnv|TestParsePasswdUser|TestBaseEnvForUser|TestDiscoverContainers' -v ./...

# Tier 2: Integration tests (no root, fake control + chanTUN)
go test -run 'TestTsnetConnectsToControl|TestTwoNodesCanCommunicate|TestExitNodeConfig|TestSSHServerConnects' -v ./...

# Tier 3: Namespace tests (requires root)
sudo go test -run 'TestCreateTUNInNamespace|TestConfigureInterface' -v ./...

# Tier 4: Full end-to-end (requires root)
sudo go test -run 'TestFullFlow' -v ./...

# All tests (requires root)
sudo go test -v ./...
```

CI runs only Tier 1 tests, `go vet`, and build.

## Architecture

Five source files, single package `main`:

- **main.go** — Entry point, subcommand dispatch (`info`, `create`, `setup`, `teardown`, `daemon`).
- **plugin.go** — Netavark plugin protocol: JSON types (Network, NetworkPluginExec, StatusBlock, etc.), plugin handlers, config merging (network options → per-container options → env vars), systemd-run invocation, readiness polling.
- **daemon.go** — Long-running daemon: reads `config.json` from state dir, creates TUN, runs tsnet, configures interface, writes `ready.json`, handles signals.
- **ssh.go** — SSH server on the tsnet interface. Identifies peers via WhoIs, checks the allowlist (`TS_SSH_ALLOW`), discovers containers via pidfile scanning, and runs commands inside containers via `nsenter`.
- **netns.go** — Network namespace operations. `createTUNInNamespace()` uses a sacrificial goroutine pattern (LockOSThread + Setns, thread never returned) to create a TUN in the container's namespace. Interface configuration uses raw netlink/ioctl syscalls (no external dependencies).
- **tun.go** — `fdTUN` struct implementing the `tun.Device` interface, wrapping the file descriptor from namespace creation for use by tsnet.

### Plugin ↔ Daemon lifecycle

```
podman run --network tailscale-net ...
  → netavark invokes: netavark-tailscale-plugin setup /run/netns/xxx < JSON
     → plugin writes config.json to /run/ts4nsnet/<container-id>/
     → plugin runs: systemd-run --user --unit=ts4nsnet-<short-id> ... daemon --state-dir=...
     → daemon creates TUN, starts tsnet, configures interface
     → daemon writes ready.json (IPs, MAC)
     → plugin polls for ready.json, builds StatusBlock, returns JSON
  → container stops
  → netavark invokes: netavark-tailscale-plugin teardown /run/netns/xxx < JSON
     → plugin runs: systemctl --user stop ts4nsnet-<short-id>
     → plugin cleans up state dir
```

### Configuration flow

Config merges three layers (later overrides earlier):
1. **Network options** (`podman network create --opt key=value`)
2. **Per-container options** (quadlet `NetworkOptions=key=value`)
3. **Environment variables** (`TS_AUTHKEY`, `TS_HOSTNAME`, etc.)

### SSH container selection

The SSH username field selects which container to enter. `discoverContainers()` scans `dirname(pidfilePath)` for `*.pid` files, reads each PID, and filters to those sharing the network namespace (via `validatePIDNetNS`). The SSH username must match a pidfile basename (without `.pid`).

### Key pattern: Sacrificial goroutine

Used in both TUN creation and interface configuration. A goroutine is locked to an OS thread, enters the container namespace via `Setns()`, performs work, and the thread is permanently discarded (no `UnlockOSThread()`). This prevents namespace contamination of the main goroutine.

### Testing infrastructure

Tests use `chanTUN` (channel-backed fake TUN) and `testcontrol` (fake Tailscale control server) from the Tailscale test libraries for integration tests without real network access or root.
