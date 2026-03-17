// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// netavark-tailscale-plugin is a netavark network plugin that bridges
// container traffic onto a Tailscale network (tailnet) via tsnet. It creates
// a TUN device inside a container's network namespace and makes containers
// appear as ephemeral Tailscale nodes.
//
// The binary operates in two modes:
//   - Plugin mode (info, create, setup, teardown): short-lived netavark plugin
//     protocol handlers, invoked by netavark with JSON on stdin/stdout.
//   - Daemon mode (daemon): long-running tsnet process managed by systemd,
//     started by the plugin via systemd-run --user.
package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("netavark-tailscale-plugin: ")

	// Refuse to run as root. The security model assumes rootless podman where
	// user namespace isolation contains same-user bugs. Running as root
	// escalates every path traversal, PID, and nsenter issue to host-root.
	if os.Geteuid() == 0 && os.Getenv("UNSAFE_ALLOW_ROOT") == "" {
		fmt.Fprintf(os.Stderr, "netavark-tailscale-plugin: refusing to run as root (rootless podman required)\n")
		fmt.Fprintf(os.Stderr, "Set UNSAFE_ALLOW_ROOT=1 to override (for testing only).\n")
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: netavark-tailscale-plugin <info|create|setup|teardown|daemon> [args...]\n")
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "info":
		err = cmdInfo()
	case "create":
		err = cmdCreate()
	case "setup":
		err = cmdSetup()
	case "teardown":
		err = cmdTeardown()
	case "daemon":
		err = cmdDaemon()
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		// For plugin commands, errors should be JSON-formatted on stdout.
		// cmdSetup/cmdTeardown handle this themselves. For other errors,
		// just log to stderr and exit.
		log.Fatalf("%v", err)
	}
}
