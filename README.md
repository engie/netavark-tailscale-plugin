# netavark-tailscale-plugin

A [netavark](https://github.com/containers/netavark) network plugin that bridges
rootless container traffic onto a Tailscale network (tailnet) via
[tsnet](https://pkg.go.dev/tailscale.com/tsnet). It creates a TUN device inside
a container's network namespace and makes containers appear as ephemeral
Tailscale nodes. Designed for use with podman.

## Requirements

- Linux (all source files are `//go:build linux`)
- Go 1.25+

## Build

```sh
go build -o netavark-tailscale-plugin .
```

## How it works

The binary operates in two modes:

- **Plugin mode** (`info`, `create`, `setup`, `teardown`): short-lived netavark
  plugin protocol handlers (JSON stdin/stdout)
- **Daemon mode** (`daemon`): long-running tsnet process started by the plugin

### Plugin / Daemon lifecycle

```
podman run --network tailscale-net ...
  -> netavark invokes: netavark-tailscale-plugin setup /run/netns/xxx < JSON
     -> plugin writes config.json to state dir
     -> plugin starts daemon as a child process
     -> daemon creates TUN in container netns, starts tsnet, configures interface
     -> daemon writes ready.json (IPs, MAC)
     -> plugin polls for ready.json, builds StatusBlock, returns JSON
  -> container stops
  -> netavark invokes: netavark-tailscale-plugin teardown /run/netns/xxx < JSON
     -> plugin stops daemon, cleans up state dir
```

### Configuration

Config merges three layers (later overrides earlier):

1. **Network options** (`podman network create --opt key=value`)
2. **Per-container options** (quadlet `NetworkOptions=key=value`)
3. **Environment variables** (`TS_AUTHKEY`, `TS_HOSTNAME`, etc.)

| Variable | Required | Description |
|----------|----------|-------------|
| `TS_AUTHKEY` | Yes | Tailscale auth key for the ephemeral node. Cleared from the process environment after reading. Use ephemeral, single-use auth keys. |
| `TS_HOSTNAME` | Yes | Hostname to register on the tailnet |
| `TS_EXIT_NODE` | No | IP address of an exit node to route traffic through |
| `TS_CONTROL_URL` | No | Custom control server URL |

**Note:** Tailscale enables [logtail](https://pkg.go.dev/tailscale.com/logtail)
by default. Diagnostic logs may be uploaded to `log.tailscale.com` during
runtime. This is standard Tailscale behavior.

## Testing

```sh
# Unit tests (no root required)
go test -run 'TestValidateMTU|TestFdTUNCloseEvents|TestPluginJSON|TestStatusBlock|TestConfigMerge' -v ./...

# Integration tests with fake control server (no root required)
go test -run 'TestTsnetConnectsToControl|TestTwoNodesCanCommunicate|TestExitNodeConfig' -v ./...

# Namespace tests (requires root)
sudo go test -run 'TestCreateTUNInNamespace|TestConfigureInterface' -v ./...

# Full end-to-end (requires root)
sudo go test -run 'TestFullFlow' -v ./...
```

## License

BSD 3-Clause — see [LICENSE](LICENSE).
