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

## Installation

Install the plugin binary where netavark can find it, and tell podman where to
look:

```sh
# Copy the binary
sudo install -m 755 netavark-tailscale-plugin /usr/local/lib/netavark-plugins/

# Tell netavark where to find plugins
cat <<'EOF' | sudo tee /etc/containers/containers.conf
[network]
netavark_plugin_dirs = ["/usr/local/lib/netavark-plugins"]
EOF
```

Create the podman network (once per host):

```sh
podman network create --driver netavark-tailscale-plugin tailscale
```

## Example deployment with rootless Podman

This shows a complete setup using [quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
systemd units and [tailmint](https://github.com/engie/tailmint) for ephemeral
auth key minting. Each container gets a fresh, single-use Tailscale auth key at
startup and appears as its own node on the tailnet.

### Prerequisites

- A [Tailscale OAuth client](https://tailscale.com/kb/1215/oauth-clients) with
  a tag (e.g. `tag:containers`) that the client is authorized to create devices
  under
- `tailmint` installed at `/usr/local/bin/tailmint`
- OAuth credentials in `/etc/tailscale/oauth.env`:

```env
TS_API_CLIENT_ID=your-oauth-client-id
TS_API_CLIENT_SECRET=tskey-client-...
```

- A sudoers rule so the container user can mint keys (replace `nginx-demo` with
  your user):

```
nginx-demo ALL=(root) NOPASSWD: /usr/local/bin/tailmint -config /etc/tailscale/oauth.env -tag tag\:containers -hostname * -output /run/user/*/ts-authkeys/*.env
```

### Quadlet container file

Place this at `~/.config/containers/systemd/nginx-demo.container`:

```ini
[Unit]
Description=nginx on tailnet
After=network-online.target
Wants=network-online.target

[Container]
Image=docker.io/library/nginx:latest
ContainerName=nginx-demo
Network=tailscale

[Service]
# Mint a fresh ephemeral auth key before each start
ExecStartPre=mkdir -p %t/ts-authkeys
ExecStartPre=sudo /usr/local/bin/tailmint -config /etc/tailscale/oauth.env -tag tag:containers -hostname %N -output %t/ts-authkeys/%N.env
ExecStartPre=podman network create --ignore --driver netavark-tailscale-plugin tailscale

# Load the minted key into the service environment
EnvironmentFile=-%t/ts-authkeys/%N.env

# TS_HOSTNAME and TS_AUTHKEY are read by netavark-tailscale-plugin on the
# host side, so they go in [Service], not [Container]
Environment=TS_HOSTNAME=%N

Restart=on-failure
RestartSec=10s

[Install]
WantedBy=default.target
```

Start it:

```sh
systemctl --user daemon-reload
systemctl --user start nginx-demo
```

The container joins the tailnet as `nginx-demo` and is reachable from any device
on the same tailnet.

### Enabling SSH into the container

To allow Tailscale SSH access into the running container, add these to
`[Service]`:

```ini
Environment=TS_SSH_ALLOW=you@example.com:root
Environment=TS_PIDFILE=%t/%N.pid
```

And add `--pidfile` to `[Container]`:

```ini
PodmanArgs=--pidfile %t/%N.pid
```

`TS_SSH_ALLOW` is a comma-separated list of `identity:user` pairs — the
Tailscale identity (login name) allowed to connect, and the container user to
run commands as (e.g. `root`). `TS_PIDFILE` tells the plugin where podman
writes the container PID, which is needed to `nsenter` into the right namespace.

The SSH command has the form:

```
ssh <container>@<tailnet-hostname>
```

- **hostname** (`<tailnet-hostname>`) is the `TS_HOSTNAME` of the node — it
  selects which Tailscale node to connect to.
- **username** (`<container>`) selects which container to enter. It is matched
  against pidfile basenames (filename without `.pid`) in the `TS_PIDFILE`
  directory. The `user` in `TS_SSH_ALLOW` is a separate concept — that controls
  which OS user you run as *inside* the container, not which container you enter.

For a single standalone container:

```sh
# TS_HOSTNAME=nginx-demo, TS_PIDFILE=%t/nginx-demo.pid
# Enters container "nginx-demo" as root on the tailnet node "nginx-demo"
ssh nginx-demo@nginx-demo
```

### SSH into containers in a pod

When multiple containers share a network namespace (e.g. in a Podman pod), a
single netavark-tailscale-plugin daemon serves them all. The daemon scans the
directory containing `TS_PIDFILE` for all `*.pid` files and filters to those
sharing its network namespace.

Point each container's `--pidfile` at the same directory so they are all
discoverable. The SSH username then selects which container to enter by pidfile
basename:

```sh
# Pod with TS_HOSTNAME=my-pod
# Pidfiles: %t/web.pid, %t/api.pid (both in the pod's shared netns)
ssh web@my-pod    # enters the "web" container
ssh api@my-pod    # enters the "api" container
```

If the SSH username doesn't match any discovered pidfile, the error message
lists the available container names.

### All configuration variables

These are set as environment variables in `[Service]` or as network/container
options:

| Variable | Option | Required | Description |
|----------|--------|----------|-------------|
| `TS_AUTHKEY` | — | Yes | Tailscale auth key (use ephemeral, single-use) |
| `TS_HOSTNAME` | `hostname` | Yes | Node hostname on the tailnet |
| `TS_EXIT_NODE` | `exit_node` | No | Exit node IP to route traffic through |
| `TS_CONTROL_URL` | `control_url` | No | Custom Tailscale control server URL |
| `TS_SSH_ALLOW` | `ssh_allow` | No | SSH allowlist: `identity:user,...` |
| `TS_PIDFILE` | `pidfile` | No* | Container pidfile path (required if SSH is enabled) |
| `TS_SSH_ACCEPT_ENV` | `ssh_accept_env` | No | Env var patterns to forward via SSH (e.g. `LANG,LC_*`) |

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
