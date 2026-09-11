# jailscale

**Tailscale's control plane, plus portal-tunnel's keyless TLS, written with Claude.**

A self-hosted HTTPS tunnel. Nodes dial out to a hub you run and get a public
`https://name.your-domain` address. The hub never sees plaintext: it forwards
the TLS bytes untouched and the node terminates the session, using a wildcard
certificate whose private key stays on the hub and is used only to sign the
handshake.

Two binaries, no runtime dependencies, nothing to install underneath them. No
TUN device, no root, no inbound ports on the node.

Full design and architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Usage

A hub is running at **`jailscale.sinabro.io`**. You can point a node at it
today. Joining puts you in an approval queue, so ask the operator to let you in.

```sh
# 1. Join. The node knocks and waits for the hub operator to approve it.
jailscale up --hub jailscale.sinabro.io

# 2. Publish a local port.
jailscale open 3000
#    https://a7f2k.jailscale.sinabro.io  ->  127.0.0.1:3000

# 3. Or ask for a name.
jailscale open 3000 --name myapp
#    https://myapp.jailscale.sinabro.io  ->  127.0.0.1:3000
```

Other things a node can do:

```sh
jailscale open 3000 --gate                    # visitors need a one-time link
jailscale open 22 --tcp                       # a raw TCP port, no TLS
jailscale open 3000 --domain app.example.com  # your own domain, key never leaves the node
jailscale verify                              # check that this node, not the hub, terminated the TLS
jailscale ls | close NAME | status | down
jailscale service install                     # keep the daemon running across logins
```

### Running your own hub

You need a host with a public address, a domain, and ports 443, 80 and 53. The
hub answers DNS for its own `_acme-challenge` name, so it issues its own
wildcard certificate with no DNS provider API token.

```
jailscale.example.com.                  A   203.0.113.10
*.jailscale.example.com.                A   203.0.113.10
_acme-challenge.jailscale.example.com.  NS  jailscale.example.com.
```

```sh
jailhub serve --base-url https://jailscale.example.com --acme-email you@example.com
```

The first run prints an invite. Whoever joins with it becomes the administrator.

Binaries for Linux, macOS and Windows are on the
[releases page](https://github.com/eth219/jailscale/releases). Container images:

```
ghcr.io/eth219/jailhub:latest
ghcr.io/eth219/jailscale:latest
```

## Resource usage

Measured on arm64 macOS with the native binaries. `./measure.sh --check`
enforces these as a budget in CI.

| | jailhub | jailscale |
|---|---|---|
| Binary | 25.0 MiB | 25.3 MiB |
| Idle RSS | 24.7 MB | 24.7 MB |
| Peak RSS, 1,000 visitors held open at once | 77 MB | 85 MB |
| CLI cold start | — | 7 ms |

The hub above runs on a GCP e2-micro: 2 shared vCPU, 1 GB of memory, Debian 12.
That is the smallest instance Google sells, and it is not the constraint.

Requirements:

| | Hub | Node |
|---|---|---|
| Inbound ports | 443, 80, 53 | none |
| Public address | yes | no |
| Root | no (`CAP_NET_BIND_SERVICE`) | no |
| TUN device | no | no |
| Runtime to install | none | none |

A hub accepts 1,024 concurrent visitors per name, and 20 names per node.

## Trust

The hub holds the wildcard private key. A compromised hub cannot read traffic to
a healthy node, but it can move a name to a node of its own and sign for it. The
node detects that afterwards with `jailscale verify`, and an honest hub reports
the move on its own. Names you bring yourself are not exposed this way: the key
stays on the node and the hub only routes.

What a compromised hub can and cannot do is written out in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Not done yet

- No production track record. The hub above has been up since 2026-09-11.
- The hub is a single process on a single host. Losing the host means downtime.
  Replacing the binary without dropping nodes works with `serve --takeover`, but
  not under a systemd unit, where an upgrade is a restart.
- `service install` is verified on macOS only. Linux and Windows are untested
  outside CI.
- The self-probe runs when you type `jailscale verify`. It should run on a
  schedule.
- Windows nodes occasionally need to reconnect, costing that connection's
  visitors up to 60 seconds. It is a JDK bug, not ours:
  [docs/windows-virtual-thread-stall](docs/windows-virtual-thread-stall/).
- Idle memory is 24.7 MB against a 20 MB goal. Most of the gap is JSSE standing
  up a TLS client.
- No standby hub, no state replication, no OIDC.

## Credit

- [Tailscale](https://tailscale.com) for the control plane shape: a coordination
  server, joining by invite rather than by identity provider, and nodes that
  only dial out.
- [gosuda/portal-tunnel](https://github.com/gosuda/portal-tunnel) for the
  keyless TLS relay, and for the self-probe, which jailscale did not have until
  reading that project.
- [Keyless SSL](https://blog.cloudflare.com/keyless-ssl-the-nitty-gritty-technical-details/)
  for separating the private key from the server that uses it.

Built with [Claude Code](https://claude.com/claude-code).

## License

[Apache-2.0](LICENSE).
