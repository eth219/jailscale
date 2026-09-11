# jailscale

**[Tailscale](https://tailscale.com)'s control plane, plus reverse
[keyless TLS](https://blog.cloudflare.com/keyless-ssl-the-nitty-gritty-technical-details/),
in Java, written with [Claude](https://claude.com/claude-code).**

A self-hosted HTTPS tunnel. Nodes dial out to a hub you run and get a public
`https://name.your-domain` address. The hub never sees plaintext: it forwards
the TLS bytes untouched and the node terminates the session, using a wildcard
certificate whose private key stays on the hub and is used only to sign the
handshake.

Keyless TLS keeps the private key at the origin and terminates at the edge.
jailscale turns that around. The key stays at the edge, on the hub, and
termination moves to the origin, on your machine. The edge signs one handshake
digest and never holds a session key, so the party you are trusting least is
also the one that can read least.

Two binaries, no runtime dependencies, nothing to install underneath them. No
TUN device, no root, no inbound ports on the node.

Full design and architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What Java bought, and what it cost

The interesting question was whether a JVM language can carry this kind of
product without apologising for itself. Four things were the target.

**Light.** 25 MiB per binary, 25 MB idle, 7 ms for a CLI round trip. That needs
GraalVM Native Image, and Native Image needs discipline: no reflection, no
dependency injection, no dynamic class loading, no third-party runtime
dependency at all. JSON, HTTP/1.1, ACME, DNS, the multiplexer and the Noise
handshake are all written here. The cost is real. Those are all things you would
normally take off a shelf.

**Easy.** `jailscale open 3000` and the link is live. On the hub side the
operator creates three DNS records and opens two ports; the wildcard
certificate arrives on its own, because the hub is the authoritative DNS server
for its own `_acme-challenge` name and answers its own ACME challenge. No DNS
provider API token anywhere.

**Portable.** No root, no TUN device, no kernel module, no inbound port, no UDP
on the node. Five native platforms plus a pure-JVM fallback JAR for anything
else. Virtual threads throughout, so a thread per direction per stream is an
ordinary thing to write rather than something to optimise away.

**Secure, and specifically how.** The hub reads the TLS SNI and nothing else, so
it never parses visitor HTTP and never holds plaintext. The wildcard private key
stays on the hub and signs one handshake digest per visitor, and the hub refuses
to sign unless the request is bound to a stream it itself delivered to that node.
Domains you bring yourself never involve the hub's key at all. The node then
checks the hub's honesty from its own side: `jailscale verify` opens a session to
its own public name and compares RFC 5705 exported keying material against what
it recorded, which catches a hub that terminated the TLS itself. The control
channel is Noise IK inside TLS, so a compromised certificate authority still does
not get you the control plane.

What it did not buy: idle memory is 24.7 MB against a 20 MB goal, and roughly
7.6 MB of that is JSSE standing up a single TLS client.

## Usage

A hub is running at **`jailscale.sinabro.io`**. Registration is open, so you can
point a node at it and start.

```sh
# 1. Join. Registration is open on this hub, so it takes effect immediately.
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

Container images are published for linux/amd64 and linux/arm64:

```
docker pull ghcr.io/eth219/jailhub:edge
docker pull ghcr.io/eth219/jailscale:edge
```

Native binaries for Linux, macOS and Windows are built for every commit and are
attached to [releases](https://github.com/eth219/jailscale/releases) once a
version is tagged. Until then, `./native.sh` builds them from source with
GraalVM.

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
- No tagged release yet, so there are no downloadable binaries. The container
  images are current.

## Credit

- [Tailscale](https://tailscale.com) for the control plane: a coordination
  server, joining by invite instead of by identity provider, nodes that only
  dial out.
- [Keyless SSL](https://blog.cloudflare.com/keyless-ssl-the-nitty-gritty-technical-details/)
  for separating the private key from the server that uses it.
- [gosuda/portal-tunnel](https://github.com/gosuda/portal-tunnel) for applying
  that to a tunnel, and for the self-probe.

## License

[Apache-2.0](LICENSE).
