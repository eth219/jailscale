# jailscale

**[Tailscale](https://tailscale.com)'s control plane, plus
[gosuda/portal-tunnel](https://github.com/gosuda/portal-tunnel)'s reverse
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

## What it does, and what it does not

A port on a machine you run, served at `https://<name>.<your-hub>` to visitors
who install nothing. That is the whole of it.

ngrok, Cloudflare Tunnel and frp do the same job — the first two hosted, frp on
a server you run. Tailscale is larger: a mesh between your own machines, of
which Funnel is this one job.

**Everything else is out of scope**, in particular:

- **A VPN.** No mesh, no peer-to-peer, no exit nodes, no subnet routes, no
  MagicDNS.
- **Reading the visitor's HTTP.** Neither end parses it: no routing on paths or
  headers, no rewriting, no request inspector, no replay, no per-request log.
- **HTTP/2 and HTTP/3 to the visitor.** The node offers `http/1.1` only.
- **More than one node behind a name.** No load balancing, no health checking,
  no failover.
- **An identity provider.** Joining is an invite, a code or an auth-key; an
  admin is a machine key ([ARCHITECTURE.md §10](docs/ARCHITECTURE.md)).
- **Mobile clients.** Desktop and server platforms only.
- **A hosted service.** You run the hub; there is nothing to sign up for.

Things *missing* rather than excluded are under [Not done yet](#not-done-yet).

## What Java bought, and what it cost

The interesting question was whether a JVM language can carry this kind of
product without apologising for itself. Four things were the target.

**Light.** 30 MiB per binary and 29 MB idle on arm64 macOS, 32 MiB and 40 MB on
linux-amd64 — of which 6 MB is memory the process actually owns and the rest is
the binary's own pages, which the kernel can take back. 6 ms for a CLI round
trip. That needs
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
checks the hub's honesty from its own side: the daemon opens a session to one of
its own public names every half hour, and `jailscale verify` does all of them at
once. Either way it compares RFC 5705 exported keying material against what it
recorded, which catches a hub that terminated the TLS itself, and `status` keeps
each name's last verdict. The control channel is Noise IK inside TLS, so a
compromised certificate authority still does not get you the control plane.

What it did not buy: idle memory is 29 MB against a 20 MB goal, and roughly
7.6 MB of that is JSSE standing up a single TLS client. On Linux the number to
compare is the 6 MB of anonymous memory, not the 40 MB `ps` prints.

## Install

`jailscale` is the node: the binary you run on the machine whose port you want
to publish. `jailhub` is the hub, and you only need it if you are running your
own. Neither has a runtime dependency and neither needs root to run.

### A binary

Every tagged release carries all five targets for both programs: `linux-amd64`,
`linux-arm64`, `darwin-arm64`, `darwin-amd64`, `windows-amd64.exe`.

```sh
base=https://github.com/eth219/jailscale/releases/download/v0.1.0
target=darwin-arm64   # pick yours

curl -fsSL -O "$base/jailscale-$target" -O "$base/SHA256SUMS.txt"
shasum -a 256 --ignore-missing -c SHA256SUMS.txt   # sha256sum -c on Linux
sudo install -m 755 "jailscale-$target" /usr/local/bin/jailscale
jailscale version
```

Keep the release's own filename until the checksum has been checked. Renaming it
on the way down leaves nothing in `SHA256SUMS.txt` to match, and
`--ignore-missing` then reports success for having verified nothing.
`jailhub-$target` is the same download for the hub.

The binaries are not code-signed. That does not affect a `curl` download, but
macOS quarantines what a browser downloaded — `xattr -d com.apple.quarantine
jailscale` — and Windows SmartScreen warns for the same reason.

### A container image

For linux/amd64 and linux/arm64. `:v0.1.0` pins this release, `:latest` follows
releases, `:edge` follows main.

```
docker pull ghcr.io/eth219/jailhub:v0.1.0
docker pull ghcr.io/eth219/jailscale:v0.1.0
```

### Anything else, with a JVM 25

`jailscale.jar` and `jailhub.jar` are in the release as well and need no
GraalVM: `java -jar jailscale.jar version`. They cost the JVM's startup and
memory, so every number under [Resource usage](#resource-usage) is the native
binary and none of them applies to the JAR.

### From source

```sh
./mvnw package    # the JARs
./native.sh       # the native binaries, needs GraalVM
```

## Usage

A hub is running at **`jailscale.sinabro.io`**. Registration is open, so you can
point a node at it and start. It is rate limited per address, and the operator
can remove a node or bar an address, which is worth knowing before you treat it
as anything but a place to try this out.

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
jailscale update                              # say whether a newer release is out; never installs it
jailscale ls | close NAME | status | down
jailscale service install                     # keep the daemon running across logins
```

### Running your own hub

You need a host with a public address, a domain, and two ports: 443, and 53
because the hub answers DNS for its own `_acme-challenge` name, which is how it
issues its own wildcard certificate with no DNS provider API token. Port 80 is a
third only for domains a node brings itself, which are proven by an http-01
challenge the hub relays; without it that one feature is off.

```
jailscale.example.com.                  A   203.0.113.10
*.jailscale.example.com.                A   203.0.113.10
_acme-challenge.jailscale.example.com.  NS  jailscale.example.com.
```

```sh
jailhub serve --base-url https://jailscale.example.com --acme-email you@example.com
```

The first run prints an invite. Whoever joins with it becomes the administrator.
[deploy/](deploy/) has a systemd unit, container files, and the proxy
configurations for putting the hub behind nginx or HAProxy.

## Resource usage

Measured with the native binaries by `./measure.sh`, which CI runs as a budget
on every push to main. Two platforms, because the same code measures differently
on each: an amd64 binary is bigger than an arm64 one, and Linux counts the
binary's own mapped pages in RSS where macOS largely does not.

| | jailhub | jailscale |
|---|---|---|
| Binary, as released | 29.9 / 31.7 MiB | 30.2 / 32.0 MiB |
| Idle RSS | 29.0 / 40.3 MB | 29.0 / 39.9 MB |
| Peak RSS, 1,000 visitors held open at once | 49.1 / 68.6 MB | 51.8 / 60.3 MB |
| CLI cold start | — | 6 / 4.5 ms |

*arm64 macOS / linux-amd64.* On Linux most of that idle RSS is the binary mapped
into the process — clean pages the kernel takes back when it needs them. The
anonymous memory, the part that is really the process's, is 6 MB for the hub and
5 MB for the node.

These are the released binaries. Building them yourself with profile-guided
optimization takes about 10 MiB off each and a fifth off the idle figures;
[profiles/](profiles/) has the profiles and one command to use them, and
[ARCHITECTURE.md §14](docs/ARCHITECTURE.md) says why the release does not.

Idle is a fresh start, not a steady state. The heap has a ceiling, 96 MB for the
hub and 64 MB for the node, and a long-running process drifts up towards it:
without one the Serial GC's allowance is 80% of the machine, and the hub above
was found at 78 MB of RSS, 54 MB of it anonymous, after 20 idle hours. It is not
a leak — the plateau follows the ceiling rather than the workload — and
[ARCHITECTURE.md §14](docs/ARCHITECTURE.md) has the measurements both ways.

Speed, from the same script: on connections already open the pair moves about
35,000 requests a second here and 9,000 on a four-core Linux runner. A fresh TLS
handshake costs much more than a request, since it opens a stream and takes a
signature, and the hub signs at most 1,000 a second for any one node — the
ceiling that matters when visitors arrive rather than when they stay.

The hub above runs on a GCP e2-micro: 2 shared vCPU, 1 GB of memory, Debian 12.
That is the smallest instance Google sells, and it is not the constraint.

Requirements:

| | Hub | Node |
|---|---|---|
| Inbound ports | 443 and 53, plus 80 for user domains | none |
| Public address | yes | no |
| Root | no (`CAP_NET_BIND_SERVICE`) | no |
| TUN device | no | no |
| Runtime to install | none | none |

A hub accepts 1,024 concurrent visitors per name and 20 names per node, and signs at most 1,000
TLS handshakes a second for any one node, with a burst of 2,000.

## Trust

The hub holds the wildcard private key. A compromised hub cannot read traffic to
a healthy node, but it can move a name to a node of its own and sign for it. The
node's self-probe detects that afterwards, on its own schedule or when you type
`jailscale verify`, and an honest hub reports the move on its own. Names you
bring yourself are not exposed this way: the key stays on the node and the hub
only routes.

What a compromised hub can and cannot do is written out in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Not done yet

- No production track record. The hub above has been up since 2026-09-11.
- The hub is a single process on a single host. Losing the host means downtime.
  Replacing the binary without dropping nodes works with `serve --takeover`, but
  not under a systemd unit, where an upgrade is a restart.
- `service install` is verified on macOS only. Linux and Windows are untested
  outside CI.
- Upgrading is manual. `jailscale update` says when a release is out; nothing
  installs it for you.
- Idle memory is 29 MB against a 20 MB goal (39.9 MB as Linux counts it, 5 MB
  of it anonymous). Most of the gap is JSSE standing up a TLS client.
- No standby hub, no state replication.
- v0.1.0 is the first tagged release, so there is no upgrade path to have got
  wrong yet. What the protocol promises across versions is
  [ARCHITECTURE.md §5.4](docs/ARCHITECTURE.md).

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
