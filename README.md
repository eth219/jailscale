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

Two binaries, no runtime dependencies, nothing to install underneath them. Full
design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Scope

One server you own runs `jailhub`, or two that stand in for each other. Every
machine that publishes something runs `jailscale`. It does what ngrok,
Cloudflare Tunnel and frp do — the first two hosted, frp on a server you run —
with no third party in the path. Tailscale is larger: a mesh between your own
machines, of which Funnel is this one job.

1. **Lightweight.** 25 MiB per binary, 25 MB idle, milliseconds for a CLI round
   trip ([Resource usage](#resource-usage)). That needs GraalVM Native Image,
   which means no reflection, no dependency injection, no dynamic class loading
   and no third-party runtime dependency: JSON, HTTP/1.1, ACME, DNS, the
   multiplexer and the Noise handshake are written here.
2. **Usability.** `jailscale open 3000` and the link is live. The operator
   creates three DNS records and opens two ports; the wildcard certificate
   arrives on its own, because the hub is the authoritative DNS server for its
   own `_acme-challenge` name. No DNS provider API token anywhere.
3. **Portability.** No root, no TUN device, no kernel module, no inbound port.
   One outbound TCP connection is all the node needs; a published UDP port
   rides it too. Four native platforms plus a pure-JVM fallback JAR.
4. **Least privilege at the edge.** The hub reads the TLS SNI and nothing else,
   so it never parses visitor HTTP and never holds plaintext. Its wildcard key
   signs one handshake digest per visitor, and only for a stream the hub itself
   delivered to that node; domains you bring yourself never involve that key.
   The node checks the hub's honesty from its own side ([Trust](#trust)), and
   the control channel is Noise IK inside TLS, so a compromised certificate
   authority still does not get you the control plane.

Out of scope: a peer mesh VPN, wire compatibility with Tailscale or ngrok or
frp, reading the visitor's HTTP — neither end parses it, so no routing on paths
or headers, no rewriting, no per-request log — HTTP/2 and HTTP/3 on the visitor
side, more than one node behind a name, mobile clients, and an external identity
provider ([ARCHITECTURE.md §10](docs/ARCHITECTURE.md)). There is no hosted
service either: you run the hub, and there is nothing to sign up for.

## Install

`jailscale` is the node: the binary you run on the machine whose port you want
to publish. `jailhub` is the hub, and you only need it if you are running your
own. Neither has a runtime dependency and neither needs root to run.

### A binary

v0.1.10 carries four targets for both programs: `linux-amd64`, `linux-arm64`,
`darwin-arm64` and `windows-amd64.exe`. There is no `darwin-amd64`, because
GraalVM CE 25.3 does not build one ([ARCHITECTURE.md
§3.2](docs/ARCHITECTURE.md)); Intel Macs get [the JAR](#anything-else-with-a-jvm-25).

```sh
base=https://github.com/eth219/jailscale/releases/download/v0.1.10
target=darwin-arm64   # pick yours

curl -fsSL -O "$base/jailscale-$target" -O "$base/SHA256SUMS.txt"
shasum -a 256 --ignore-missing -c SHA256SUMS.txt   # sha256sum -c on Linux
sudo install -m 755 "jailscale-$target" /usr/local/bin/jailscale
jailscale version
```

Keep the release's own filename until the checksum has been checked; renamed,
there is nothing in `SHA256SUMS.txt` to match and `--ignore-missing` verifies
nothing. `jailhub-$target` is the same download for the hub.

Once there is a `jailscale` on the machine, `jailscale update` says whether a
newer release is out, and `jailscale update --download` fetches the right
target, verifies it against the Ed25519 signature the maintainer publishes with
each release, and prints the one command that installs it. It stops there on
purpose: nothing here replaces a binary you are running. What the signature
covers, how to check it without `jailscale`, and why the binaries are not
code-signed is in [docs/release-verification.md](docs/release-verification.md).

### A container image

```
docker pull ghcr.io/eth219/jailhub:v0.1.10
docker pull ghcr.io/eth219/jailscale:v0.1.10
```

linux/amd64 and linux/arm64, distroless, non-root, built by the same workflow
as the binaries. `:latest` follows signed releases and `:edge` follows main.
Inside a container `127.0.0.1` is the container's own loopback, so the node
reaches your app by name on a shared network or with `--network host`;
[deploy/README.md](deploy/README.md) has both and the state volume to keep.

### Anything else, with a JVM 25

`jailscale.jar` and `jailhub.jar` are in the release as well and need no
GraalVM: `java -jar jailscale.jar version`. They cost the JVM's startup and
memory, so nothing under [Resource usage](#resource-usage) applies to them.

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
jailscale open 51820 --udp                    # a raw UDP port, carried over TCP
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

A second host can stand by for the first. Copy the first host's `hub.key` into
the second's state directory and run the same command there with
`--peer https://jailscale.example.com`. It follows the first — certificate,
keys, every change to the state — and if the subdomain is delegated to both
hosts instead of the three records above, nodes connect to both, a visitor who
reaches either is served, and the standby promotes itself once its nodes
confirm the first is gone. The records, what promotion needs, and the
availability figure each hub's page shows are in
[ARCHITECTURE.md §13](docs/ARCHITECTURE.md).

## Resource usage

Measured on main with the native binaries by `./measure.sh`, which CI runs as a
budget on every push there, with the toolchain and options the release workflow
uses. The figures are v0.1.2's; the releases since changed the hub's control
plane and nothing on a visitor's or an idle process's path, and the same gate
held on each release commit ([ARCHITECTURE.md §14](docs/ARCHITECTURE.md)).

| | jailhub | jailscale |
|---|---|---|
| Binary size | 25.3 / 26.1 MiB | 25.5 / 26.4 MiB |
| Idle RSS | 25.1 / 35.6 MB | 25.0 / 34.4 MB |
| Peak RSS, 1,000 visitors held open at once | 52 / 62 MB | 52 / 55 MB |
| CLI cold start | — | 6.3 / 2.6 ms |

*arm64 macOS / linux-amd64.* On Linux most of the idle figure is the binary
mapped into the process, clean pages the kernel takes back when it needs them;
the memory that is really the process's is 3 MB for the hub and 2 MB for the
node. Idle is a fresh start, not a steady state: the heap has a ceiling, 96 MB
for the hub and 64 MB for the node, and a long-running process drifts up
towards it rather than towards the workload. §14 has the idle figure taken
apart, the toolchain v0.1.0 was built with and what it cost, and the long-run
measurements.

Speed, from the same script: on connections already open the pair moves about
38,000 requests a second here and 14,000 to 17,500 on a four-core Linux runner.
A fresh TLS handshake costs more, since it opens a stream and takes a
signature, and the hub signs at most 1,000 a second for any one node, 2,000 in
a burst. A hub accepts 1,024 concurrent visitors per name and 20 names per
node. The hub above runs on a GCP e2-micro, the smallest instance Google sells,
and it is not the constraint.

Those are the code's numbers, with no network in the way. For what a visitor
pays from wherever they are, [docs/demo/](docs/demo/) is an app to publish and
a page that times the link it arrived on; the keyless handshake costs round
trips, not CPU, and a visitor pays it once on arrival.

What each side needs:

| | Hub | Node |
|---|---|---|
| Inbound ports | 443 and 53, plus 80 for user domains | none |
| Public address | yes | no |
| Root | no (`CAP_NET_BIND_SERVICE`) | no |
| TUN device | no | no |
| Runtime to install | none | none |

## Trust

The hub holds the wildcard private key. A compromised hub cannot read traffic to
a healthy node, but it can move a name to a node of its own and sign for it. The
node catches that afterwards from its own side: the daemon opens a session to
each of its own public names once every half hour, one at a time, and
`jailscale verify` does all of them at once; either way it compares RFC 5705
exported keying material against what it recorded, which a hub that terminated
the TLS itself cannot match.
`status` keeps each name's last verdict, and an honest hub reports the move on
its own. Names you bring yourself are not exposed this way: the key stays on the
node and the hub only routes.

What a compromised hub can and cannot do is written out in
[ARCHITECTURE.md §11](docs/ARCHITECTURE.md).

## Limits

- No production track record. The hub above is the only instance with any
  uptime behind it, and it serves one person's names.
- Two hubs is the most there can be, and streams in flight on a host that dies
  are cut. Raw TCP and UDP ports live on the primary alone. Replacing the
  binary without dropping nodes works with `serve --takeover`, but not under a
  systemd unit, where an upgrade is a restart.
- Upgrading stops one step short of automatic: `update --download` verifies,
  you run the `install` it prints. Which release is *current* comes from a signed
  pointer that expires, and a node refuses one older than the newest it has seen,
  so being held back on an old release is visible and cannot be repeated -- but a
  node installed fresh has nothing to compare with yet. It is never moved below
  what it runs.
- A hub and its nodes can be upgraded separately, and have been, each way that
  has been tried; a newer node against an older hub and rolling back have not
  ([ARCHITECTURE.md §5.4](docs/ARCHITECTURE.md)).
- `service install` is verified on macOS only. Linux and Windows are untested
  outside CI.
- Idle memory is 25 MB against the 20 MB originally aimed at. Almost all of the
  gap is the binary's own code becoming resident, clean and evictable
  ([docs/jsse-idle-cost](docs/jsse-idle-cost)).

[ARCHITECTURE.md §15](docs/ARCHITECTURE.md) has the rest, in more detail.

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
