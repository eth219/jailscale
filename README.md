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
TUN device, no root, no inbound ports on the node. Full design:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Scope

One server you own runs `jailhub`. Every machine that publishes something runs
`jailscale`. It does what ngrok, Cloudflare Tunnel and frp do — the first two
hosted, frp on a server you run — with no third party in the path. Tailscale is
larger: a mesh between your own machines, of which Funnel is this one job.

1. **Lightweight.** 25 MiB per binary, 25 MB idle, milliseconds for a CLI round
   trip ([Resource usage](#resource-usage)). That needs GraalVM Native Image,
   and Native Image needs discipline: no reflection, no dependency injection, no
   dynamic class loading, no third-party runtime dependency at all. JSON,
   HTTP/1.1, ACME, DNS, the multiplexer and the Noise handshake are written here
   rather than taken off a shelf.
2. **Usability.** `jailscale open 3000` and the link is live. The operator
   creates three DNS records and opens two ports; the wildcard certificate
   arrives on its own, because the hub is the authoritative DNS server for its
   own `_acme-challenge` name and answers its own ACME challenge. No DNS
   provider API token anywhere.
3. **Portability.** No root, no TUN device, no kernel module, no inbound port,
   and one outbound TCP connection is all the node needs on the wire — a
   published UDP port rides that same connection. Four native platforms plus a
   pure-JVM fallback JAR.
   Virtual threads throughout, so a thread per direction per stream is an
   ordinary thing to write rather than something to optimise away.
4. **Least privilege at the edge.** The hub reads the TLS SNI and nothing else,
   so it never parses visitor HTTP and never holds plaintext. Its wildcard key
   signs one handshake digest per visitor, and only when the request is bound to
   a stream the hub itself delivered to that node; domains you bring yourself
   never involve that key at all. The node checks the hub's honesty from its own
   side ([Trust](#trust)), and the control channel is Noise IK inside TLS, so a
   compromised certificate authority still does not get you the control plane.
   The node's side of this is smaller by construction — no root, no TUN device,
   nothing listening — and the published container image puts a filesystem
   boundary around it as well ([A container image](#a-container-image)).

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

v0.1.2 carries four targets for both programs: `linux-amd64`, `linux-arm64`,
`darwin-arm64` and `windows-amd64.exe`. There is no `darwin-amd64`, because
GraalVM CE 25.3 does not build one ([ARCHITECTURE.md
§3.2](docs/ARCHITECTURE.md)); Intel Macs get [the JAR](#anything-else-with-a-jvm-25).
The two targets the budget measures are 25.3 to 26.4 MiB
([Resource usage](#resource-usage)), which is what the rest of this file
describes; the other two carry no measured figure.

```sh
base=https://github.com/eth219/jailscale/releases/download/v0.1.2
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

Once there is a `jailscale` on the machine, it can do the above for you.
`jailscale update` says whether a newer release is out; `jailscale update
--download` picks the right target, verifies `SHA256SUMS.txt` against the
Ed25519 signature published beside it, verifies the binary against that file,
and prints the one command that installs it:

```sh
jailscale update --download
# jailscale 0.2.0 is out; this is 0.1.3. https://github.com/eth219/jailscale/releases/latest
# downloaded  jailscale-darwin-arm64  25.5 MiB
# verified    sha256 3f2a...
#             against a RELEASE.txt for v0.2.0 signed by release key fa85db4931653cbb
#
# install it with:
#   sudo install -m 755 /var/folders/.../jailscale-darwin-arm64 /usr/local/bin/jailscale
```

It stops there on purpose: nothing here replaces a binary you are running
([ARCHITECTURE.md §9.4](docs/ARCHITECTURE.md)). The signing key lives in Cloud
KMS and is used from the maintainer's own machine after the build, never from
the release workflow; its public half is compiled into the binary, so a build
that carries no key refuses to download rather than trusting the checksum file
alone.

What is signed is `RELEASE.txt` — the release's tag and the SHA-256 of
`SHA256SUMS.txt` — rather than the checksum list on its own, which would say
nothing about *which* release it belongs to. To check a release by hand:

```sh
curl -fsSL -O "$base/RELEASE.txt" -O "$base/RELEASE.txt.sig" -O "$base/SHA256SUMS.txt"
openssl pkeyutl -verify -pubin -inkey release-key.pem -rawin \
  -in RELEASE.txt -sigfile RELEASE.txt.sig    # the tag in it must be the one you downloaded
shasum -a 256 SHA256SUMS.txt                  # must equal the sha256sums: line in RELEASE.txt
shasum -a 256 --ignore-missing -c SHA256SUMS.txt
```

The public key is in
[`ReleaseKey.java`](node/src/main/java/io/jailscale/node/ReleaseKey.java), base64
of the DER SubjectPublicKeyInfo; `base64 -d > release-key.der` and `openssl pkey
-pubin -inform DER -in release-key.der -out release-key.pem` turns it into the
file above.

Separately, every released file carries a build attestation, which says which
workflow built it rather than who approved it:

```sh
gh attestation verify jailscale-darwin-arm64 --repo eth219/jailscale
```

The binaries are not code-signed. That does not affect a `curl` download, but
macOS quarantines what a browser downloaded — `xattr -d com.apple.quarantine
jailscale` — and Windows SmartScreen warns for the same reason.

### A container image

For linux/amd64 and linux/arm64, built by the same workflow, toolchain and
options as the binaries above, so [Resource usage](#resource-usage) describes
them too. `:v0.1.2` pins that tag, `:latest` follows releases (it moves when
one is published, after signing, not when a tag is pushed), `:edge` follows
main.

The images tagged `:v0.1.0` are not worth pulling: they were built before the
runtime base carried a libc, so they answer `exec /jailscale: no such file or
directory` instead of starting, and `:latest` pointed at one of them until this
release.

```
docker pull ghcr.io/eth219/jailhub:v0.1.2
docker pull ghcr.io/eth219/jailscale:v0.1.2
```

Both images are distroless and run as a non-root user: the binary, glibc and
zlib, no shell, no package manager, no JVM. That is worth most on the hub,
which holds the wildcard private key and is the one part of this with a public
address. On the node it adds a filesystem boundary — what reaches the process
does not reach your home directory — around a program that needed no root to
begin with.

The container runs the daemon, and the CLI is `exec`ed into it:

```sh
docker network create demo   # the app joins this too, see below
docker run -d --name jailscale --network demo \
    -v jailscale-state:/var/lib/jailscale ghcr.io/eth219/jailscale:v0.1.2
docker exec jailscale /jailscale up --hub jailscale.sinabro.io
docker exec jailscale /jailscale open 3000 --host myapp --name myapp
```

The one thing to know first: `127.0.0.1` inside a container is the container's
own loopback, and reaching a local service is the node's whole job. There are
two ways out and they are not equally isolated. Put the app on the same
container network and name it with `--host`, as above, which needs no published
port on the app either and keeps both boundaries. Or run the node with
`--network host` and keep `127.0.0.1`, which hands back the network namespace
and leaves only the filesystem one. The state volume holds the machine key,
which is the node's identity: lose it and you rejoin as a new node.

macOS and Windows nodes run the binary. These images are Linux only.

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

## Resource usage

Measured on main with the native binaries by `./measure.sh`, which CI runs as a
budget on every push there. Two platforms, because an amd64 binary is bigger
than an arm64 one and Linux counts the binary's own mapped pages in RSS where
macOS largely does not.

This describes v0.1.2, the release [Install](#a-binary) downloads: the budget
builds with the toolchain and options the release workflow uses, so the gate
measures what ships. v0.1.0 did not — it was tagged a day before that pin landed
and was built with Liberica NIK 25.0.4, which cost it about 5 MiB per binary,
5 to 6 MB of idle RSS on linux-amd64 and 2.3 ms of CLI start.
[ARCHITECTURE.md §14](docs/ARCHITECTURE.md) measures both toolchains side by
side.

| | jailhub | jailscale |
|---|---|---|
| Binary size | 25.3 / 26.1 MiB | 25.5 / 26.4 MiB |
| Idle RSS | 25.1 / 35.6 MB | 25.0 / 34.4 MB |
| Peak RSS, 1,000 visitors held open at once | 52 / 62 MB | 52 / 55 MB |
| CLI cold start | — | 6.3 / 2.6 ms |

*arm64 macOS / linux-amd64.* Both columns are v0.1.2's own tree and toolchain:
linux-amd64 is the gate's output on the release commit, macOS a local run of the
same script on the same binaries. The node's peak fell from 69 MB to 52 with the
visitor bound ([ARCHITECTURE.md §9.3](docs/ARCHITECTURE.md)), which is the same
drop Linux shows.

On Linux most of that idle RSS is the binary mapped into the process, clean pages
the kernel takes back when it needs them. The anonymous memory, the part that is
really the process's, is 3 MB for the hub and 2 MB for the node. That is not a
Linux accounting quirk: taking the node's idle figure apart on macOS
([docs/jsse-idle-cost](docs/jsse-idle-cost)) finds the same thing, 8.0 MB of RSS
between a daemon that has never opened a TLS connection and one connected with a
link open, and 1.5 MB of it pages the process has written.

Two things about the idle row are worth knowing before it is compared with
anything. It is sampled in the daemon that has just joined, and joining is 2.0 MB
that a node pays once — restarted, the same node idles about 2 MB lower. And
`measure.sh` joins with `--ca-file`, so it describes a node whose trust manager
holds two certificates; a node joined to a hub with an ordinary web-PKI
certificate leaves that null and pays about 0.55 MB more for the trust store the
binary carries, which no budget here measures. Together, a long-running node on a
public-CA hub settles near 23.7 MB against the 25.0 in the table. Both figures
are darwin-arm64.

Idle is a fresh start, not a steady state. The heap has a ceiling, 96 MB for the
hub and 64 MB for the node, and a long-running process drifts up towards it: the
hub above was found at 78 MB of RSS, 54 MB of it anonymous, after 20 idle hours.
It is not a leak — the plateau follows the ceiling rather than the workload —
and [ARCHITECTURE.md §14](docs/ARCHITECTURE.md) has the measurements both ways.

Speed, from the same script: on connections already open the pair moves about
38,000 requests a second here and 14,000 to 17,500 on a four-core Linux runner.
A fresh TLS handshake costs much more than a request, since it opens a stream
and takes a signature, and the hub signs at most 1,000 a second for any one
node, 2,000 in a burst — the ceiling that matters when visitors arrive rather
than when they stay. A hub also accepts 1,024 concurrent visitors per name and
20 names per node.

The hub above runs on a GCP e2-micro: 2 shared vCPU, 1 GB of memory, Debian 12.
That is the smallest instance Google sells, and it is not the constraint.

Those are the code's numbers, measured with no network in the way. For a
visitor's numbers — what the handshake and the round trip cost from wherever
they are — [docs/demo/](docs/demo/) is an app to publish and a page that times the link it
arrived on. It is a demonstration, not a gate: a browser on the internet
measures its own distance to the hub at least as much as it measures either
binary.

What it says with a network in the path, through the hub above on 2026-09-14,
with the visitor and the node each about 7 ms from it: a TCP round trip of 6.6
to 6.7 ms, a TLS handshake of 29 to 33 ms on top of that, and a warm round trip
of 14 ms at p50, about twice the floor for the extra hop. **The keyless
handshake costs round trips, not CPU** — the same handshake measures 2.4 ms on
loopback, where the round trips are free, and the hub's own work in it is one
signature. That is the shape to plan for: a visitor pays it once on arrival, and
nothing after that.

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
one of its own public names every half hour, `jailscale verify` does all of them
at once, and either way it compares RFC 5705 exported keying material against
what it recorded, which a hub that terminated the TLS itself cannot match.
`status` keeps each name's last verdict, and an honest hub reports the move on
its own. Names you bring yourself are not exposed this way: the key stays on the
node and the hub only routes.

What a compromised hub can and cannot do is written out in
[ARCHITECTURE.md §11](docs/ARCHITECTURE.md).

## Limits

- No production track record. The hub above is the only instance with any
  uptime behind it, and it serves one person's names.
- The hub is a single process on a single host, with no standby and no state
  replication. Losing the host means downtime. Replacing the binary without
  dropping nodes works with `serve --takeover`, but not under a systemd unit,
  where an upgrade is a restart.
- Upgrading stops one step short of automatic. `jailscale update --download`
  fetches a release and checks it against the signature; you run the one
  `install` command it prints. A binary built before the signing key existed
  carries no key and refuses to download at all. Which release is *current*
  comes from an unsigned index, so publishing can withhold an upgrade from a
  node that is behind, though never move one backwards
  ([ARCHITECTURE.md §15](docs/ARCHITECTURE.md)).
- `service install` is verified on macOS only. Linux and Windows are untested
  outside CI.
- Idle memory is 25 MB against the 20 MB originally aimed at (34.4 MB as Linux
  counts it, 2 MB of it anonymous). This used to say that most of the gap was
  JSSE standing up a single TLS client; measuring it
  ([docs/jsse-idle-cost](docs/jsse-idle-cost)) says otherwise. Almost all of the
  gap is the binary's own code becoming resident as it runs for the first time —
  clean pages, evictable — and standing up the TLS client writes 139 KB. The
  number is real and the explanation for it was not.
- Upgrades have been exercised once each way they have been tried, on one hub
  and one node. v0.1.2 is the third tagged release, and each step added one
  optional `Hello` field — `host` before v0.1.1, `visitors` before v0.1.2 —
  which is the additive case [ARCHITECTURE.md §5.4](docs/ARCHITECTURE.md)
  permits, pinned in `WireFormatTest` against v0.1.0's own `Hello` line. Both
  steps have also run mismatched on the hub above: a released v0.1.0 node
  against a hub that reads `host`, and the hub on v0.1.2 for half an hour while
  its node was not, the capacity row reading `not advertised` throughout. So a
  hub and its nodes can be replaced separately rather than together. Not tried:
  the other order, a newer node against an older hub, and rolling either half
  back.

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
