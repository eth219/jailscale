# jailscale architecture

A self-hosted HTTPS tunnel. A node runs `jailscale open 3000` and `https://<name>.<hub-domain>`
starts serving whatever listens on that node's local port. Visitors install nothing. The hub reads
the TLS SNI and forwards ciphertext; the node terminates TLS and asks the hub for one signature per
handshake.

This describes the system as it stands, organised by subsystem. Section numbers are stable.

[1. Scope](#1-scope) · [2. Pieces](#2-pieces) · [3. Modules and build](#3-modules-and-build) ·
[4. Keys](#4-keys-and-identity) · [5. Control channel](#5-control-channel) ·
[6. Control API and state](#6-control-api-and-hub-state) · [7. Certificates](#7-certificates-and-acme) ·
[8. Public ingress](#8-public-ingress) · [9. The node](#9-the-node) · [10. Joining](#10-joining) ·
[11. Security model](#11-security-model) · [12. Threading](#12-threading-and-memory) ·
[13. Availability](#13-availability-and-hand-off) · [14. Characteristics](#14-current-characteristics) ·
[15. Limits](#15-limits)

---

## 1. Scope

One server you own runs `jailhub`. Every machine that publishes something runs `jailscale`. It does
what ngrok, Cloudflare Tunnel and Tailscale Funnel do, with no third party in the path.

1. **Lightweight.** The node is a resident daemon: one executable, no runtime dependency, small idle
   footprint, millisecond CLI round trips. Measured and gated in CI (§14).
2. **Usability.** Publishing is one line, inviting is one line, and the operator sets three DNS
   records and opens two ports. Lengthening that setup list counts as a regression.
3. **Portability.** No root, no TUN device, no kernel module, no inbound port, and one outbound TCP
   connection is all the node needs on the wire; a published UDP port (§8.4) rides that same
   connection. A pure-JVM fallback JAR ships beside the native binaries.

Out of scope: a peer mesh VPN, wire compatibility with Tailscale or ngrok or frp, HTTP/2 and HTTP/3
on the visitor side, mobile clients, an external identity provider (§10).

---

## 2. Pieces

```
   visitor browser                       jailhub (one process)                     jailscale node
   https://myapp.hub.example.com     ┌──────────────────────────────────┐      ┌──────────────────────┐
          │                          │  :443  SNI router                │      │ TLS termination      │
          │  TLS ClientHello         │   ├ hub.example.com -> own HTTP  │ mux  │  ├ signing delegated │
          ├─────────────────────────>│   ├ *.hub...       -> node stream├─────>│  ├ visitor gate      │
          │  (ciphertext passes      │   └ user domain    -> node stream│Noise │  └ plaintext to      │
          │   through untouched)     │  coordinator: invites, names     │ in   │     127.0.0.1:3000   │
          │                          │  ACME: wildcard via own DNS-01   │ TLS  │                      │
          │                          │  :53   _acme-challenge TXT       │<─────│ CLI <-> daemon       │
          │                          │  admin IPC and /admin web        │      │      (AF_UNIX)       │
          │                          │  signing service: wildcard key   │      └──────────────────────┘
          │                          └──────────────────────────────────┘
```

- **The hub only reads SNI.** It peeks the ClientHello on 443 and hands the byte stream to the node
  that owns the name. It never parses visitor HTTP, so its internet-facing attack surface is a
  TCP-level parser and it sees only ciphertext.
- **The node terminates TLS without holding the key.** One `*.hub.example.com` wildcard covers every
  name, and its private key never leaves the hub. The node asks for the one handshake signature, and
  the hub signs only when the request is bound to a stream it delivered to that node (§9.2).
- **The node does not parse HTTP either.** It strips TLS and copies plaintext to the local port, so
  HTTP/1.1, WebSocket, SSE and chunked bodies all pass. The only HTTP parsers in the system are a
  small one for the control channel and the first-request-head read the visitor gate needs.

TCP 443 carries everything and UDP/TCP 53 carries the ACME DNS-01 answers. TCP 80 is optional (HTTPS
redirect and the http-01 relay user domains need), and raw TCP/UDP publishing adds one port range.
The node needs outbound 443 and nothing else. A local port exposed to the internet is a **link**;
invite links (§10) and visit links (§9.3) are different things.

---

## 3. Modules and build

Maven multi-module, dependencies flowing one way only. Packages are `io.jailscale.*`.

| Module | Contents |
|---|---|
| `crypto` | BLAKE2s, HMAC, HKDF, X25519, ChaCha20-Poly1305, Noise IK, key encoding |
| `proto` | control messages and JSON codec, mux framing, minimal HTTP/1.1, SNI parser, ACME client, PROXY protocol, IPC, logging |
| `node` | daemon, CLI, local IPC, TLS termination, remote-signing provider, gate. Binary `jailscale` |
| `hub` | SNI router, coordinator, ACME and DNS responder, signing service, admin IPC and web. Binary `jailhub` |

Two binaries so server code never lands in the client artifact; the module boundary turns a
dependency inversion into a compile error rather than a review comment.

### 3.1 GraalVM Native Image rules

Followed from the start, not retrofitted. Together they are why the binaries are one file with no
reachability metadata and no third-party jars.

| Item | Rule and reason |
|---|---|
| Reflection, dynamic proxies, dynamic class loading, DI frameworks | Forbidden; constructors wired by hand. Metadata upkeep and binary bloat, and Spring and Guice are reflection engines |
| JSON | Own parser and encoder. Jackson means reflection and megabytes for about a dozen schemas |
| HTTP | Own minimal HTTP/1.1 at both ends. `com.sun.net.httpserver` will not hand back the socket after an Upgrade and `HttpClient` will not either, and writing our own keeps `java.net.http` out of both binaries |
| TLS | JDK JSSE: `SSLServerSocket` on the hub, `SSLEngine` on the node. Already in the image |
| Remote signing | Own JCE `Provider`, opaque `PrivateKey`, `Signature` SPI: the path PKCS#11 keys take. Registered by overriding `Provider.Service.newInstance`, so no reflection |
| ACME client, DNS responder | Own. Only the PKCS#10 DER and the DNS answers are genuinely hand-written |
| Logging | Own small logger over `System.Logger`. SLF4J plus logback means ServiceLoader and reflection |
| Cryptography | JDK JCE for X25519 and ChaCha20-Poly1305; own BLAKE2s, HMAC and HKDF. BouncyCastle is large and awkward here, and those three are forced: the JDK has no BLAKE2s, and Noise defines HMAC and HKDF over the chosen hash. Noise's HKDF also differs from RFC 5869 (an output counter byte instead of salt and info, at most three chained outputs) |
| AWT and `java.awt.Desktop`; IPC | Forbidden, so browsers open through `ProcessBuilder`; AF_UNIX everywhere, since Windows 10 1803+ supports it and named pipes have no public JDK API |
| Threading; build-time initialisation | Virtual threads throughout, because there is no packet hot path (§12). **Nothing is configured to initialise at build time**: the native configuration is `-O2`, `-H:+ReportExceptionStackTraces` and a per-binary `-R:MaxHeapSize` (§14), so the image otherwise takes native-image's own policy. Whatever is whitelisted later must leave JCE on the run-time side, or a `SecureRandom` seed is frozen into the image |

### 3.2 Build and toolchain

**Maven**, not Gradle: with zero third-party dependencies there is nothing for Gradle's dependency
and build-logic flexibility to do, and a fixed lifecycle drifts less across four platforms. `./mvnw`
runs in **only-script** mode so no binary jar is committed, because a project that ships signed
binaries should not carry a jar whose provenance it cannot check, and the Maven distribution it
fetches is pinned with `distributionSha256Sum`. Keeping the supply-chain surface at zero is the point
of this section. `-Pnative` produces the binaries for linux on amd64 and arm64, darwin-arm64 and
windows-amd64, and each release also ships `jailscale.jar` and `jailhub.jar` for JVM 25 -- which is
what an Intel Mac runs, since the toolchain §3.2 settles on does not build that target.

**Static analysis is a job, not a build step.** `-Xlint:all -Werror` runs in every build, because
it is a compiler already on the machine. SpotBugs is a third party with a dependency tree of its
own, and the supply-chain argument above does not stop at runtime dependencies, so it lives behind
`./mvnw -Panalyze verify` and runs as its own CI job: building from source still needs nothing but
a JDK. It reads bytecode, so it sees the class of mistake `-Xlint` cannot — a field written by one
thread and read by another without a lock, a stream never closed, a return value dropped — which is
the class this project's threading makes easy to write. Its exclusions are in
`spotbugs-exclude.xml` and each one states its reason, because an exclusion with no reason and a
finding nobody answered look identical six months later.

**Coverage is a profile too, and nothing is gated on the number.** `./mvnw -Pcoverage verify`
writes a report to `coverage/target/site/jacoco-aggregate`. JaCoCo is a third party with a
dependency tree, so it lives behind a profile for the same supply-chain reason SpotBugs does; what
it is *not* is a threshold. `node.Main` reads 3.9% of its lines covered while being one of the
better tested classes here, because `CliTest` runs the CLI as a process and an agent attached to the
test JVM cannot see into a child. A threshold would have punished that test for having the right
shape and pushed its assertions back in-process, giving up the argument parsing, the exit codes and
the daemon spawn that are the point of it. Coverage here is a way to find code nothing runs, not a
number to defend.

**The number is only right when it is aggregated, and getting that wrong is silent.** Per-module
figures mislead badly in this build: hub's end-to-end tests exercise most of `node`, which alone
reports 23.2% against 68.1% merged. The aggregation lives in `coverage/`, a module that exists only
inside the profile, because jacoco's `report-aggregate` reads the *direct compile* dependencies of
wherever it runs — run from `hub` it covered hub and proto and dropped `node` (a test-scope
dependency) and `crypto` (reached through proto), printing a plausible number for two thirds of the
code. `CoverageModuleTest` holds the root pom's module list against that module's dependency list,
because the next module added is the next one silently left out.

**Three workflows.** `ci` is the gate: the tests on ubuntu, macos and
Windows for every push and pull request, and on main and nightly two more jobs that are too heavy
for a pull request -- the §14 budget, which needs a native build, and the `load`-tagged tests, which
hold a thousand sockets open. Both of those were written before anything ran them: `-Dgroups=load`
appeared in no workflow, so `LoadTest` ran only when somebody typed it, and the budget job left
`SLOW=` out, so the one axis §14 records as over its budget was also the one axis nothing on main
measured. A test excluded by a tag and a phase skipped by an unset variable fail the same way,
which is silently. The first run of the saturation phase then found why leaving it out had been
comfortable: at a thousand stalled readers it does not measure a peak, it reaches the open
per-visitor defect (§14). It runs at 400, where it measures the node. Windows was a
nightly job for a while, because the stall below failed about 2% of runs and a gate that is red
2% of the time teaches people to ignore it; it is per-push now that the stall is fixed and measured
at 0 in 3,000, and it costs 1.5 min against the other two at 1.2. The nightly run gates nothing any
more and stays for drift in the runner images and in what `graalvm-community` + `25.3` resolves to. `release`
builds the four native targets on a tag, and `images` the two container images. The images build with
`-DskipTests`, deliberately: they are packaging, not verification. They build the binary with the
release's toolchain and copy it onto a distroless base, rather than building it inside the image as
they used to -- the only JDK 25 `ghcr.io/graalvm/native-image-community` publishes is 25.0.2, the
version the next paragraph forbids, so every image published before this carried the one JDK the
release is pinned away from.

Two toolchain hazards are load-bearing. **JDK 25.0.0 to 25.0.2 must not be used**: moving
virtual-thread timed park onto ForkJoinPool delayed tasks (JDK-8351927) made cancelling a delayed
task corrupt the scheduler heap, so other threads' `Thread.sleep` wakes late or never (JDK-8370887),
and virtual threads get stuck PARKED (JDK-8369227). Hand-off cancels the old connection's keepalive
sleep by interrupt, which is exactly that path, so the release workflow builds on GraalVM CE 25.3
(JDK 25.0.4.1). Note that `setup-graalvm`'s `version:` and `java-version:` are different knobs:
`java-version: '25'` on the community distribution still resolves **25.0.2**, which is why that
distribution looked unusable until `version: '25.3'` was tried. **The 25.3 line does not build
macos-amd64**, which is why the release workflow builds four native targets and not five: Intel Macs
get `jailscale.jar`. v0.1.0 was tagged the day before that pin landed and is the one release that
carries five, `darwin-amd64` among them; v0.1.1 is the first built on this pin. §14 has what the line
is worth, which is most of a doubling in throughput, and what v0.1.0 shipped instead. And **Windows
cannot poll one socket for read and for write at the same time**: the JDK gives virtual threads one wepoll handle per direction, and
with a thread parked on each direction of the same socket the AFD driver underneath completes the
wrong one, leaving the thread that asked for the event asleep for good (JDK-8334574, open, and still
present in 26). So one side of every socket two threads use at once runs on a platform thread, which
enters no poller at all: `io.jailscale.proto.net.DuplexThread`, Windows only. The 60 s read timeout
(§5.1) and 25 s keepalive (§5.3) stay as the backstop. Measured, with the variants that isolate the
condition, in `docs/windows-virtual-thread-stall/`.

---

## 4. Keys and identity

| Key | Held by | Purpose | Lifetime |
|---|---|---|---|
| **MachineKey** (`mkey:`) | node | Noise static key of the control-channel client. The machine's identity, and its `/admin` login identity | Life of the machine |
| **hub key** (`hkey:`) | hub | Noise static key of the control-channel server. Pinned by nodes | Rotatable (§5.2) |
| **Wildcard certificate key** | hub | ECDSA P-256 for `hub.example.com` and `*.hub.example.com`. **Never leaves the hub** | New on each ACME renewal |
| **User domain key** | node | Certificate key for a domain the user brought. Not on the hub | New on each node-side renewal |

A node's identity is its MachineKey alone; node id and name ownership hang off it. Encoding is
`prefix:base64url-nopad`, so the key type is visible in logs and a key pasted into the wrong slot
fails at parse time. Node state is `node.json` (0600) under `$XDG_CONFIG_HOME/jailscale/` or
`%LOCALAPPDATA%\jailscale\`, with user-domain keys beside it under `domains/`. Hub state is §6.2.

---

## 5. Control channel

### 5.1 Noise inside TLS

Node to hub traffic is a Noise_IK channel opened inside a web-PKI TLS connection. The carrier is an
HTTP/1.1 Upgrade; after the 101 it is a byte stream, and the multiplexer rides on top.

```
TCP 443, SNI = hub.example.com
 └─ TLS 1.3, ALPN http/1.1      (web PKI: authenticates the hostname, bootstraps first trust)
     └─ HTTP/1.1 Upgrade        POST /v1/noise, Upgrade: jailscale-control-v1
         └─ Noise_IK            (MachineKey <-> hub key; holds without trusting any CA)
             └─ [2B len BE][Noise transport message]    <- one mux frame in each
```

Both HTTP ends are hand-written (§3.1): the hub's front is about 300 lines serving `/v1/key`,
`/v1/noise`, `/join/<token>`, `/admin/*` and a root page, the node's client about 40, and the socket
read timeout is 60 s. WebSocket was rejected as the carrier because its 4-byte client-to-server
masking would touch every visitor byte again, frame headers and close semantics come with it, and it
would only help behind proxies passing `Upgrade: websocket` when SNI passthrough already rules out an
HTTP proxy in front of the hub (§7.2). ALPN is pinned to `http/1.1`, because HTTP/2 has no Upgrade.

**Noise parameters.** `Noise_IK_25519_ChaChaPoly_BLAKE2s`, prologue `jailscale-control-v1`. The
version string is mixed into the handshake hash, so incompatible versions fail the handshake itself
rather than something later. A transport message is at most 65535 bytes, which is why the length
prefix is two bytes.

**Why keep the TLS.** Noise alone authenticates the channel, but the hub-key bootstrap needs some
reason to trust a first contact and web PKI is it, `/join` and `/admin` are browser paths, and
corporate firewalls pass TLS on 443 while dropping unidentifiable binary streams. The hub obtains the
certificate itself, so this costs the operator nothing.

**Why put Noise inside it anyway.** The web PKI threat model still contains CA compromise and the
corporate MITM proxy with its root installed. Both defeat TLS; neither defeats a Noise handshake
against a pinned hub key. This is the same shape as Tailscale's ts2021, and it matters here because
**signature delegation flows over this channel** (§9.2): requests for the wildcard key need
authentication that does not depend on a CA.

### 5.2 Hub key bootstrap and rotation

A node needs one hostname, which the invite link carries. It fetches `GET /v1/key` over ordinary
verified TLS, pins the returned `hkey:`, and every later handshake uses the pinned key; a mismatch is
a hard failure. `jailhub key rotate --grace 30d` generates a next key and announces it as
`HubKeyRotation` inside a channel already authenticated by the old key, so it needs no separate
signature. During the grace period the hub's responder tries each candidate static key against
message 1 and only the right one decrypts, while the node tries current then next. A node that never
connected during the grace period fails with both keys, and only then is the operator asked to
re-trust the hub; an unattended node stays failed and logs why.

`--hub-key hkey:...` skips the `/v1/key` fetch for air-gapped or PKI-distrusting deployments, since
Noise then completes server authentication on its own. Passing the hub key as a clickable
`https://...?key=` URL is deliberately unsupported: people do not verify things that look like links.
An invite is a secret, so a link is the right carrier; a hub public key must be checked, so a link is
the wrong one.

### 5.3 Stream multiplexer

One Noise channel carries many byte streams, one per visitor connection, in a protocol at roughly the
level of yamux and about 500 lines. Frames are `[4B streamId][1B type][1B flags][2B len][payload]`,
exactly one per Noise message. DATA payloads are capped at 16 KB, because filling 65535 would let one
stream monopolise the channel. A stream with the `DGRAM` flag treats one DATA frame as one datagram.

| Type | Payload | Meaning |
|---|---|---|
| `OPEN` | `{linkId, kind, sni, visitorAddr, visitorPort, keyId}` | Hub to node: a visitor connection is delivered |
| `DATA` / `WINDOW` | bytes / `[4B delta]` | Stream data / flow-control window increase |
| `CLOSE` / `RST` | none / `[1B reason]` | Half close (a FIN) / forced teardown |
| `CTRL` / `KEEPALIVE` | JSON / none | **Stream 0 only**, the messages of §6.1 / every 25 s |

- **Flow control** is per stream: a 256 KB receive window refilled once half has been consumed. A
  sender out of credit stops, which keeps one slow visitor from stalling the others. There is no
  retransmission, because the carrier is TCP. A connection-level window would be the other way to
  do it, and is what HTTP/2 does; it is not done here because a window shared across streams is a
  window one stalled stream can eat, which is the starvation the per-stream window exists to avoid.
- **A receive budget** bounds what the per-stream windows do not: their sum. 256 KB plus a frame is
  272 KB, the hub admits 1,024 visitors per name with no global cap, and the product is 272 MB
  against a 96 MB heap ceiling -- so a visitor who simply reads its download slowly, needing no
  registration and no authentication, could make the hub hold bytes until its heap was gone.
  Measured on the native binaries: under a high enough arrival rate it *can*, and when it did the
  `OutOfMemoryError` surfaced on the thread carrying a node's control connection, whose death runs
  `NodeGroup.detach` -- so **the whole node session went, with every link and visitor on it**, and the
  node reconnected a second later. An unauthenticated outage of every name on that node, not a dead
  process. Two hedges, both measured: it fired once in three identical attempts, in the one with the
  fastest ramp, and ramp time tracked the hub's peak inversely across all three -- 144s/134.8 MB,
  176s/121.4 MB, 218s/114.1 MB -- so quote the ramp time beside any peak from this axis or the runs
  read as unexplained scatter. That is the same arrival-rate effect that fills the budget at 120
  visitors arriving in half a second but not at 300 spread over 25s. The ramps also got monotonically
  slower as the machine did, so one in three is an underestimate and not a rate to quote. It also needs the node's own ceiling raised, because at the shipped 64m the node's
  per-visitor TLS state saturates first and the hub never reaches its heap -- which is why this axis
  read as harmless every time it was measured without that. Whether it fires and what it takes with
  it are both chance, which is the argument for bounding it rather than for waiting on a repro. `FlowBudget` is one byte total across every session, a quarter of
  the heap ceiling and derived from it rather than chosen. Over it, the receiver **reclaims**: it
  RSTs the stream holding the most bytes among those that have consumed nothing for two seconds,
  which is a stalled reader and not a slow one. Three things follow. It is a byte bound and not a
  connection count, because deriving a count would have to assume the worst case per connection and
  would cap a hub that really serves a thousand light visitors at a few hundred. It reclaims rather
  than refuses, because refusing would hand an attacker a cheaper denial than the one being fixed
  and would not free what is already held. And **nothing is advertised on the wire** -- RST is
  already the receiver's to send at any time -- so no flag day and no node needs upgrading for a hub
  to protect itself.
- **One writer a session, and control does not queue behind data.** `NoiseChannel.write` holds one
  lock across the encryption and the socket write, because the nonce must advance in wire order. With
  every producer calling it directly, one blocked write stalled every frame on that session: a
  visitor's handshake waited on its `SignResponse` behind other visitors' data — measured at 12.8
  seconds, with two answers released in the same millisecond — and the keepalive waited behind it
  too, so a congested session could be timed out as a dead one. Producers now hand frames to a
  writer thread through **two FIFO queues**, and it drains control first. `CTRL`, `WINDOW`, `RST` and
  `KEEPALIVE` may go ahead; `DATA`, `OPEN`, `CLOSE` and any type a later build adds keep their place.
  Two FIFOs rather than a priority queue, because order within a class has to hold — control messages
  refer to each other — and a priority queue does not order equal priorities.
  - **`CLOSE` is deliberately not prioritised**, and it is the one that looks like it should be. A
    receiver drops payloads for a stream once the peer has closed it, so a `CLOSE` that overtook data
    already sent would silently truncate the stream: a short response that only appears under load.
    `WINDOW` is safe because credit deltas are additive, `RST` because discarding what is queued is
    what `RST` means, and `OPEN` stays with data so it cannot arrive after its own stream's frames.
  - The data queue is **bounded in bytes and blocks its producer**, which is the backpressure stream
    credits already applied; it is a handoff, not a second window. The control queue is bounded by
    count and a session that fills it is treated as gone, because blocking a control producer would
    reintroduce the problem — one of them is the reader thread.
  - **What the priority left behind measures in tens of milliseconds.** After it landed an
    ordinary visitor still waited 12 to 17 s while 400 stalled readers were served, and the node's
    one socket write was blocking for 3.2 s. That read as the connection itself being full -- a
    queue with nothing in front of it is still a queue -- and three designs were priced against it:
    a connection-level window, smaller data frames under congestion, keeping control off
    connections carrying bulk. None of them touched the cause. The write blocked because the
    *machine* had no network memory left: the harness's 8 MB bodies had autotuned every socket in
    the chain to megabytes, 400 chains put 660 to 680 MB in kernel socket buffers with the pool's
    cluster classes at their caps, and the machine's sockets then froze -- the hub's writes to
    visitors, the node's write to the hub, the harness's own ramp -- while both processes' timers
    reported idle, because they were. At that occupancy it froze in two of four runs and not the
    other two, on the same binaries, which is what made it look like a code change. The same 400
    streams through the same multiplexer with the kernel at 454 MB show the node's writer, the one
    carrying the bulk, at a worst queue wait of 22 ms and a worst socket write of 16 ms over 81,000
    frames, and the ordinary visitor served in 13 to 45 ms (§14). That pair is the multiplexer's
    whole head-of-line cost with 400 stalled streams behind one socket. The connection-level window
    stays not done, for the reason above and now for this one too: what it would have bounded was
    never the thing that was full. What was bounded instead is the kernel's share, on the node
    (§9.3).
- **A window overrun costs the stream, not the session.** A peer that sends past its granted window
  gets that stream RST; the session survives, because it is every other visitor on that node. Eight
  of them and the peer is not honouring flow control at all, and the session goes.
- **Stream ids.** The hub opens even ids, the node odd ones, 0 is control. The node opens none today;
  the parity rule is enforced on receipt so a peer cannot claim ids that are not its to allocate.
- **Multiple connections per node.** One connection for every stream means head-of-line blocking on
  loss and a ceiling of one TCP flow's throughput, so a node may open N connections, default 1 and up
  to 4. Each is a complete Noise channel announcing its index in `Hello{conn}`, and the hub treats
  connections sharing a MachineKey as one **group**. Stream 0 exists only on connection 0, a visitor
  stream goes to the least loaded connection, and stream ids are globally disambiguated as
  `(conn << 24) | localId` so the hub always knows which connection owns a stream. If connection 0
  dies the whole group is torn down and the node reopens.
- A second connection with the same MachineKey and `conn` index wins; the old one gets
  `Goodbye{shutdown}` and its streams are reset. `TCP_NODELAY` is set.

### 5.4 Changing the protocol

A node and a hub are updated separately and by different people, so every wire change has to say
what it does to the pair that is now mismatched. Two numbers carry that. `Message.PROTO` is what
this build speaks and rises with any wire change; `NodeSession.MIN_PROTO` and
`HubLink.MIN_HUB_PROTO` are the oldest each side will talk to, and they move only when talking to
an older peer would be unsafe or impossible. A peer below the floor gets
`Goodbye{upgrade-required}` naming the version it needs, which is the one failure mode here that
explains itself.

**What is compatible.** Adding a field to an existing message: the decoder reads by name and
ignores what it does not recognise, so an older build reads the message as it always did. `Hello`
gained `visitors` that way (§9.3) and is the worked example: a node that does not send it decodes to
0, which the hub reads as "no bound I know of", and re-encoding that Hello produces the same bytes
rather than inventing a field the peer never sent. Both halves are pinned in `WireFormatTest`. Adding a
message type: an unrecognised `"t"` decodes to `Message.Unknown`, which the receiver logs and
answers with `Error{unknown-type}` instead of dropping the channel. Adding a mux frame type: a
frame carries its own length, so one with an unknown type is skipped and the stream stays in sync.
The last two are tolerances in the *receiver*, which is why they had to be in the first release —
they do nothing for a peer that already shipped without them.

**What is not.** Renaming a field, removing one, or changing what it means. A missing required
field throws in the decoder and takes the control connection with it, and the rename is symmetric
in our own code, so nothing in the build catches it: `WireFormatTest` pins one example of every
message type as a literal string for that reason, and it is where a rename should stop. If a
rename is genuinely wanted, the field is added under the new name and the old one kept.

**What can never be compatible** is a check that was missing. Protocol 2's signing rules (§9.2,
§11.1) could not be made to accept a protocol 1 `SignRequest`, because accepting one means signing
something the hub cannot verify — which is the vulnerability, not a compatibility shim. That class
of change moves `MIN_PROTO` and costs every node an upgrade, and is the reason the floor exists.

**Two strings never change**: the Noise prologue and the HTTP upgrade token, both
`jailscale-control-v1`. They are mixed into the handshake hash, so a peer that disagrees fails the
handshake with nothing to read; evolution belongs in the `proto` number, where the mismatch can be
explained in a sentence the operator sees.

---

## 6. Control API and hub state

### 6.1 Messages

JSON on **stream 0**, each `{"t": "<type>", ...}`.

| Message | Role |
|---|---|
| `Hello` / `HelloResponse` | Version negotiation: `proto`, `version`, `os`, `conn`, and `host`, the name the node resolved to reach the hub or null when it was handed an address (§7.2); the reply adds `minProto` and `dnsSuffix` |
| `Goodbye` | `upgrade-required`, `revoked`, `shutdown`, `draining`, plus an optional human `detail` |
| `RegisterRequest` / `RegisterResponse` | hostname, os, self-chosen user, and one of `invite` / `code` / `authKey` or none to knock. Reply is `approved{nodeId, user}`, `pending` or `rejected{reason}` |
| `CertUpdate` | Wildcard chain (public part) and its `keyId`, on connect and on renewal |
| `LinkOpen` / `LinkOpened` | `kind: https\|tcp\|udp`, optional name, domain, port, local target, and for user domains the certificate chain. Reply carries `linkId` and a URL or hub port, or a reason |
| `LinkClose` / `LinkRevoked` | Stop serving, ownership surviving / this node no longer serves that name, domain or port (§11.4) |
| `SignRequest` / `SignResponse` | `streamId`, `keyId`, `alg`, `content`, `serverHello`, `encryptedExtensions`, optional `helloRetryRequest`; then a signature or a reason (§9.2) |
| `ChallengeSet` / `ChallengeClear` | Register or drop a user-domain http-01 token (§8.3) |
| `InviteCreate` / `InviteCreated`, `AdminLinkRequest` / `AdminLink` | A member node issuing an invite; a one-shot `/admin` login URL for an admin node |
| `HubKeyRotation`, `Ping` / `Pong`, `Ack` / `Error` | §5.2; on-demand round trip; generic replies |

**Versioning.** `proto` versions the message schema and the frame set together, and the hub accepts
`minProto` and above. Below that it answers `Goodbye{upgrade-required}` **as the handshake reply**,
so the node never sees a `HelloResponse` and cannot learn `minProto` or the hub version from it.
`detail` therefore carries the required protocol number, the hub version and what to do next; the
node prints it verbatim, keeps it in `status` as `lastError`, and stops reconnecting, because a
one-word reason in a log leaves the user with nothing to act on. The check runs the other way too:
a node needs the hub to speak at least its own minimum, and a `HelloResponse` announcing less makes
the node stop with the same kind of message, naming the hub's version and asking for `jailhub` to
be updated, because there is no older encoding for it to drop to. The prologue number changes only
when the Noise parameters change.

`proto` is **1**, and `minProto` is 1 with it. The number moves when a message gains a field the
hub needs in order to check the request at all; a signing request without the node's ServerHello and
EncryptedExtensions, a domain claim without its proof of key possession or an http-01 challenge
without its domain would each have to be refused rather than accepted unchecked, so a node speaking
an older version is told to upgrade.

### 6.2 Storage

An append-only JSON Lines event log plus in-memory state, replayed at startup. Events are fsynced and
snapshots are renamed into place. `jailhub serve` is the only writer; admin commands ask the running
server over IPC.

```
$JAILHUB_STATE/            (default /var/lib/jailhub, else ~/.local/share/jailhub)
├── hub.key                hub static private key (0600); hub.key.next during a rotation
├── state.jsonl            event log (node-registered, name-claimed, invite-created, ...)
├── state.snapshot         periodic snapshot (log compaction)
├── jailhub.lock           process lock; a second `jailhub serve` fails immediately
├── jailhub.sock           admin IPC socket (§6.3)
└── tls/                   account.key, wildcard.key, wildcard.pem, wildcard.key.prev (0600)
```

The snapshot carries a format version `v`, and the hub **refuses to start** when it is higher than
the version it understands. Adding fields or events within a version is compatible both ways and
unknown events are skipped with a warning, so a rollback is safe in that range; `v` is bumped only
for changes that would make an older binary *misread existing data*. A hub that cannot read its state
should stop rather than come up holding part of it. In memory the state is plain maps (nodes, names,
domains, ports, credential hashes, admins, the pending queue, undelivered notices), which is the
simplest thing that works up to thousands of names.

### 6.3 Admin IPC, the status page, and the admin web

Admin commands are separate processes and the state is in memory, so they talk to the running server
over an AF_UNIX socket at `$JAILHUB_STATE/jailhub.sock`, mode 0600, exchanging line-delimited JSON
through the `proto` codec. **The socket file permission is the authorisation.** Settings that change
at run time (invite policy, registration mode, knocking) live in the store, and `serve` flags only
seed them on first start.

`/admin` exists because an approval queue that can only be drained from a shell on the hub violates
the usability principle. There is no password and no IdP: **an admin node's MachineKey is the
identity**. `jailscale admin` asks for an `AdminLink` over stream 0, the hub returns a 60-second
one-shot URL, and the CLI opens a browser; the visit sets a `__Host-` prefixed session cookie
(`HttpOnly; Secure; SameSite=Lax`, 12 hours), and `jailhub admin login-link` covers the case with no
node available. The pages approve or deny the queue, manage nodes, names and domains, issue invites
and auth-keys, and toggle the three settings, as server-rendered HTML with no JavaScript, no template
engine, and a session-bound CSRF token on every form.

The hub's own page at `/` is the same machinery seen from the other side. It states what the hub is,
how to join *this* hub (read from the stored registration setting rather than assumed), and how it
is doing: version, uptime, nodes online against nodes registered, links open, whether a certificate
is loaded, and resident memory. Those are properties of the service, so they are public. The node
list, the addresses nodes connect from, and the controls over them are rendered only when the
request carries a current admin session, and the rights are re-checked on that request rather than
trusted from the cookie. Resident set size is read from `/proc/self/status` where it exists and
omitted elsewhere rather than guessed at, because a native image's heap is a small part of what it
occupies.

The page is one column, 48rem. It was 40rem, and what was wrong there was not the margins but the
measure: a 64-character binary hash ran to the edge of its cell and a two-word label wrapped onto two
lines. Both fit on one line now, and the rows are full-width with a hairline between them rather than
a table boxed inside a narrower one. Section headings are small, muted and uppercase, because on this
page they separate blocks rather than being read. The stylesheet is inline and under a kilobyte,
there is no script and no image, and dark is whatever the system asked for, since a toggle would need
somewhere to remember the answer. **Both colours come from the same place**: taking the background
from the `Canvas` keyword while the text colour came from a media query let them disagree, and a
browser that darkens the page on its own -- Chrome's auto dark theme -- then painted dark text on a
dark background.

Two endpoints answer something that is not a person, and they are deliberately not in the same
place. **`GET /v1/status`** is liveness on the hub's own name: `ok`, the hostname, the version,
uptime, and when the certificate expires -- the last being the one that takes every name down at
once and the one worth alerting on. That is the whole list, and it is public because an uptime check
has no credential to offer and a name that has stopped answering was never a secret. Fields may be
added, so a monitor that reads the ones it knows keeps working (§5.4).

**`GET /metrics`** is the Prometheus text format, which needs no library to produce, and it is **not
on 443 at all**. It has a listener of its own -- plain HTTP, `--metrics-listen 127.0.0.1:9090` by
default, `none` to turn it off -- and nothing else is served there: counters for visitors routed and
refused, signatures issued and refused, control sessions and relayed bytes, gauges for what the hub
is carrying, and the stage and mux timings below. **Where it listens is the authorisation**, exactly
as the file mode is for the admin socket next door. This hub has no inside to be on -- its name is
the public internet by construction -- so a credential checked on 443 would be one more secret to
issue, rotate and get wrong, and not listening there is the shorter answer. etcd's
`--listen-metrics-urls`, Spring Boot's management port and headscale's `metrics_listen_addr` are the
same move. A scraper somewhere else reaches this through a tunnel or a proxy that can say who is
asking, which a bare port cannot. The old path on the hub's name answers 404 and names the flag,
because an operator who upgrades and loses their dashboard should not have to read the source to
find out where it went.

It was public on 443 until it was not, and `/v1/status` carried the same counters in JSON beside it
-- build digest, hub key, nodes registered and online, links open, relayed bytes, the receive budget,
resident size. Two things were wrong with that. Every one of those is a fact about what the hub is
*carrying*, which is a different question from whether it is *up*, so the health check a load
balancer polls had quietly become a second copy of the scrape. And a stranger had the throughput of
everything behind the hub for the asking: no name and no address appear, but on a hub serving one
node the byte counters *are* that node's traffic, and anonymity that holds only while the hub is
busy is not a property, it is a coincidence.

**No metric names anything.** Not a link, not a node, not an address -- a scrape says how much the
hub is doing and never who is doing it, and the test asserts that no line carries a label except
`jailhub_build_info`, which is about the binary. That is the line that would be easy to cross: one
label per name and the metrics become the directory the admin page deliberately is not. Counting
lives in `Metrics`, six `LongAdder`s written from every visitor thread and read once a scrape, and
the signature counter sits at the one point that decides, so a refusal added later cannot forget to
be counted.

It lists the open links as well -- the address a visitor would type and whether it is https, tcp or
udp -- because a hub that serves nothing and a hub that is busy look identical without it. The count
that used to sit in the status table is gone with it: the list is the count, and saying both invited
them to disagree. Those
addresses are public by construction: a visitor reaches one by typing it, and a DNS lookup finds it
either way. What stays behind the admin session is the part that is nobody else's business -- who
opened a name and which local port it reaches -- and the list stops at fifty rows and says how many
are left, so a busy hub does not turn its front page into a directory dump.

It also names the build and the key it is running: the SHA-256 of the executable the kernel has
mapped, taken from `/proc/self/exe` where that exists and the command otherwise, and the hub's
current Noise public key, plus the next one while a rotation is open (§5.2). Both are comparable
with something the reader already holds -- the release's `SHA256SUMS.txt`, and the key the node
pinned at `up`, which `jailscale status` prints -- and neither is evidence against a dishonest hub,
which writes this page and can put anything on it (§11.2). What they catch is an operator running a
build they did not mean to, and a key that changed without the rotation they expected. The page says
so in those words rather than presenting them as an assurance. The digest is computed once, on the
first request that needs it, so a hub nobody looks at never reads its own 26 MiB; only a native
image is hashed, since under a JAR the executable is the JVM and its digest answers a different
question. Printing the key gives nothing away: `/v1/key` already serves it unauthenticated, because
a joining node has to fetch it before it can trust anything.

---

## 7. Certificates and ACME

### 7.1 One wildcard through the hub's own DNS

**Certificates are not issued per name.** Let's Encrypt allows 50 new certificates per registered
domain per week; with a UX that mints a fresh random name on every `open` that is gone in a day, and
each new name would stall for the seconds an ACME round trip takes. One wildcard means issuance twice
a month and a new name that opens in zero seconds.

A wildcard needs dns-01, which normally means a DNS provider API token. Instead **the hub is the
authoritative DNS server for the `_acme-challenge` name** (the acme-dns pattern), so the operator
creates three records:

```
hub.example.com.                  A   203.0.113.10     (direct, no proxy; Cloudflare must be DNS-only)
*.hub.example.com.                A   203.0.113.10
_acme-challenge.hub.example.com.  NS  hub.example.com. (NS target is outside the delegated zone, so no glue)
```

The CA follows the delegation to the hub's port 53, and this one name validates both SANs. Add a
firewall opening for TCP 443 and UDP/TCP 53, optionally TCP 80 and the raw port range, and the
operator setup is complete. First run is `jailhub serve --base-url https://hub.example.com`, which
prints the first invite link (§10).

### 7.2 Issuance and renewal

A still-fresh wildcard in `$JAILHUB_STATE/tls/` is installed at once and 443 opens immediately.
Otherwise the hub starts the port 53 responder (TXT, NS and SOA for `_acme-challenge.<hub>`, REFUSED
for everything else, UDP and TCP), runs the self-check, then issues. The **self-check** must pass
first and retries every 60 seconds on failure: it sets a random TXT value and asks 1.1.1.1 and
8.8.8.8 for it, which separates a missing NS delegation from a blocked port 53 from a cached answer.
`--no-selfcheck` skips it where hairpinning does not work; it does not touch the address check
below, which holds nothing up and so needs no escape hatch of the same kind.

Issuance creates an EC P-256 account key if absent, orders both names, publishes each dns-01 token as
`base64url(SHA-256(keyAuthorization))` in a TXT record, polls the authorizations, generates a new EC
P-256 certificate key, hand-encodes the PKCS#10 CSR, finalizes, downloads the chain, writes it
through temporary files, opens 443 and pushes the chain to every connected node with `CertUpdate`.
Renewal is checked daily and runs when less than a third of the lifetime is left; the previous key
stays usable for 24 hours so in-flight handshakes complete.

Details that had to be written by hand: the JDK's `SHA256withECDSA` produces DER while JWS wants the
raw 64-byte `R||S`, and without that conversion the CA rejects every request; and the JDK has no
public PKCS#10 API, so a small DER writer builds the `CertificationRequestInfo` with both SANs and
signs it. The certificate is **ECDSA** so that the delegated private-key operation is exactly one
signature, since RSA key exchange would need a decryption (§9.2). Scope is ACME v2 and dns-01 only,
with no External Account Binding; `--tls-cert/--tls-key` covers internal CAs and hosts that cannot
open 53, and that certificate must also be ECDSA with the wildcard SAN. On Linux, 443 and 53 need
root or `CAP_NET_BIND_SERVICE`, which the reference systemd unit grants to a dedicated user through
`AmbientCapabilities`.

**The address check.** The self-check above proves the `_acme-challenge` delegation reaches this
process and says nothing about the address records every visitor actually follows, so a hub started
with ACME, unless `--no-address-check` says otherwise, also asks once in the background: do public
resolvers have an address (A or AAAA) for `hub.example.com` and for a name under
`*.hub.example.com`, do those two share one, and does that address answer `/v1/key` on the base
URL's port with **this process's** hub key? The last question needs no PKI — the hub key is what a
node pins, so an address returning a different one is a different hub whatever certificate it
presents — and the middle one is the case where only the wildcard is proxied, where the hub's own
name and the names it serves arrive in different places. "Share one" rather than "are equal" because
the two lookups are not equally fresh: the hub's name is one resolvers have cached, the wildcard
probe is a label nobody has ever asked for, so mid-change the apex can still carry the old address
next to the new one and that is propagation, not a fault.

It can fail to answer, and that is not an alarm. Reaching your own public address from the host
behind it is something many networks do not allow, a cloud instance with a translated address
typically among them, so a connection that **does not complete** is reported as inconclusive and
never as a fault. A connection that completes and finds something that is not a hub — a 403 page, an
HTML index — is the opposite: that is the TLS-terminating proxy the trap below says cannot sit in
front, and it is reported as the fault it is. From outside, a node adds one more view: `Hello`
carries the name the node resolved to get here (null when it was given an address with `--hub-addr`
and never asked DNS), and a handshake that completed against the pinned hub key proves that name led
*that node's resolver* here. The hub counts it only when the node arrived from a public address — a
node on the hub's own host or LAN may have the name from `/etc/hosts` or a split-horizon resolver,
which says nothing about what the world is told — and only for its own name, compared against what
it already knows rather than stored from the wire.

Two operational traps. SNI passthrough needs raw TCP 443, so **no TLS-terminating HTTP proxy can sit
in front** (nginx `http`, Caddy, Cloudflare Proxied); a layer-4 proxy that only copies bytes is
supported (§8.5). And a node started with `--ca-file` keeps that path in its state, so it will not
recover on its own if the hub later serves a certificate from a different CA; re-running
`jailscale up --hub <name>` without the flag clears it, which is the usual snag moving from ACME
staging to production.

---

## 8. Public ingress

### 8.1 SNI router

A single `ServerSocket` accepts on 443. Without opening TLS the router reads the ClientHello
(5-second timeout), parses the SNI in about 100 lines, and branches.

| SNI | Handling |
|---|---|
| `hub.example.com` | Handed to the hub's own `SSLServerSocket`: control channel, `/join`, `/admin`, `/v1/*` |
| `<name>.hub.example.com`, active | Open an `OPEN` stream on the owning node and replay the ClientHello bytes already read |
| `<name>.hub.example.com`, claimed but offline | Wait up to 3 s for the node to return (hand-off, restarts), then serve a short "not open" page under the wildcard certificate, which the hub can do because it holds the key |
| A registered user domain | Stream to the owning node with `keyId = domain:<domain>`. The hub has no key for it |
| Anything else, or no SNI | Closed immediately |

After that the hub copies bytes both ways and looks at neither TLS records nor HTTP; a visitor half
close becomes `CLOSE` and an error becomes `RST`. What the hub can see is the SNI, the visitor IP,
byte counts and timing, not the content. Because neither end parses HTTP, any TLS client that sends
SNI reaches a name, so `psql "sslmode=require host=db.hub.example.com"`, MQTT over TLS and gRPC work
as they are; only clients that cannot speak TLS need the raw ports of §8.4.

**Limits.** 64 concurrent connections per visitor IP, 1,024 per name (`SniRouter.MAX_PER_NAME`),
5 seconds to produce a ClientHello, listen backlog 1,024 capped by `somaxconn`; SYN flood defence is
the kernel's job. Loopback is exempt from the per-IP limit, because behind a local proxy without
PROXY protocol every visitor folds into one address, and while `--proxy-protocol` (§8.5) is the right
answer there this exemption is the safety net.

**Visitors that never close.** Both directions are half closes, so the hub would wait for a visitor
under no obligation to close its own half. A 10-second timer therefore starts **when the node closes
its side**, and because the clock only starts then, streams meant to stay open (WebSocket, SSE, long
downloads) never reach it. Without it a socket, its reader thread and a half-open stream would be
pinned indefinitely.

### 8.2 Names

Format is `<name>.hub.example.com`: lower-case letters, digits and hyphens, up to 40 characters, not
starting or ending with a hyphen, with reserved labels (`hub`, `admin`, `www`, `api`, `ns`,
`_acme-challenge`, `join` and others) refused. `jailscale open 3000` gets a five-character random
name from a 30-character alphabet with look-alikes removed, and the same node reopening the same
local target gets the same name back, so the URL survives restarts. `--name myapp` binds the name to
the first requester's *user*, so that user's other nodes may use it while another user gets `taken`,
and an admin moves it with `name reassign`. A name routes only while the node holds the link open and
is connected; otherwise it stays claimed and visitors see the "not open" page. Opening a name costs
one `LinkOpen` round trip because the wildcard already covers it, and a node may hold at most 20 name
and domain links.

### 8.3 User domains

`jailscale open 3000 --domain myapp.com` publishes a domain the user owns, pointed at the hub with a
CNAME or A record. When the node has no certificate for it, or renewal is due, the node runs ACME
**http-01 with its own key**: since DNS points at the hub, the CA's
`http://myapp.com/.well-known/acme-challenge/...` request arrives on the hub's port 80, the node
uploads `ChallengeSet{domain, token, keyAuthorization}` (at most 10 per node, 10 minutes each), the
hub answers on its behalf, and `ChallengeClear` removes it. The hub learns the token and the response
string and nothing about the node's key.

**The relay is lending out domain validation, so it is lent narrowly.** The hub owns port 80 for
every name that resolves to it, which is every user domain any member has pointed here and every name
under the hub's own. A token is therefore stored against the domain it was issued for and answered
only when the request's `Host` is that domain; a token for `<hub>` or anything under it is refused
outright, and a domain another user already holds is refused too. Answering any token under any Host
would let one member pass validation for another member's domain, or for the hub's own name — the
origin that serves `/admin`, `/join` and the first-contact key — and walk away with a publicly trusted
certificate for it.

Then comes `LinkOpen{domain, chainPem, domainProof}`. **The chain says which certificate; the proof
says the node holds its key.** A chain is public — it is handed to every visitor in the clear and
mirrored in CT logs — so presenting one shows only that the presenter has seen the site. The key is
what the CA bound to the domain, so the key is what answers: `domainProof` is a signature by the
leaf's private key over `"jailscale domain claim v1" || handshakeHash || domain`, where
`handshakeHash` is the Noise handshake hash of the connection carrying the claim. Both ends derive it
and nobody else can, so the proof is good for that claim on that connection only, and no round trip
is needed to agree a nonce. The hub binds the domain when the chain validates against public roots,
its SAN is that domain, and the proof verifies against the leaf's public key — rejecting otherwise
with `domain-unverified`, `domain-cert-name-mismatch`, `domain-cert-untrusted`,
`domain-proof-missing`, `domain-proof-invalid`, or `bad-domain` for a name under the hub's own domain.

A domain already held by **another user** is `taken`, the same rule as a name (§8.2): the operator
releases it with `domain release` and the new owner claims it then. Between machines of the same user
the newest claim wins, as names do. After that it is pure SNI passthrough: certificate and key exist
only on the node, the hub forwards ciphertext, and there is no `SignRequest`. The node renews on the
same third-of-lifetime rule, checked hourly, and an offline node does not renew. **Port 80 on the hub
is a precondition**; `--http-listen none` means user domains are refused.

### 8.4 Raw TCP and UDP ports

Clients that do not speak TLS (SSH, game servers, plaintext databases, DNS, WireGuard) send no SNI
and cannot be told apart by name, so the hub assigns **a port instead of a name**, the same shape as
ngrok's tcp mode or frp's tcp and udp types.

```
$ jailscale open 22 --tcp      ->  tcp://hub.example.com:10042  ->  127.0.0.1:22
$ jailscale open 51820 --udp   ->  udp://hub.example.com:10043  ->  127.0.0.1:51820
$ jailscale open 22 --tcp --port 10022      # request a specific port in the range
```

The range is `--port-range 10000-10999` by default, or `none` to disable; it must be open for both
TCP and UDP, its size is the ceiling on concurrent raw links, and an assignment is remembered per
node, kind and local target. Ports outside the range are not offered, because the hub's low ports are
the hub's. TCP opens a `ServerSocket` and one stream per visitor connection, with no SNI parsing and
no TLS. UDP opens a `DatagramChannel`, gives each new visitor address a `DGRAM` stream, turns every
later datagram from that address into one DATA frame, and drops an address idle for 60 seconds, with
the node making one local UDP socket per stream; the size ceiling is the 16 KB frame cap, and
ordering and delivery are stronger than UDP semantics promise, never weaker, because the carrier is
TCP.

**Where the plaintext is.** Visitor to hub is exactly what the client sent and hub to node is still
Noise-encrypted, so plaintext exists **only inside the hub process**, and only for apps that do not
encrypt themselves. SSH, WireGuard and a TLS-enabled database are effectively end to end because the
hub sees only the app's ciphertext; plaintext protocols are visible to the hub. This cannot be fixed
without the visitor's client cooperating, and it is the same for ngrok and frp, so `open --tcp/--udp`
says so in its output. A client that can speak TLS should use the 443 path.

### 8.5 Behind a TCP proxy, and PROXY protocol

An operator whose server already runs nginx or HAProxy on 443 can put the hub behind it, provided the
proxy **forwards TCP bytes without opening TLS**; reference configs are in `deploy/nginx-stream.conf`
and `deploy/haproxy.cfg`, including an `ssl_preread` example that routes only the hub's names to it.
The hub then runs as `--listen 127.0.0.1:8443 --proxy-protocol` and reads a PROXY v1 or v2 header at
the start of each connection to learn the visitor address. Because the header is only trustworthy
from a trusted proxy, `--proxy-protocol` is accepted only when `--listen` is on loopback or
`--trusted-proxy <cidr>` is given, and connections from untrusted peers are refused outright;
otherwise anyone could forge a visitor address. The parser takes v1 text and v2 binary (IPv4, IPv6,
LOCAL), and v1 addresses must be **literals**, because allowing hostnames would put a DNS lookup on
the accept path where an attacker could stall the hub (fuzzing found that one). A hub with
`--proxy-protocol` on rejects header-less connections, so the node's control connection must also
come through the proxy, and the address derived from the header is what the rate limits, the knock
queue and the session logs use, so nodes behind one proxy are not collapsed into one address.

---

## 9. The node

### 9.1 Publishing

```sh
$ jailscale open 3000                      # https://q7x2k.hub.example.com -> 127.0.0.1:3000
$ jailscale open 3000 --name myapp         # chosen name
$ jailscale open 3000 --gate               # visitor gate; prints a visit link too (§9.3)
$ jailscale open 3000 --domain myapp.com   # user domain (§8.3)
$ jailscale open 22 --tcp                  # raw TCP, hub assigns a port (§8.4)
$ jailscale open 8080 --host 192.168.1.20  # another machine on the same LAN
$ jailscale ls ; jailscale close q7x2k
```

The daemon remembers open links and reopens them with the same name or port after a reboot.

### 9.2 TLS termination with hub-side signing

A visitor stream is a byte stream, not a socket, so `SSLSocket` cannot be layered on it. The node
drives an `SSLEngine` directly: stream to `unwrap` to plaintext to the local socket, and back.

```
visitor ──ClientHello──> hub ──OPEN + bytes──> node (SSLEngine)
                                                  │  CertificateVerify content c
                                                  ├──SignRequest{streamId, keyId, alg, c}──> hub
                                                  │                          checked, then signed
                                                  <──SignResponse{streamId, sig}─────────────┘
                                                  │  ServerHello ... CertificateVerify(sig) ... Finished
visitor <──────────────── hub <──bytes──────────  node
```

The `SSLContext` is built from the chain the hub sent in `CertUpdate` and an **opaque `PrivateKey`**
holding no bytes, only a `keyId`. A small JCE provider offers `Signature.SHA256withECDSA` for that
key type, and JSSE's delayed provider selection picks it, the mechanism PKCS#11 keys rely on.
`engineSign()` sends a `SignRequest` on stream 0 and blocks for the reply, which costs nothing on a
virtual thread. The service is registered by subclassing `Provider.Service` and overriding
`newInstance`, so no reflection is involved.

**The conditions that narrow the signing oracle.** Signing unconditionally would give every member
node an oracle for the whole wildcard, and anyone able to spoof a visitor's DNS could then impersonate
someone else's name. So the hub signs only when all of these hold:

1. `SignRequest` carries **what is to be signed, not its hash**, and those bytes are a TLS 1.3 server
   `CertificateVerify` content: the 64 spaces, the `TLS 1.3, server CertificateVerify` label and the
   zero byte of RFC 8446 §4.4.3, followed by a transcript hash. The hub hashes them itself. A bare
   digest cannot be checked against anything, so a hub that signed one would sign whatever 32 bytes
   it was handed, for any purpose at all.
2. `streamId` names **a stream this hub opened on this connection**, still open.
3. The `sni` recorded in that stream's `OPEN` maps to a name currently **assigned to this node**.
4. **The transcript hash is that stream's handshake.** The hub keeps the ClientHello it delivered on
   the stream (both of them, around a HelloRetryRequest); the request carries the node's ServerHello
   and EncryptedExtensions; the Certificate message is the hub's own chain. The hub hashes
   `ClientHello || ServerHello || EncryptedExtensions || Certificate` (with the `message_hash` rule
   of RFC 8446 §4.4.1 after a retry) and signs only if that is the hash the content ends in. A
   handshake the node is running for some other visitor, one whose ClientHello never came through
   this hub on this stream, hashes to something else and is refused as `transcript-mismatch`.
5. That stream has used fewer than 4 signatures. A normal TLS 1.3 handshake uses one, and two covers
   HelloRetryRequest.
6. The node is within its signing rate: a token bucket of 2,000 with 1,000 per second sustained,
   sized from a load test where 1,000 visitors handshake at once. Resumption needs no signature.

**Where the node gets the messages from.** JSSE asks for the signature before it has written a byte
of its flight, and shows neither its ServerHello nor its EncryptedExtensions, so the node rebuilds
them (`Transcript`). The ClientHello and any HelloRetryRequest are plaintext, taken off the wire by
`TlsEndpoint`. The Certificate is the chain. The EncryptedExtensions are a function of the ClientHello
and a fixed server configuration: one key-exchange group (X25519; a client whose key share is for
something else gets a retry) and one ALPN protocol. The ServerHello has two unknowns, its random and
the X25519 key share, and both come out of the `SecureRandom` the node hands the `SSLContext`, which
records what it draws for the handshake thread; the public key is recomputed from the recorded
scalar, the cipher suite is on the handshake session, the session id is the client's echoed. The
node checks its reconstruction against the hash JSSE handed it **before** sending anything, so a JDK
that writes these messages differently fails the handshake locally with a clear reason, and
`TranscriptTest` runs the reconstruction against JSSE itself, retry included, so such a JDK fails the
build first. The hub trusts none of this: it recomputes from its own copy of the ClientHello.

**What this binds.** Conditions 2 and 3 bind the *request* to a stream the hub delivered for a name
the node owns; condition 1 binds the *content* to being a TLS 1.3 server handshake; condition 4 binds
that handshake to the visitor on that stream. A member node that separately obtains a network or DNS
position in front of another name under the hub can drive a handshake with that visitor, but the
hub never delivered that visitor's ClientHello to it, so no request it can make hashes to what that
handshake needs signed. Each of the hub's names is therefore impersonable only by the node that
owns it, which was the claim §11.1 makes.

**Keeping it to one signature.** Visitors are offered TLS 1.3 only: condition 1 means the hub signs
nothing but a TLS 1.3 server `CertificateVerify`, and TLS 1.2 ECDHE would ask it to sign a
`ServerKeyExchange` instead. The certificate is ECDSA P-256, so the private-key operation is a
single signature and RSA key exchange is excluded by the key type. Session
tickets are generated by the node and kept in memory, so a resumed handshake never touches the hub.
0-RTT is off, and ALPN offers only `http/1.1`, because negotiating h2 would break a local app that
speaks h1. `CertUpdate` carries a `keyId` (a certificate fingerprint) that the node echoes in
`SignRequest`, and the hub keeps the previous key for 24 hours so a handshake begun just before a
renewal still completes. Each first handshake from a visitor adds one node-to-hub round trip, the
same cost Cloudflare Keyless SSL pays. A user-domain stream arrives with `keyId = domain:<domain>`
and is terminated with the node's own real key, with no hub involvement.

### 9.3 Relaying and the visitor gate

Once TLS is off the node **copies bytes**: visitor plaintext to `127.0.0.1:<port>` and local
responses back, so HTTP/1.1 keep-alive, chunked bodies, WebSocket upgrades and SSE all pass through
because the local app handles them. `open --proxy-protocol` prepends a PROXY v1 line so the local app
learns the visitor address, using the `visitorAddr` and `visitorPort` the hub put in the stream
metadata, and raw TCP links behave the same way. A refused or reset local connection is retried five
times with 50 ms doubling (about 1.5 s) before the visitor gets a 502 page, because a burst of
visitors really does overflow a small listen backlog (macOS defaults to 128) and it surfaces as an
immediate refusal. That page and the gate are the only two places where the node *writes* HTTP, and
only on https links.

**The node serves at most `Visitors.MAX_IN_FLIGHT` visitor streams at once, and resets the rest.**
What a visitor costs the node is its TLS state — about 99 KB live (§15) — and that is the same
whether the visitor reads what it asked for or stalls, so the bound is a count where the hub's is a
byte budget (§5.3). The hub bounds bytes because there a thousand well-behaved visitors hold almost
nothing and a count would have to assume the worst case for all of them; here the count *is* the
resource. It is derived at startup from the heap the process was given — 450 at the shipped 64 MiB
ceiling, linear above it — so raising the ceiling with `-XX:MaxHeapSize=` through
`JAILSCALE_DAEMON_OPTS` (§14) buys visitors rather than leaving a node with a number that suited a
smaller heap. Over the bound the stream is reset with `RST_NO_CAPACITY` before the handshake, since
what is being conserved is the state the handshake would create; the node logs at most one line a
minute saying it is at its ceiling, and `jailscale status` reports `visitorCeiling` and
`visitorsRefused` beside `visitorsInFlight`.

**450 was measured, not chosen, and the alternative it is measured against is not a healthy node.**
Against an unbounded node on darwin-arm64 at the shipped ceiling: 400, 450, 500 and 550 stalled
readers all live, peaking at 82.1 to 98.5 MB of RSS and climbing about 99 KB a visitor; **600 dies**,
admitting 550 of them, and 1,000 dies admitting 817, with six `OutOfMemoryError`s that took
`mux-reader` and `mux-writer` with them, dropped the hub connection and every visitor on it, and
left an ordinary visitor timing out at 30 s fourteen probes running. The bound is below the cliff
rather than at it because whether the heap is exhausted depends on arrival rate as well as count —
`FlowBudget`'s own figures show the same axis behaving differently at three ramp speeds — and
because the budget gate measures at a count that has to stay admissible (§14). With the bound, the
same thousand hold 450, refuse the rest, peak at 86.2 to 86.8 MB across three runs, and serve an
ordinary visitor in 1 to 36 ms.

**What it costs is what `FlowBudget` warns about: refusing hands an attacker a cheaper denial than
the one being fixed.** Someone who holds `MAX_IN_FLIGHT` connections open keeps everyone else out.
The hub avoids that by reclaiming instead — it can pick a stream that has provably not consumed a
byte in `STALL_MS`, so it frees memory from a connection that is not using it. Nothing on the node
is idle in that sense: a visitor's TLS state is live for as long as the visitor is, so reclaiming
here means choosing a victim among connections that are all making progress. Refusing the
thousand-and-first visitor costs that visitor; not refusing it costs all of them and the hub link
besides, which is what the measurements above are of. The hub already caps a name at
`SniRouter.MAX_PER_NAME` = 1,024 on the same reasoning.

**The node tells the hub this number, and the hub admits against it.** It rides on `Hello`
(§5.4), and `SniRouter` checks it beside its own two caps, so a visitor a full node cannot take is
turned away before a stream is opened rather than after the node resets it -- 567 such resets in the
measured thousand-visitor run became none. The node's own bound stays exactly where it is and always
will: an old hub does not send the number, a hub and a node are upgraded separately, and there is a
race between the hub's check and the open. The way to tell the hub is really doing the refusing is
that the node's `visitorsRefused` stays at zero, which is what `measure.sh` prints and what
`NodeCapacityTest` asserts.

**The socket to the local app is given the stream window, 256 KB each way, before it connects.**
Left to the kernel both buffers autotune to megabytes -- measured at up to 8 MB on macOS, whose
default ceiling is 4 MB a side; Linux allows 6 -- and what they hold is bytes the visitor has not
read: a stalled download stops its stream at the window of credit (§5.3), the relay stops taking
from the app, and everything the app can still push lands in the kernel on the node's machine,
outside any number the node reports. With 400 stalled visitors on loopback those sockets held 300 to
400 MB, a megabyte each, while the machine's network memory sat at its cap and every socket on it
froze (§14). A byte the stream cannot send yet is a byte it should not have taken from the app, so
the kernel is told the window. What the kernel then reports is its own business, and it is not the
same answer twice: macOS doubles what it is told at connect and holds it there, Linux gives the
receive side the window as asked, and the send side comes back smaller wherever
`net.core.wmem_max` sits below it -- 212,992 on the linux-amd64 CI runner. Smaller is the safe
direction, and the clamp does not cost the property this is for, since Linux takes the lock that
ends autotuning before it does the clamping. So the node's share is about half a megabyte a visitor
on macOS and at most the window on Linux -- 240 MB for the same 400, and a figure that stops
growing. What the app puts in its own send buffer is the
app's; `measure.sh`'s app bounds its own. The app is local or on the node's network, where 256 KB is
far past the bandwidth-delay product, and the warm throughput of §14 does not move: 42,500 requests
a second with the buffers given, against about 38,000 recorded, at 83 and 94 µs of hub and node CPU
an operation against 101 and 113. The hub's
visitor-facing sockets are left autotuning on purpose: a visitor a continent away is what the
kernel's pipelining is for (§15).

A link that should not be public is locked behind a visit link, the same capability model as invites.
`jailscale open 3000 --gate` prints `https://q7x2k.hub.example.com/?jail=<token>` alongside the
public URL, and `jailscale gate <name> --ttl 7d` or `--off` manages it afterwards. Each run of the
former issues a fresh link and retires the one before it, so it is not a way to look at the gate.
There is no `--new-link`: it was documented here, declared in the CLI and read by nothing, because
the command has only ever had the one behaviour.
Immediately after TLS termination the node reads only **the first request head** of the connection
(request line and headers, at most 16 KB): a valid `Cookie: jail=<token>` lets the whole connection
through, because the same TCP connection is the same client; a valid `?jail=<token>` query gets
`Set-Cookie: jail=...; Path=/; Secure; HttpOnly; SameSite=Lax` and a 302 to the same path without the
token, then closes; neither one gets a 403 page and a close. Tokens are 128-bit and the node stores
only a SHA-256 hash. The hub knows nothing about gates, because it only sees ciphertext, and keeping
the gate on the node is the position consistent with end-to-end encryption.

**The gate is for https links, and both commands say so.** A raw tcp or udp link has no HTTP in which
to carry a token, so `open --gate` refuses it — and so does `jailscale gate <name>`, which used to
take it: the raw link is named `tcp/<port>` in node state, so the command matched, armed the gate,
saved it, printed a visit link and reported the link as gated, while the raw serving path never looks
at `gateHash`. A control that is on in the status output and absent on the wire is worse than one
that was never offered. The serving path refuses a raw link carrying a gate as well, so state written
by an older build cannot serve a phantom one.

### 9.4 Daemon and CLI

`jailscale` is one binary with two roles. `jailscale daemon`, or a registered service, stays
resident; every other subcommand except `version`, `update` and `service` talks to it over **local
IPC**, an AF_UNIX socket at `$XDG_RUNTIME_DIR/jailscale.sock` or next to the config file (0600),
Windows included, carrying line-delimited JSON with streaming replies for progress output. **Whoever
starts the daemon passes both paths**, `--home` and `--socket`, because those two rules do not give
the same answer to everyone: the CLI resolves the socket from the environment, and a daemon told
only its home would bind the one next to the config file while the CLI waited on the one in
`$XDG_RUNTIME_DIR` -- so on any systemd login session `up` reported that the daemon did not start,
five seconds after starting it, and left it running. One more orphan for every command typed.
`Service.daemonCommand` is the single place that builds that command, so the CLI and an installed
unit cannot drift apart on it.

**One daemon per state directory, enforced by a lock on `daemon.lock`.** Passing both paths settles
what the CLI starts; it does not settle what someone starts by hand, or what an installed unit and a
`jailscale daemon` in a terminal do between them, and two daemons on one directory share a
MachineKey and a state file and connect to the hub as the same node. The daemon takes the lock
before it opens anything and holds it for its lifetime, and a second one exits saying who has it.
The lock is an `fcntl` record lock, so the kernel releases it however the process ends: there is no
stale lock to clear and no pid to test for liveness. The byte locked is past the end of the content,
because a Windows lock is mandatory and locking the bytes themselves would stop a reader.

Holding the lock is also what makes its contents trustworthy, which is why there is no separate
pointer file: the holder writes its pid and **the socket it actually bound**, and a CLI that finds
nothing at the socket its own environment implies reads that file before concluding the daemon is
down. So `jailscale status` from cron, with no `XDG_RUNTIME_DIR`, still finds the daemon a login
session started in `/run/user/<uid>`. The path is used only if something answers there, so a file
left behind by a daemon that has died sends nobody anywhere. Commands
are `up`, `down`, `status`, `open`, `close`, `ls`, `gate`, `invite`, `admin`, `netcheck`, `verify`
(§11.3), `leave`, `update` and `service install|uninstall|status`; service registration uses only
what the OS already has (a launchd agent, a `systemctl --user` unit, or a logon scheduled task) with
no service wrapper.

**`update` reports; `update --download` fetches; neither installs.** The plain form reads the
published release index and prints the version and where to get it, and the daemon does the same
once a day so `status` carries the answer without anyone asking. The check runs in the CLI process,
so it answers while the daemon is down, and a check that could not be made is an error like any
other command's: the reason goes to stderr and the exit status is 1, so a script can tell "up to
date" from "could not tell".

**What `--download` adds is the checking, not the installing.** It works out which asset this build
should run — target from `os.name` and `os.arch`, or `jailscale.jar` when this is not a native image
— and then walks a chain of three links, in this order, every one of them fatal:

1. an Ed25519 signature over **`RELEASE.txt`**, against a compiled-in key;
2. the `sha256sums:` digest in that file against the `SHA256SUMS.txt` actually fetched;
3. that list's hash for exactly the asset, streamed to disk and hashed as it arrives.

The bytes go to a `.part` file beside the final name and are moved into place only once the hash
has matched, so a download that fails leaves nothing behind and touches nothing that was there —
`--dir .` from the directory holding the running jar must not truncate that jar — and there is never
a half-checked binary next to instructions for installing it. The file this process runs from is
refused as a target outright: writing it would be the install this command leaves to the operator.
A release that answers 404 for `RELEASE.txt` is refused *without* the advice to install by hand,
because this build carries a key and only releases newer than it are fetched, so every one of them
was published under signing; a missing signature there is a publishing mistake or a stripped one,
and steering the operator to unchecked bytes would make stripping it a way past the whole check. The parts of doing this by hand that go wrong quietly
are exactly the parts it removes: picking the right target, and `sha256sum --ignore-missing -c`,
which exits 0 for having verified nothing when the file has been renamed — so a name absent from the
list is an error here rather than a download nobody compared with anything.

**`RELEASE.txt` exists because a checksum file does not say which release it is.** It carries a
format line, the `tag:`, and the digest of `SHA256SUMS.txt`, and it is the only thing signed. Sign
the checksum list on its own and the signature is valid for every release, past and future, because
nothing in those bytes distinguishes one from another — so whoever can publish a release could
republish an old, genuinely signed, vulnerable one under a higher version number, and `--download`
would call it verified. The tag inside the signed bytes is what closes that, and it is also what
makes the comparison in `check()` mean anything: until it is verified, the version this announced
came from an unauthenticated `tag_name`. `SHA256SUMS.txt` is left byte for byte as the workflow
wrote it, so `sha256sum -c` still works on it; a `tag:` line inside it would have broken every
reader of the format. Unknown fields in `RELEASE.txt` are ignored and an unknown format line is
refused, which is §5.4's additive rule applied to a file instead of the wire.

**What the maintainer checks before signing, and why it is not the release itself.** The signing
step downloads the draft, and everything in it — the binaries, `SHA256SUMS.txt`, `BUILDINFO.txt` —
is an asset that whoever can write to that release can write. Checking those against each other
proves only that they agree, so an attacker who swaps a binary and the checksum line beside it
passes every such check and the signature goes on their bytes: the guarantee would degrade from
"the pipeline cannot make this signature" to "the maintainer has to be tricked once, during a
window only write-holders can see". The anchor outside the release is the maintainer's own clone,
and `tools/sign-release.sh` makes that a check rather than an assumption: the tag has to be in the
clone already and its commit has to be on the clone's `main`, and a tag that is missing is *not*
answered with "fetch it and retry" — a tag that appeared on the remote without the maintainer is
exactly one that write access could have pushed, and fetching it would import that commit and then
verify the release against it with every check green. The script prints the commits between the
previous release and this one before it asks, and requires every asset to carry build provenance
for *that* commit and that workflow (`gh attestation verify --source-digest --source-ref`) before
it will sign. This is the same Sigstore attestation the
paragraph below says the client must not trust, used where it does work: the client has no anchor
to compare an attested commit against, and the maintainer does. What it leaves is source review —
the attack becomes "get malicious code into the commit the maintainer tagged", which is in the
history rather than invisible in a draft.

**A signature the release pipeline cannot make.** A checksum file published by the account that
published the binaries proves that the download was not corrupted on the way and nothing about who
produced it: whoever could replace the binary could replace the list beside it. So the release
workflow leaves a draft, and `tools/sign-release.sh` — run on a machine that is not the pipeline,
with a key the pipeline cannot reach — downloads every asset, re-hashes it against `SHA256SUMS.txt`,
checks that the key it is about to sign with is the one the tag compiled in, signs that file and
publishes. The public half is compiled into the binary, like `LATEST` and for the same reason
(§11.2). A build that carries no key refuses to download rather than falling back to the checksum
alone; the check that cannot be made is not quietly skipped.

**The key is a list, so that it can be changed.** With one compiled-in key there is no way out of a
key that has to move: every binary in the field accepts that one and nothing else, so publishing
under a new key strands all of them and publishing under a key believed compromised is the only
alternative. Rotation is therefore a two-release move, and it only works if the clients were taught
the next key before it was used — release N ships accepting `{old, new}` and is still signed with
old; release N+1 is signed with new, and the binaries already out there accept it. Any key on the
list can sign, so the list is also the blast radius: a key stays on it only while it is meant to be
able to sign, and `ReleaseKeyTest` pins the fingerprints so that adding or removing one is a line
someone wrote on purpose.

**Where the private half lives, and why not in a secret.** In Cloud KMS, called from the
maintainer's machine. Not as a file there: a file is readable by everything that runs as that user
between releases, and losing it strands every binary that carries the public half. KMS gives three
things a file does not — the bytes are never on the machine, every use is in an audit log, so a
signature nobody asked for is *detectable*, and a key believed compromised can be disabled instead
of lived with. **Not in a repository secret, and not federated to the workflow.** The tempting
version of this is a credential in GitHub Actions and a rule that only the maintainer may release;
it does not hold, because whoever has repository write can edit the workflow, add another one, or
be a compromised third-party action already running in that job, and the rule about who may release
is administered by the account being assumed compromised. Signing in CI would also duplicate the
provenance attestation below while answering none of the question it leaves open. What KMS does not
fix is a compromised machine at signing time: whoever holds the credentials can ask for a
signature. That is why signing is one command a person runs and reads the output of, rather than a
step in a pipeline, and why the script prints the key and the build it is about to vouch for before
it asks.

**Provenance is a different claim, and it is published too.** The release workflow attests every
file in `SHA256SUMS.txt` with `actions/attest-build-provenance`, so `gh attestation verify
jailscale-linux-amd64 --repo eth219/jailscale` answers which workflow of which repository built it
from which commit. That is Sigstore keyless signing -- the modern default for a CLI release -- and
it is deliberately *not* what `--download` checks, for the reason that makes it cheap: the identity
it binds is the workflow's, so an account that has been taken over can push a tag, run the workflow
and obtain a perfectly valid attestation for a binary of its choosing. It answers "what built
this"; the release key answers "who approved this", and only the second is a reason to install
something. Verifying Sigstore in the binary would also mean a Fulcio certificate chain, an identity
policy over its extensions, a Rekor inclusion proof and a trust root that ages -- a thousand lines
of security-sensitive code, in a binary with no third-party runtime dependency at all (§1), in
place of ninety.

**Replacing the running binary is still not implemented**, and the reasons that survive the above
are the ones about privilege and ownership rather than trust: `/usr/local/bin` is root-owned while
the daemon deliberately runs without root, Windows cannot overwrite a running `.exe` in place
(though it can rename it, which is what the printed instructions do), and a package manager or a
container image must not find a second owner of its file. Those are answerable — the writability of
the path is most of the test, since a package-managed binary is one this process cannot write — and
answering them is the next step rather than this one. A daemon already running keeps the binary it
started with until it restarts, which the output says.

**The URL is compiled in and the hub cannot name it.** The hub already sends its own version in
`HelloResponse`, and it would be a short step to let it say where the update is; that step hands a
compromised hub (§11.2) every node's next binary. A version string from the hub is one thing, a
download location is another.

**What the node does not do:** no WireGuard, no userspace TCP/IP, no STUN, no SOCKS5, no MagicDNS.
One outbound 443 connection, streams in, TLS off, plaintext to a local port. No inbound port, no
local UDP, no root.

---

## 10. Joining

There is no IdP. The right to join is a **capability**: an invite link, a short code and an auth-key
are all secrets where possession is the permission, and the hub registers whichever MachineKey
arrives with one. Joining is the right to publish; visitors never join.

**Why no IdP.** An IdP answers "who is this person", not "may they publish", so an invite and
approval queue would be needed anyway, and the IdP ends up being a name tag stapled to someone
already invited. The cost is an app registration for every hub operator, on the order of a thousand
lines of security-sensitive code, and the exclusion of collaborators without an account there.
Putting the user name in the invite solves the name-tag problem directly, which is the model
Tailscale auth-keys, headscale pre-auth keys and Syncthing device approval all use. What is given up
is externally verified identity: a leaked link lets someone else in under that name, and the
countermeasures are one-use short-TTL defaults and removal from the admin list.

**A user name is an identity, so it cannot be self-served.** Admin rights and name ownership are both
keyed on the user string, so whoever chooses that string chooses who they are. A joining node
proposes its own name only when the credential does not fix one, and a proposal that collides with an
existing user is refused with `user-taken` — otherwise joining as "alice" would be enough to *be*
alice, with her admin rights and her names. Joining as an existing user is a real thing to want, and
it is authorised the same way everything else here is, by a credential that names them: an invite
pinned to that user (the second machine of a person runs `jailscale invite --self` on the first), an
auth-key whose owner is them, or an operator typing the name at approval. For the same reason a
member may pin an invite to a *new* user or to themselves, but naming an existing user in an invite
is an admin's call.

**A rejection answers the attempt that caused it, and no later one.** `up` reports what the hub said
by reading the last `RegisterResponse` off the link, and the link outlives the command: a refused
`--user alice`, followed by the `invite --self` the refusal itself recommends, used to report
`user-taken` a second time for an invite the hub had just accepted. The node was joined and the
person at the keyboard had been told it had failed. `HubLink.start` clears that answer when it is
given a new credential, since a new credential is a new question.

**Credentials.** Invites are not admin-only: by default any member issues one from their own node,
the issuer is recorded, and an admin can narrow it with `--invite-policy admins`. `jailscale invite`
prints a link carrying a 128-bit token (one use, 24 hours by default) and a short code that is an
alias for the same invite, 40 bits in Crockford base32 as `XXXX-XXXX`, valid 10 minutes and
normalised on entry. The hub stores only hashes. An **auth-key** (`jk_` plus 128 bits) is the
unattended form for CI jobs, containers and servers, optionally bound to a tag instead of a person.

**Joining.** `jailscale up --invite <link>` takes the hostname from the link, pins the hub key
through `/v1/key` (§5.2), opens the Noise channel, negotiates versions, asks for a name only when the
invite does not fix one, and sends `RegisterRequest`; the hub matches the token hash, checks expiry
and remaining uses, decrements, assigns a node id, and replies `approved` followed by `CertUpdate`.
No browser opens, so a headless server runs the same command, and opening `/join/<token>` in a
browser shows install instructions without consuming a use. An attacker can hand out an invite to
their own hub, so the CLI prints which hub it is about to join and asks for confirmation; even if the
victim joins, nothing local is exposed until they run `open`.

**Knocking.** With only the hostname a node can knock: the hub queues MachineKey, hostname, OS,
source address and self-chosen name, and an admin approves through `/admin` or `jailhub node
approve`, which is pushed over the already-open stream 0. The queued name is the joiner's own
suggestion and a knock is unauthenticated, so the approval form leaves the box **empty** when that
suggestion is an existing user, and approving without naming anyone is refused in that case rather
than handing a stranger someone else's account on one click. Knocking is unauthenticated, so pending
entries are capped at 5 per source address, and `--knock off` disables it. `--registration open`
suits a personal hub or small team where the gate is overhead, approving a knocking node immediately;
the default is still invite-only, and turning it on prints the consequence, which is that anyone who
knows the hostname can open names under `*.hub.example.com`. There is deliberately no web signup
form, because that would be the same thing with more code.

**First bootstrap.** When `jailhub serve` finds no admin it prints a one-use 24-hour invite on the
console, and whoever joins with it becomes an admin. If every admin node is lost, `jailhub admin
login-link` on the hub shell recovers access, because shell access is the top of the authority chain.
Nodes do not expire by default; an admin removes them with `node remove`.

---

## 11. Security model

Four axes. None of them implies any other.

| Axis | Question | Answer |
|---|---|---|
| **Transport** | Who can read between visitor and node | Nobody, the hub included. It sees SNI, IP, byte counts, timing (§8.1) |
| **Right to publish** | Who can open a name | Only nodes that joined through an invite, auth-key or approval. No open registration by default |
| **Right to visit** | Who can reach a published link | Public by default; with `--gate`, only holders of the visit link (§9.3) |
| **Name identity** | Who vouches that `myapp.hub.example.com` is alice's node | **The hub.** It owns the routing table and the wildcard key (§11.2) |

### 11.1 The boundary of signature delegation

The wildcard private key exists only on the hub, and a node gets a signature only for a stream the
hub delivered to it whose SNI is one of its own names, over the transcript of the handshake with the
visitor on that stream (§9.2). So a compromised member node gains impersonation of **its own names**,
which were already its own: a handshake it runs with some other visitor, for a name it does not
hold, is one whose ClientHello the hub never delivered to it, and the hub signs no hash it cannot
recompute from a ClientHello it did. Because the control channel is pinned to the hub key by Noise,
a MITM proxy that defeats TLS still cannot intercept or forge signing requests. The hub checks every
request against content, stream, name, transcript, count and rate and logs refusals; a node that
keeps being refused is disconnected and flagged.

The one thing the binding rests on outside the hub is that the node can tell the hub what its own
ServerHello and EncryptedExtensions were, which it reconstructs rather than reads (§9.2). That is a
correctness dependency on JSSE's wire format, checked by tests and failing closed, not a trust
dependency on the node: a node that lies about those messages gets no signature.

Separately, joining opens no port on the node: only the port named in `jailscale open` is reachable,
and only while that link is open. There is no TUN device, so there is no OS routing path to leak
through, and a visitor reaches exactly the one `host:port` the node named, never the node's other
services or its LAN.

### 11.2 The hub is trusted

Stated plainly. If the hub is compromised:

| It cannot | It can |
|---|---|
| Read visitor traffic to an honest node (the node terminates it) | **Reassign a name to an attacker node** and sign with the wildcard key, intercepting that name entirely. Not preventable, but detectable (§11.3) |
| Obtain a node's MachineKey or user-domain keys (it never has them) | Register arbitrary nodes and issue invites at will |
| Reach local services a node has not published | See who connected to which name, when, and how much |

The hub is the TLS authority for its own domain, so its compromise is impersonation of every name
under it. User domains are the exception, since their keys live on the node and a compromised hub can
only stop routing them. For a self-hosted deployment where the hub operator *is* the organisation
this matches the usual threat model, and names needing more should be user domains. Preventing and
knowing are different: the hub decides who owns a name, so it cannot be stopped from reassigning one,
and §11.3 makes the node notice instead.

### 11.3 Self-probe

The node connects to its own public name and checks whether it terminated that TLS session itself;
the command is `jailscale verify`. The mechanism is RFC 5705 exported keying material: both ends of a
TLS 1.3 session derive the same bytes from a label, and a third party that did not terminate the
session cannot.

1. The node records the exported value of every visitor session it terminates, keeping the last 120
   seconds and at most 4,096 entries. It records **on the first application bytes from the peer**,
   not when `handshake()` returns: on the server side of TLS 1.3 the peer's Finished may not have
   been processed yet, and JSSE will not export until it has, so recording earlier can silently skip
   a session this node really did terminate. A false report of a compromised hub is the worst
   failure this feature can have, and application bytes cannot arrive before the Finished.
2. `jailscale verify` connects to each open https link **by its public name**, at the hub address, so
   it genuinely traverses the hub.
3. It sends `GET /` and waits for the response. A response means the server side has already read
   application bytes and recorded them, which removes the race between steps 1 and 4.
4. If the exported value is in the record the verdict is `terminated by this node`; otherwise
   `TERMINATED ELSEWHERE`. The comparison uses `MessageDigest.isEqual`.

If a hub holding the wildcard key terminates the name itself or hands it to another node, the
certificate the visitor sees is still valid but the session is a different one, so its exported value
is not in the record; a hub that decrypts and re-encrypts is caught for the same reason. The probe
leaves the node's own address, so a hub that singles those connections out and routes only them
correctly is not caught, though doing so requires discriminating between visitors, which is itself
detectable; `--tls-insecure` or a stale `--ca-file` blinds the probe, and TLS 1.2 and below cannot
export the material, giving the verdict `keying material unavailable`.

The four signing conditions are enforced by **the hub**, so they stop a rogue *node* and say nothing
about a rogue *hub*. The self-probe runs on **the node**. They do not overlap; they face opposite
directions.

**It also runs on its own, one name every half hour.** Waiting for someone to type `jailscale verify`
means an interception is found when somebody happens to look, which for an unattended node is never.
The objection to a schedule was that the period has to scale with the number of open names — short
enough to matter for one name is a lot of self-traffic for twenty. It does not have to, if a tick
probes **one** name and the next tick takes the next: the cost of a tick is then one request whatever
the node holds, and what stretches is how long a full pass takes, from half an hour at one name to
ten hours at the 20-link ceiling. Raw ports are stepped over within the same tick rather than
spending it, since they carry no TLS of ours to compare. The result of the last probe of each name
rides in `status`, so the answer is visible without running anything, and a `TERMINATED ELSEWHERE`
from the loop logs exactly as loudly as one the operator asked for. There is no switch to turn it
off: the traffic goes to this node's own name through its own hub and reaches no third party.

### 11.4 Name revocation notices

The self-probe finds a move after the fact, and a name's turn can be hours away (§11.3), so an
**honest hub announces a name change in advance** with `LinkRevoked{linkId, name, reason, at}`, where
`reason` is `reassigned` (another node opened the same name) or `released` (an operator took it
back). A compromised hub simply does not send it: this is incident notification, not attack
detection, and catching a compromised hub is §11.3.

**The trigger is stored ownership, not a live link.** That distinction is the whole design. A node
losing a name is usually **offline**, and being offline is exactly why someone else took the name, so
at that moment there is no live link to look at. `Links.open` therefore watches for the stored claim's
MachineKey changing and notifies the previous one; domains and raw ports use the same rule against
their own records.

A connected node gets the notice immediately, otherwise it is stored and handed over on the node's
next connection, then cleared; clearing happens only after everything has been sent, so a node that
dies mid-delivery hears it again, and a node that never returns is capped at 20 stored notices. On
receipt the node removes the name from local state, because leaving it would silently reopen it on
the next reconnect and make the notice pointless, and records it under `revoked` so `status` keeps
saying so after the log line has scrolled away; deliberately reopening the name clears the warning,
since that is the answer to it. `name release` and `domain release` take the live link down and send
the notice rather than quietly clearing ownership while the old node keeps serving. Release is not a
ban, so the same node may reopen the name; banning a node is `node remove`.

### 11.5 Abuse and rate limits

A public link can host a phishing page. The operator can release the name and remove the node, random
names are five characters and hard to guess, chosen names exist only for members, and the structural
limits are 1,024 connections per name and 20 links per node. Beyond that, abuse response is the
operator's job. Unauthenticated work is metered with per-source token buckets:

| Target | Burst | Sustained | On excess |
|---|---|---|---|
| `/v1/noise` handshake | 30 | 1/s | HTTP 429, Upgrade refused |
| Credential presentation (invite token, code, auth-key) | 20 | 0.2/s | `rejected{reason: rate-limited}` |
| Registration under `--registration open` | 5 | 1 per 12 min | `rejected{reason: rate-limited}` |
| Knock queue | 5 entries per address | n/a | `rejected{reason: too-many-pending}` |

A node the hub already knows returns before the credential check, so reconnections never touch the
bucket. The bursts are generous because a node opens up to four connections and a NAT can hide many
nodes behind one address; the sustained rate is what limits abuse. Open registration needs a bucket
of its own because nothing is presented in that case, so the credential one never sees it, and
without a limit one address could register nodes without bound and claim public names under the hub
domain. To stop an attacker inflating the map by rotating addresses, once more than 10,000 keys are
tracked the full buckets are dropped: a full bucket is indistinguishable from one that never
existed, so nothing is lost. The same rotation is why the per-address connection counters of §8.1
are dropped once the last connection using one is gone, rather than left behind at zero.

**`/admin` sessions.** The login link is one-shot and lives 60 seconds, the session cookie lasts 12
hours, and every POST carries a CSRF token. On top of that, **admin status is rechecked on every
request**, because checking only at issuance would leave `admin remove` ineffective for 12 hours; a
link issued over the IPC socket is exempt, since socket permission is the authorisation. The cookie
uses the `__Host-` prefix, which forbids a `Domain` attribute, so a node controlling a sibling
subdomain under `*.<hub>` cannot plant an admin cookie. Auth-keys, invite tokens, codes, gate tokens
and admin login URLs are never written to logs.

---

**Address bans.** An operator can bar an address or a CIDR block, v4 or v6, from the control plane:
`jailhub ban add 203.0.113.0/24`, or the button beside a node on the status page. Matching is on
the raw address bytes with a prefix mask, so a v4 rule never matches a v6 address and no text
parsing happens per check. A hostname is refused rather than resolved, since that would be a DNS
lookup driven by admin input.

It is enforced twice on purpose. `NodeSession` refuses a banned address before the Noise handshake,
so a banned peer cannot make the hub do any crypto, and `Registrar` refuses before it looks at
whether the node is already known, so banning covers a node an operator has just removed. Either
alone is sufficient; both together mean a mistake in one is not a hole.

Placing a ban also disconnects what that address currently has open, with `Goodbye{banned}` rather
than `Goodbye{revoked}`: the node's registration on the hub is untouched, and telling it "revoked"
would make it erase a registration the hub still holds. A ban is not a firewall and does not touch
visitors. The point is to stop someone running nodes here, not to stop them reading a page.


### 11.6 Side channels and the local attacker

Two things sit outside everything above, and this says which, so that nothing is quietly assumed
into them.

**A process on the same machine is not defended against.** On the node that means the MachineKey and
any user-domain keys; on the hub it means the wildcard private key, which is what the rest of §11 is
written around. Key material is an ordinary heap object read from an ordinary file: nothing is
pinned in memory, nothing is zeroed after use, and a core dump or a debugger attached to either
process yields it. The boundary is the operating system's -- `node.json` and the hub's keys are
written 0600 (§4; on Windows `setPosixFilePermissions` is unsupported and the directory ACL is what
holds), the daemon needs no root and opens no port, and the container image adds a filesystem
namespace around the node as well. Those are real and they are not cryptographic: an attacker
already running as that user has the key. The self-probe does not help here either, because a node
with a stolen MachineKey is, to the hub and to the probe, that node.

**Timing is not a property anything here claims.** X25519 and ChaCha20-Poly1305 come from the JDK's
own providers -- `XDH` and SunJCE -- and have whatever properties those have; this project adapts
them to the Noise encodings and implements neither. What is written here is BLAKE2s and the HMAC and
HKDF over it, which branch on nothing secret but are not audited for timing and claim nothing. They
hash handshake material; they are never the thing that compares a presented secret against a stored
one. The comparisons that do decide something:

| What is compared | How | Where that leaves it |
|---|---|---|
| Self-probe keying material (§11.3) | `MessageDigest.isEqual` | Constant time, deliberately: the verdict is the whole feature |
| Invite token, short code, auth-key (§10) | SHA-256, then a lookup by the hash | Timing follows the hash of what was presented, which does not walk back to the secret |
| `/admin` CSRF token (§11.5) | `MessageDigest.isEqual` over the bytes | Constant time. It was `String.equals`, and nothing reachable turned on that; a comparison of a presented secret is the wrong place to keep the cheaper habit |
| `/admin` session cookie and login link (§11.5) | 128-bit random, a `ConcurrentHashMap` key | **Not constant time, and not made so:** a hash lookup has no byte compare to replace. Reaching a useful prefix of 128 random bits over HTTP is not a path anyone has, and a correct guess needs no timing |

**Traffic analysis is not addressed at all.** The hub sees the SNI, the visitor's address, byte
counts and timing (§8.1), and nothing on either side pads, batches or delays anything. Sizes and
arrival times say what they usually say, and a hub that wants to know which page went over a link it
cannot decrypt has the ordinary means. What §11.2 claims is that the hub cannot read the bytes, not
that it cannot count them.

**None of this is a gap waiting on a fix.** A tunnel whose node runs unprivileged on a machine its
owner already controls has no meaningful place to put a key the machine's owner cannot reach, and
padding a proxy that forwards ciphertext buys latency and bandwidth against an adversary this design
already grants the metadata to. They are written down because a security model that lists four axes
and stops invites the reader to assume a fifth.

---

## 12. Threading and memory

There is no packet hot path, so there is no reason to insist on platform threads. The hub's 443
accept loop is the one platform thread; a visitor connection uses two virtual threads, one per
direction, at both ends; each mux connection has a virtual reader plus a virtual keepalive, with
writes running on the producing thread under a lock because the Noise nonce counter must advance in
wire order; and the hub's own HTTP, ACME, port 80, DNS and both IPC servers use one virtual thread
per request. Remote signing blocks on the calling thread, which is free on a virtual thread. Buffers
are 16 KB per direction, allocated per stream, and the per-stream flow-control window is 256 KB.

Concurrency scales with the number of names: the hub accepts 1,024 per name and a node can hold 20,
so one node's ceiling is 20,480 concurrent streams and the hub's is that times the number of names it
serves. **Both binaries do carry a heap ceiling** -- 96m for `jailhub`, 64m for `jailscale` (§14) --
because without one the Serial GC's allowance is 80% of the machine and a long-running hub drifts
into it. The connection ceilings above are not derived from those, and cannot be: what a connection
costs depends on whether anyone is reading it, so no count covers the bytes correctly. The two used
to have nothing to say to each other at all, and the product of them was 272 MB against a 96 MB
ceiling -- reachable by an unauthenticated visitor reading slowly. What connects them now is the
receive budget of §5.3, which is in bytes, is a quarter of the heap ceiling and derived from it, and
resets the stalled stream rather than letting the process die. The ceilings themselves are still
what 1,000 visitors held open were measured to fit in; the budget is what makes that measurement
hold when those visitors are not reading. A host that needs
more passes `-XX:MaxHeapSize=` at run time, which the native runtime consumes before `main`. Two consequences: Serial GC does not
return the heap to the OS, so RSS stays at its high-water mark after a load burst, which is headroom
and not a leak; and idle RSS is unrelated to heap size, because at idle there is no heap to speak of:
across a node daemon's whole start, connect and first link the collector runs **zero times** and the
heap grows from 0.5 MB of chunks to 1.0, against 0.78 MB of objects ever allocated. Lowering the cap
cannot move a number the heap is not in.

That measurement replaced what this paragraph used to claim. It read "the node daemon alone is about
16.7 MB and reaches about 24.3 MB the moment it connects, so roughly 7.6 MB is JSSE initialisation
for one TLS client" -- one delta between two processes, attributed whole to JSSE. Held in five
states and measured three ways (`docs/jsse-idle-cost`), the same transition is 8.0 MB on
darwin-arm64, and **1.5 MB of it is memory the process owns**: the rest is the binary's own code and
image heap becoming resident, clean, file-backed and evictable. JSSE's share is between 2.6 and
5.8 MB of that RSS, because the second half of it is the Noise handshake, the multiplexer and the
registration as well; 2.0 MB is the join, which a restarted node never repeats; and standing the TLS
client up writes 139 KB.

---

## 13. Availability and hand-off

The hub is one process on one host. The main deployment is a single self-hosted VPS, and at scale one
hub handles thousands of nodes and tens of thousands of streams, because all it does is copy bytes
and sign. What remains is availability, and the answer is fast recovery.

| Item | Target |
|---|---|
| Hub process restart | Under 5 s including state replay. Nodes reconnect with 1, 2, 4, 8, 16, 30 s backoff |
| What a visitor sees | Connections refused during the restart; streams in flight are cut |
| Backup unit | The `$JAILHUB_STATE` directory. `hub.key`, `tls/` and `state.*` are all of it |
| Host replacement | Copy the directory and change DNS. Nodes notice nothing, since the hub key and wildcard key are unchanged |

**Hand-off.** Updating the binary does not need a restart. `jailhub serve --takeover` starts a new
process that asks the old one to hand off over the IPC socket. The old process closes the 443
listener, the raw ports, port 80, the DNS responder and ACME, snapshots its state, releases the state
lock, and sends `Goodbye{draining}` to every node; visitor streams already in flight keep flowing on
those connections, and no new ones are opened on them. The new process takes the lock, replays the
state and opens 443, and for the few hundred milliseconds in between new visitors are refused
(`SO_REUSEADDR` means no bind wait). On `draining` a node immediately opens a fresh connection and
reopens its links, keeping the old connection until its open streams finish, and a signing request
goes to the connection that owns the stream, which is what makes a draining stream's signature
findable. The old process exits when the draining connections are empty or after 60 seconds, and
deletes the IPC socket file only if it is still its own (compared by inode) so it cannot remove the
new process's socket.

A visitor sees a few hundred milliseconds of refused connections; downloads and WebSockets in flight
are not cut, nodes reconnect with no backoff, and deploy and rollback are the same one line. The
router's 3-second wait for a claimed but momentarily offline name (§8.1) keeps the gap from becoming
an error page.

**Hand-off does not compose with a systemd unit.** It works by leaving a second process holding the
listeners while the first exits, and under `Type=simple` the first process is the one systemd
tracks: its exit stops the unit and the cgroup takes the new process with it. Tested, and the hub
went inactive. Under systemd the upgrade is `systemctl restart`, which costs a few seconds while
nodes reconnect. `deploy/jailhub.service` therefore has no `ExecReload`. Making the two work
together would need the listening sockets handed over rather than rebound, which is not implemented.

**Readiness can be reported, and the reference unit does not ask for it.** The hub speaks the
readiness half of `sd_notify`, so under `Type=notify` `systemctl start` returns when it is serving
rather than when the process exists; on a first boot those are minutes of ACME apart. It is off by
default because it is not free: `start` does not return until a certificate is installed and
issuance retries for as long as that takes, so an ordinary first boot outlives systemd's 90-second
`TimeoutStartSec` and the unit has to say `TimeoutStartSec=infinity` as well, or systemd kills the
hub part-way through its first issuance and `Restart=on-failure` does it again forever. The
notification is sent by running `systemd-notify`, because `NOTIFY_SOCKET` is an AF_UNIX *datagram*
socket and the JDK will not open one, so the unit also needs `NotifyAccess=all` and the host needs
**systemd 246 or newer** — a notification from a child that has already exited is one the manager
cannot attribute to a unit and drops, and `systemd-notify` waiting for it to be processed is a 246
feature (Ubuntu 20.04 has 245, RHEL 8 has 239). The exit status is 0 either way, so a hub cannot
detect it; the unit just never leaves `activating`. `deploy/jailhub.service` lists the three lines
and what each is for. None of it makes the hand-off compose with a unit.

---

## 14. Current characteristics

Measured with the native binaries by `./measure.sh`, which starts a real hub and two node daemons on
loopback, joins them with the real CLI and opens a link. Both columns are measured, on the two
platforms CI can run the gate on; the budgets differ per platform for the reason below the table.

Both columns are the toolchain and options the release workflow uses: GraalVM CE 25.3, `-O2`, no
profile-guided optimization. That was not always true of the macOS column, and the cost of it is
below the table.

**This table is v0.1.2 and not v0.1.0.** The first tag is from 2026-09-12 and the 25.3 pin landed
on 2026-09-13, which leaves v0.1.0 alone on Liberica NIK 25.0.4 -- the left-hand column of the
edition table below -- and every release from v0.1.1 on the same toolchain and options this gate
measures. Measured on v0.1.0's own assets and that column: binaries of 29.8 to 31.9 MiB against the
25.3 to 26.4 here, idle RSS on linux-amd64 of 40.6 MB for the hub and 40.1 for the node against 35.1
and 34.4, and a 4.7 ms CLI cold start against 2.4. It also carries five native targets rather than
four, since the 25.3 line is what dropped macos-amd64 (§3.2). README says the same where it tells
people which file to download.

| Measurement | arm64 macOS | linux-amd64 | Budget (macOS / linux) |
|---|---|---|---|
| Binary size | 25.3 MiB (`jailhub`), 25.5 MiB (`jailscale`) | 26.1 MiB, 26.4 MiB | 28 / 28 MiB |
| Node idle RSS | about 25.0 MB | about 34.4 MB (2.1 anonymous) | 28 / 38 MB |
| Hub idle RSS | about 25.1 MB | about 35.6 MB (3.3 anonymous) | 28 / 38 MB |
| RSS with 1,000 visitor sessions held open | node 52 MB, hub 52 MB | node 55 MB, hub 62 MB | node 88 MB, hub 88 MB |
| CLI cold start | about 6.3 ms (`jailscale status`, median of 10, IPC round trip included) | about 2.6 ms | 50 ms |

The two columns are different runs of the same script on the same tree: linux-amd64 is the gate's
own output at the commit v0.1.2 was cut from, macOS a local run on binaries built by `./native.sh`,
whose `native-image` banner and byte size match the release assets to within the version string.
§9.3's visitor bound is visible in both, taking the node's held-open peak from 67 MB to 55 on linux
and from 69 to 52 here. The held-open peaks are the noisy row: two macOS runs gave hub 50.7 and
52.1, node 49.4 and 51.8, so read that line as "about 52" rather than a figure to compare at one
decimal.

### How many visitors this serves, and what stops it

The numbers for this were spread across §5.3, §9.3, §15 and the table above, so answering "what
happens when a thousand visitors arrive" meant reading four places and doing the arithmetic. It is
one place now.

| | hub | node |
|---|---|---|
| What one visitor costs | the bytes it has not read yet — **0 if it reads**, up to 272 KiB if it stalls | **about 99 KB** of TLS state, the same whether it reads or stalls |
| The bound | `FlowBudget`, **24 MB** of receive queues (§5.3) | `Visitors.MAX_IN_FLIGHT`, **450** visitor streams (§9.3) |
| In what unit | bytes | a count |
| Where it comes from | a quarter of the 96 MiB heap ceiling | measured against the 64 MiB heap ceiling |
| Over it | resets the stalled stream holding the most | refuses the new visitor before its handshake |
| Reported as | `jailhub_receive_budget_bytes`, `_queued_bytes`, `_queued_peak_bytes`, `jailhub_streams_reclaimed_total` | `jailhub_node_visitor_capacity` on the hub, `visitorCeiling` / `visitorsInFlight` / `visitorsRefused` in `jailscale status` |
| Moved by | `-XX:MaxHeapSize=` on the hub | `-XX:MaxHeapSize=` in `JAILSCALE_DAEMON_OPTS` |

**Which one binds first is a question about the visitors, not about the deployment.** The two bounds
are in different units on purpose, and that is the whole answer: the hub's is reached by *behaviour*
and the node's by *count*. A thousand visitors who read what they asked for cost the hub almost
nothing and the node 99 MB, so the node's count binds and the hub's queues stay near empty — which is
what the budget gate sees on the CI runner, 2.0 to 11.9 MB of 24. A few hundred who stall cost the
node the same 99 KB each but can fill the hub's 24 MB, which is what a developer's machine sees at
`SLOW=400`: the queue pinned at 24.0 of 24.0 with streams shed. Both bounds have been reached in
measurement; neither is the one that always goes first.

**The hub admits on three caps now, and only the third is about capacity.** Per address
(`MAX_PER_IP` = 64) and per name (`MAX_PER_NAME` = 1,024) are abuse limits and were never
capacities — the per-name number sat on the hub's own page as though it were one, against a node
holding a few hundred. The third is what the node said it will hold, sent on `Hello` (§5.4's
additive case, and the first field added to an existing message since the protocol shipped). A node
that does not send it — every build older than the field — is admitted exactly as before, and its
own bound resets what the hub oversends.

**What the operator can do about it.** A node at its bound shows up as
`jailhub_visitors_refused_capacity_total` rising and as "N of 450" in the admin node table; the
answers are to give that node more heap, which raises its bound proportionally, or to move a name to
another node. A hub at its receive budget shows up as `jailhub_streams_reclaimed_total` rising with
`jailhub_receive_queued_peak_bytes` at the limit, and the answer is more heap on the hub. The two are
told apart by which counter moves, which is why they are separate counters.

**`measure.sh SLOW=` measures a third axis, and the node does not meet its budget on it.** `LOAD=`
holds visitor sessions open with no bytes in flight; `SLOW=` has each visitor ask for 8 MB and read
only the status line, which is the only shape that reaches the receive budget of §5.3. On that axis
the hub is fine -- the receive queue pins at its budget, streams are shed, and its RSS stays under
the load budget -- but **the node reaches 96.7 to 98.9 MB against an 88 MB budget** at about 1,000
visitors (two people, one macOS arm64 machine). The cause is not the receive
budget, which this direction barely touches: a visitor sends one GET line, so the node's receive
queues hold tens of bytes.

**This was the axis's open defect, and it is bounded now (§9.3).** The paragraph below is what a
thousand stalled readers did to an unbounded node, kept because it is what the bound is measured
against and because the gate's count was chosen from it. With `Visitors.MAX_IN_FLIGHT` in place the
same thousand hold 450, the rest are reset before their handshake, the node peaks at 86.2 to 86.8 MB
across three runs with no `OutOfMemoryError`, and an ordinary visitor is served in 1 to 36 ms. The
budget job asks for a thousand again, because that is what exercises the bound: 450 held, 550
refused, and a node still running afterwards.

**At a thousand stalled readers this axis used to stop measuring the node and reach the defect.**
Measured on main with the release toolchain, darwin-arm64, `SLOW=1000`: **817 of 1,000 held, and
the ramp took 60.7 s against 5.4 s at 400**; six `OutOfMemoryError`s in the node's log, two of them
taking `mux-reader` and `mux-writer`, so the hub connection dropped and was remade mid-phase; an
ordinary visitor timed out at 30 s fourteen probes running; and the kernel refused 118,554 socket
allocations at a 502 MB peak. The node's 106.6 MB there **is not its cost at a thousand visitors** —
it is the ceiling it died against, with 183 visitors never admitted. This is the per-visitor
`TlsEndpoint` term of the paragraph above, arriving as a fault rather than as a number, and it is
the same shape `docs/mux-saturation` predicted on the JVM.

**The gate runs at 1,000 now, and the budget is pinned to whatever count it runs at.** On
darwin-arm64 that run holds 450 of 1,000 — the node's bound — refuses the rest, peaks at 86.2 to
86.8 MB across three runs, serves the ordinary visitor in 1 to 36 ms, and pins the hub's receive
queue at 24.0 MB of 24.0 with streams shed. The budget is 95, about 10% over the highest of the
three; it was also 95 at `SLOW=400`, where the figures were 82.1 to 83.2, because past the bound the
node holds `MAX_IN_FLIGHT` visitors whatever the count asked for and this number stops moving.

`measure.sh` carries `B_NODE_SLOW_AT` and **skips the node gate at any other count**: the cost being
bounded is per visitor, so the budget is only a budget at the count it was measured at. That check
earned itself before the bound existed, when this gate was very nearly wired to `SLOW=1000` against
a number measured at a thousand on a machine where a thousand no longer behaved.

**The linux-amd64 budget is 105, measured at the count the gate runs.** Two `workflow_dispatch`
runs on `ubuntu-24.04` at `SLOW=1000` put the node at **92.5 and 94.6 MB**; 105 is about 11% over
the higher. This constant was 105 once before and the coincidence is worth naming rather than
claiming: that one was *derived*, from the macOS figure plus the two platforms' idle difference, and
it was applied to `SLOW=400`, where four runs on the same runner read 88.5 to 89.7 — loose by more
than the margin it was meant to carry. A derived number that later lands near a measurement of a
different thing is still a number nobody measured.

**What raising the count did not buy, which is what it was raised for.** The reasoning was that at
400 the runner's receive queue peaked at 2.0 to 11.9 MB of its 24.0 MB budget with nothing
reclaimed, so `measure.sh`'s queue check — an upper bound — could not fail where the gate runs, and
that a thousand would reach it. On a developer's machine it does, at 400 and at 1,000 alike: 24.0 of
24.0 with 27 to 116 streams shed. **On the runner it does not, at either count** — two runs at a
thousand read 0.1 and 10.2 MB, *lower* on average than at four hundred, because the node refuses 550
of them and the ramp stretches to 18 s, so the hub drains what arrives as fast as it arrives. The
runner is about five times slower per warm request (8,360 a second against 44,721 here) and the
honest reading is that it cannot fill the queue at all. That assertion lives with whoever runs this
by hand; a green budget job asserts the node's RSS and its bound, and says nothing about the receive
bound. What the count does buy is the bound itself under load, which is new and which nothing in CI
would otherwise exercise.

**The long tail on this axis was the machine, and it took four attributions to reach that.** This
paragraph has said that an ordinary visitor's 7 to 19 s wait while slow readers arrive was the
node's per-visitor TLS state (an inference), then the hub's control frames queued behind data (true,
fixed in §5.3, and not enough: the wait survived it), then that what remained was in no stage at all
-- retired by the stage metrics, which put all of it in one:

    admissions 416, mean/worst ms: peek=7/14 resolve=0/0 open=0/0 reply=224/13491
                                   first_byte=231/13491 unaccounted=-0

All of it is `reply`, the wait for the node's first byte, and the node's own timers put that in one
socket write blocking for 3.2 s. What it was, found by sampling `netstat -m` through the phase: the
harness's 8 MB bodies on loopback, autotuned into megabytes of kernel socket buffer per chain, 400 of
which put 660 to 680 MB in use during the 5 s ramp, the pool's cluster classes at their caps and its
allocation at 798 MB. Every socket on the machine then froze -- the hub's writes to visitors, the
node's write to the hub for 3.2 s, the ordinary visitor's own handshake for 4.5 to 17 s, the
harness's own ramp -- while both processes' timers reported idle, which they were. The same 400
visitors with a 768 KB body kept the kernel at 229 MB and were served in 5 to 26 ms through the same
multiplexer. Three multiplexer designs had been priced against this before the kernel was sampled,
and the cheapest instrument in the story was one `netstat` line; `measure.sh` prints it now, with the
count of allocations the kernel refused during the phase -- which rises in every run at this scale,
frozen or not, so it says the pool is at its cap and not whether that cost anything.

Three things changed. The node gives its app socket the stream window (§9.3), so a stalled visitor
parks half a megabyte in the node's kernel and not up to 8; the harness gives each slow visitor a
small receive buffer, so its unread bytes come to rest in the hub's queue -- which is what the budget
bounds -- instead of in the kernel, where they had been reaching the budget only by exhausting the
machine first; and the harness app bounds its own send buffer to 64 KB. With all three the same 400
visitors put 454 MB in the kernel instead of 660 to 680 -- the node's app sockets 240 MB, the
visitors' 148, the hub's 31, the app's 25 -- the ordinary visitor is served in 13 to 45 ms, the
hub's queue reaches its 24 MB budget and sheds 130 streams, and the node's own writer, the one
carrying the bulk, shows a worst queue wait of 22 ms and a worst socket write of 16 ms across
81,000 frames. That pair is the multiplexer's whole head-of-line cost with 400 stalled streams
behind one socket, and it is what the three designs would have been paid for. Two cautions for
whoever runs this again: the freeze was intermittent at the old occupancy, two of four runs, so one
clean run at 660 MB proves nothing; and macOS keeps the pool allocated at its last peak, so the
figure `measure.sh` prints is clusters in use and not the pool's size, which reads high for minutes
after any run.

**What the node's RSS on this axis is, separately from the tail.** It is `TlsEndpoint`'s per-visitor
state -- `netInBuf`, `appInBuf` and the `SSLEngine`'s own, 50 to 60 KB each -- times however many
visitors are live at once. That was an unbounded per-connection term of exactly the kind §5.3's
budget bounds for receive queues; §9.3 bounds it now, by count rather than by bytes, and what this
axis measures past the bound is `MAX_IN_FLIGHT` visitors and not the count asked for. The node's RSS
on this axis repeats to 0.1 MB across runs,
unlike the hub's, because per-visitor state scales with the visitor count where queue occupancy
moves with the collector. `measure.sh` gates the node on this axis at `B_NODE_SLOW_MB`, which is set
above today's figure on purpose and says so.

**Linux is not 10 MB heavier; it counts differently.** Of the hub's 35.1 MB there, **3.3 MB is
anonymous** — the heap, the stacks, everything the process actually owns — and the rest is the
26.1 MiB binary's own text and rodata mapped in: clean pages, shared with the page cache, which the
kernel can take back. macOS's `ps` attributes far fewer of those to the process.

The live hub shows what that means under pressure. On a GCP e2-micro with 969 MB of RAM, after a
day of service, `smaps_rollup` reported 41.1 MB of RSS split into 15.0 MB anonymous and 26.2 MB of
file-backed pages — and only 25.7 MB of the then-31.6 MiB binary was still resident, the kernel having
already dropped the rest with no effect anyone can see. `measure.sh` prints the anonymous share on
Linux next to RSS, and still gates on RSS so that the two platforms are gated on the same
measurement.

**The anonymous share is heap sizing, and it is capped for that reason.** An earlier version of this
section called the difference accounting rather than heap sizing, which was wrong: the live hub was
found at 78.2 MB of RSS with **53.9 MB anonymous** after 20 hours with no nodes and no visitors at
all. It is not a leak. The same binary on the same instance, driven with 40,000
scanner-shaped connections, settles at 39.0 MB of anonymous memory with `-XX:MaxHeapSize=128m` and
at 9.7 MB with `32m`, reaching both inside the first 10,000 connections and then holding flat, so
the plateau is set by the heap allowance and not by the work; and 6,000 of the same connections
against the hub on a JVM leave the heap *smaller* after a forced GC, with an unchanged class
histogram. What sets the allowance when nobody sets it is `-XX:MaximumHeapSizePercent=80`, printed
by the binary's own `-XX:PrintFlags=`, which on a 969 MB instance is about 775 MB — five times the
hub's own budget. So both binaries are now built with a ceiling: `-R:MaxHeapSize`, 96m for `jailhub`
and 64m for `jailscale` (`native.maxHeap` in the poms). At 1,000 visitors held open that is 64.9 MB
peak RSS for the hub against 91.7 MB uncapped, and 61.5 MB for the node against 94.0 MB, with all
1,000 still served, idle RSS and CLI start unchanged, and the ramp 2.7s against 2.5s. Both binaries take
`-XX:MaxHeapSize=` at run time, the native runtime consuming it before `main` sees it, so a hub that
needs more gets it on the unit's `ExecStart`. The node takes it through
`JAILSCALE_DAEMON_OPTS`, which `Service.daemonCommand` puts straight after the executable when the
CLI spawns the daemon and when `service install` writes a unit -- so whatever is set at install time
is what the unit carries. It exists for measurement and diagnosis rather than as a product surface:
nothing measured so far asks for a different ceiling.

**Serial is the collector, and G1 was measured rather than argued about.** GraalVM CE offers
`serial` (default), `parallel` and `epsilon`; G1 needs Oracle GraalVM and Linux, so it could only
ever cover two of the four targets. It was built and measured anyway, on Oracle GraalVM 25.0.4 with
the same ceilings, against the same toolchain's serial build: the binaries went from 31.8 and
32.0 MiB to **39.9 and 40.3**, over the linux binary budget; idle anonymous memory went from 5.0 and
4.1 MB to **11.1 and 10.9**; and peak RSS with 1,000 visitors held open went from 68.0 and 58.2 MB
to **110.3 and 92.7**, about 60% more. The ramp was unchanged at 2.4s against 2.5s. So G1 is a cost
here, not a bonus — Native Image's own documentation calls the serial GC the one "optimized for low
memory footprint and small Java heap sizes", and at a 96 MB ceiling that is the whole requirement.
Swapping collectors was never the fix for the drift either: `MaximumHeapSizePercent` applies to
serial, parallel and epsilon alike, so the ceiling is what bounds it.

**The edition question, measured once there was something to measure it with, and answered
"neither".** An earlier version of this section said Oracle GraalVM was worth "about 1.2 MB of idle
anonymous memory and nothing else measurable" -- which was true of everything §14 measured at the
time, and wrong as a conclusion, because nothing measured CPU. With `RATE=` in place, all three
choices ran in one workflow on `ubuntu-24.04`, three measured runs each, spread within an arm under
1%:

| | Liberica NIK 25.0.4 | Oracle GraalVM 25.0.4 | Oracle 25.0.4 + PGO | **GraalVM CE 25.3** |
|---|---|---|---|---|
| `jailhub`, `jailscale` binary | 31.7, 32.0 MiB | 31.8, 32.0 | 21.9, 21.9 | **26.1, 26.2** |
| Idle RSS (anonymous) | 40.6 (6.2), 40.1 (5.0) MB | 39.4 (5.0), 38.6 (4.0) | 32.4 (4.8), 32.0 (3.9) | **35.1 (3.3), 34.4 (2.1)** |
| Peak RSS, 1,000 held | 71.7, 61.0 MB | 64.7, 58.4 | 61.3, 51.6 | **64.8, 67.4** |
| Handshake CPU | 2,525, 3,025 µs | 2,362, 2,750 | 1,962, 2,300 | **1,544, 1,985** |
| Warm request CPU | 163, 181 µs | 149, 163 | 66, 70 | **71, 79** |
| Warm requests a second | 7,697 | 8,419 | 19,169 | **17,560** |
| CLI cold start | 4.7 ms | — | — | **2.4 ms** |

**Releases build with the right-hand column: GraalVM CE on the 25.3 line, no profile.** The first
three columns are the same 25.0 line, and the story they tell is that the edition is worth 6 to 10%
of CPU -- real, consistent across four metrics, and close to the 7% seen between jobs on different
runner instances -- while a profile is worth a doubling of throughput. The fourth column is the one
that settled it: **the newer compiler line gets essentially the same doubling with no profile and no
licence.** Two independent routes arrive at about the same place, and only one of them costs
anything.

PGO was adopted for releases and dropped again within the day, once it could be measured on both
platforms rather than one; the profiles stay as a local option (`profiles/README.md`). The
25.3 line costs one release target -- it does not build macos-amd64 -- and is not the LTS line, so
`version:` has to be moved forward as GraalVM's feature releases land. Both were judged worth
17,560 warm requests a second against 7,697.

**PGO's size and memory gains are dependable. Its CPU gain lands only where the profile came
from.** What holds up, across nine builds:

- **Size and memory, every time.** Every PGO build measured, on either platform, lands at 21.6 to
  21.9 MiB against the 29.9 to 32.0 of the 25.0-line builds it was measured against, with idle RSS
  down about a fifth. Against what actually ships now it is a smaller gain: the 25.3 line reaches
  25.3 to 26.2 MiB with no profile at all.
- **CPU on the profile's own platform: real.** On linux-amd64, where these profiles were collected,
  warm throughput went from 8,419 to 19,169 requests a second and handshake CPU from 2,362 to
  1,962 µs.
- **CPU on any other platform: a loss.** The same profiles on arm64 macOS gave 862 µs of hub CPU per
  handshake against 747 plain and 28,976 warm requests a second against 34,780 -- 11% and 16% the
  wrong way. Both arms there are the toolchain of the time, not what ships now; what matters is the
  sign. Per-platform profiles were then collected on macOS and measured: no better, slightly
  worse. The FAQ's "in most cases, the PGO profiles are sufficiently cross-platform" holds for size
  and memory and not for CPU.
- **The same recipe does not produce the same profile twice.** Four PGO builds of the same source
  gave hub CPU per handshake of 1,225, 1,756, 2,094 and 2,244 µs, and **two builds from the
  identical configuration gave 1,756 and 2,094**, with the three measured runs inside each build
  within 1% of each other. So the variance is between builds, not between measurements. A profile
  collected without the load phase (visitors arriving) gave no handshake gain at all, while profiles
  from warm requests only, handshakes only, and both landed within 1% of each other -- coverage of
  *kinds* of work matters, the particular throughput shape does not.

What it costs is not performance. GFTC puts Oracle's terms on binaries this repository ships under
Apache-2.0: free for us, since we charge nothing and Native Image output counts as unmodified
Program, but a downstream that wants to sell a bundle is blocked and every toolchain bump becomes a
licence review. And a profile is only collectable where a workload driver runs: `measure.sh` is a
POSIX script that wants `pgrep`, `pkill`, `bc` and `/proc`, none of which the Windows runner has, so
**windows-amd64 could not be profiled from its own traffic today** (it does have `python3`,
`tasklist` and `powershell`, so a driver is possible; none is written). Weighing that against a gain
that only reaches one of the release targets is what decided it. Almost no project of this size ships
profile-guided binaries, and the ones that do -- Firefox, Chrome, CPython, the Go compiler, rustc --
each run a build bot whose job is keeping the profile current.

**What the 25.3 line is, and what part of it is compressed references.** GraalVM's version and the
JDK's are two tracks: CE 25.3.4.1 carries JDK **25.0.4.1**, the same LTS JDK as Liberica NIK
25.0.4.1, on a newer Graal compiler (`jvmci-25.3`). So the whole difference above is code
generation and runtime, not a JDK change. Part of it is **compressed references**, 32-bit instead of
64-bit object references, which the banner advertises and which is an **edition feature rather than
a flag**: `-H:±UseCompressedReferences` exists in Oracle GraalVM and in CE 25.3 and does not exist
at all in Liberica NIK (zero hits in `--expert-options-all`). Isolated by building CE 25.3 with it
off, on arm64 macOS: the flag itself is worth **3.3 MiB of binary and 1.7 MB of idle RSS, and no
measurable CPU**. Everything else -- the throughput, the halved CLI start -- is the compiler line.

One thing the 25.3 line does cost: it **expands the heap more eagerly under the same ceiling**. With
1,000 visitors held open the node peaks at 67 MB on linux and 69 on macOS against Liberica's 59 and
52, and it is sizing rather than live data -- at `-XX:MaxHeapSize=32m` the same run peaks at 59.8
and 53.7 with all 1,000 still served. The ceilings are left at 96m and 64m, since 88 MB of budget
holds either way; 32m is the lever if that ever binds.

**`-O3` was measured too, and is not adopted.** It needs no Oracle GraalVM and no profile, so it was
the one remaining free knob. Three runs of each on arm64 macOS, measured on the toolchain of the
time rather than the current one: the binary is 0.9 MiB smaller (29.1 and 29.3 against 29.9 and
30.2), warm request CPU is about 2% lower (101 µs against 104), handshake CPU and warm throughput do
not move (722/741/778 µs against 747/744/741), and **`jailscale status`
takes 20% longer to start** -- 7.6, 7.9 and 7.6 ms median against 6.2, 6.5 and 6.1, thirty samples
an arm, well outside anything else here that moved. `status` is a command a person types, so that
trade is the wrong way round. `-Dnative.optLevel=3` is the knob if a future measurement disagrees.
Note that `--pgo` turns `-O3` on by itself, which is one reason the PGO numbers above are not
comparable to a plain `-O2` build on size alone.

`./measure.sh --check` fails when a number exceeds its budget. The budget values live at the top of
the script and must match this table; they change only by a PR that states a reason. The `budget` job
of the `ci` workflow runs it with `LOAD=1000` on linux-amd64 for every push to main and once a
night; the macOS column is what `./measure.sh` reports on the machine this is developed on.

**The macOS column used to be a different toolchain's, and that is how two numbers here were
wrong.** It used to come from whatever GraalVM the development machine happened to have --
`brew`'s Community Edition -- while every release was built with something else (§3.2). On the same
source that is a 4.6 MiB difference: v0.1.0 shipped `jailhub-darwin-arm64` at 29.8 MiB and
`jailscale-darwin-arm64` at 30.1 against the 25.2 and 25.3 this table claimed, so the released
`jailscale` was over its own 30 MiB budget from the first release, and idle RSS was 24.7 here
against 29.0 for the binary people actually download. Neither could be caught, because the `budget`
job only runs on linux-amd64. `native.sh` now looks for the release's toolchain, says which one it
found, and refuses to guess; the budgets above were re-set against it. It also prints the command
that installs that toolchain, because none of the candidates is on Homebrew: GraalVM CE is published
as GitHub release assets under `graalvm/graalvm-ce-builds`, which is where `setup-graalvm` fetches
it from too.

The macOS column is still not enforced anywhere: a `budget` job there would need the runner to
raise its file-descriptor limit, which it refuses, so only 600 of the 1,000 visitors can be held.

**Throughput is reported and not gated.** Everything else here is memory, size or
one cold start, so a build that traded CPU for footprint had nothing to move, and neither the
edition question nor the compiler-line question above could even be asked. Both were then answered
by it, which is the case for keeping it. `measure.sh RATE=8`
drives `tools/throughput.py`, and what it reports is **server CPU per operation** rather than a
maximum rate. A maximum was the first design and it measured the wrong thing: offered 32 workers of
fresh handshakes, the hub completed exactly 7,000 in 5 seconds -- `NodeGroup.SIGN_BURST` of 2,000
plus `SIGN_PER_SECOND` of 1,000 for five of them -- and refused 7,908 more, which is §11.5's limiter
working and says nothing about a build. Handshakes are now offered at a fixed rate under that limit;
warm requests, which nothing limits, keep the rate as capacity.

| | arm64 macOS (14 cores) | linux-amd64 (4-core runner) |
|---|---|---|
| Handshake, hub CPU | 716 µs | 1,544 to 1,969 µs |
| Handshake, node CPU | 1,100 µs | 1,985 to 2,475 µs |
| Warm request, hub CPU | 101 µs | 71 to 92 µs |
| Warm request, node CPU | 113 µs | 79 to 105 µs |
| Warm requests a second | about 38,000 | 13,700 to 17,600 |

The linux column is a range because a GitHub runner instance is: the same commit and toolchain gave
17,560 warm requests a second on one and 13,732 on another, which is 22% and larger than most of
what this section compares. **Two arms of a comparison have to run in the same workflow**, which is
why every table above was measured that way; a number from one run against a number from another
run says almost nothing.

A handshake costs seven to twenty times a warm request on either side, which is the shape the design
predicts: one opens a stream, asks the hub for a signature bound to that stream (§9.2) and finishes
a TLS handshake on the node, while the other is a relay copying bytes. The per-operation figure is
steady against the offered rate -- on the previous toolchain, 200 a second and 400 a second gave the
runner 2,356 and 2,322 µs of hub CPU -- which is what makes it usable for comparing builds; the warm figure moved about 15%
between two runs of the same build, which is the noise any comparison has to clear. The client's own
CPU is printed beside each phase, because a load generator in Python can become the thing measured.

Two corrections came out of building it, both in the harness rather than the product. The local app
is an event loop that honours `Connection: close`: with keep-alive and a thread per connection,
1,000 held visitors became 1,000 Python threads, 900 of 1,000 were held instead of all, the peaks
rose from 53 and 69 MB to 76 and 100, and a four-core runner stopped finishing the phase at all.
Taking that server out of the path then showed how much of the warm figure had been the harness:
38,000 requests a second against 18,000, at 101 µs of hub CPU against 132. And
`tools/hold-visitors.py` times out every step now -- without that, a saturated node left it waiting
for a reply that never came, which is how a measurement becomes a hang instead of a number.

**Load is measured with the connections held open.** An earlier gate fired 1,000 short requests with
`curl --parallel` and finished, which means 1,000 were never alive at once and the figure was roughly
a third of the real number. `tools/hold-visitors.py` now keeps all 1,000 open and samples peak RSS
during that time, ramping in batches of 100 because bursts larger than the kernel accept queue are
reset before they reach jailscale. Structural ceilings that go with these numbers: 1,024 concurrent
visitors per name (`SniRouter.MAX_PER_NAME`), 20 links per node, up to 4 control connections per node.

---

## 15. Limits

- **A compromised hub can impersonate every name under its domain** (§11.2). Detectable (§11.3) but
  not preventable, because the hub is what decides name ownership.
- **The self-probe reaches one name every half hour** (§11.3), so at the 20-link ceiling a given name
  is looked at about every ten hours, and a tick is skipped entirely while the node is not connected
  to the hub. What bounds detection is that pass, not the tick.
- **The address check runs once, at startup, and its answer is only a log line** (§7.2). Nothing
  re-runs it and nothing keeps the verdict, so a record that changes afterwards -- a proxy switched
  on in front of the name, an edited A record -- is never noticed, and an operator who missed the
  line at boot has nowhere to look it up.
- **Delegated signing depends on reconstructing JSSE's ServerHello and EncryptedExtensions** (§9.2).
  The binding of a signature to the visitor's handshake is only as good as the node's ability to
  say what JSSE wrote, which it derives from the ClientHello, a fixed configuration and the
  randomness it recorded. A JDK that changes those encodings breaks every hub-signed handshake
  until the reconstruction is updated; it cannot weaken the binding, because the hub recomputes
  the hash itself, but it can take the service down. `TranscriptTest` exists to catch that at
  build time. Visitors are also confined to TLS 1.3 with X25519 for the same reason.
- **Raw TCP and UDP links are not end to end unless the app encrypts itself** (§8.4).
- **Raw UDP is UDP over TCP** (§8.4). Both ends really are datagrams, but the carrier is the node's
  one TCP connection, so a lost packet holds up every stream sharing it until the retransmit lands,
  and a sender out of window credits waits instead of dropping. Request-reply protocols over UDP are
  fine; latency-sensitive ones -- game netcode, WireGuard roaming -- get delivery they can rely on
  and a delay distribution they cannot.
- **User domains require port 80 on the hub.** The http-01 relay is the only verification path
  implemented; tls-alpn-01 would remove that requirement.
- **Upgrading stops one step short of automatic.** `jailscale update`, and the daemon's daily check
  behind `status`, say that a newer release exists; `update --download` fetches it and checks it
  against a signed `RELEASE.txt` (§9.4); the command that puts it in place is printed for the
  operator to run. A binary released before the signing key existed carries no key and refuses to
  download at all, so the first release able to verify another is the one after the key was
  compiled in.
- **Nothing signed says which release is current.** `update` learns that from `releases/latest`,
  which is not signed, and `RELEASE.txt` says which release it *is* rather than whether it is the
  newest. Whoever can publish can therefore keep a node that is behind on an older release -- one
  genuinely signed, so the whole chain verifies -- for as long as the index keeps naming it. What
  bounds the damage is that a node is never moved below what it runs (`newer` is strictly above the
  running version) and the binary installed is always the version announced, so this withholds an
  upgrade rather than forcing a downgrade, and the same party could equally delete the newer
  release. Closing it needs signed freshness: a sequence number the client refuses to go backwards
  on, or an expiring signed pointer to the current release. That is the piece of an update
  framework this design does not have.
- **A certificate that stops renewing is reported, not prevented.** Renewal is automatic on both
  sides at a third of the lifetime remaining. When it does not happen the node logs the name and
  the time left once a day inside the last fortnight, the hub says how long the installed wildcard
  has next to every issuance failure and on its status page, and `ls` marks the link. None of that
  helps a node that stays offline: renewal needs the hub, so the node that cannot renew is the one
  nobody hears from, and its domain goes dark when the certificate runs out.
- **Hand-off does not work under systemd** (§13). Upgrading a unit-managed hub is a restart, so it
  is not zero-downtime. Readiness reporting exists but is opt-in and is only about when systemd
  calls the unit started; the listening sockets are still rebound rather than handed over.
- **There is no standby hub.** Recovery is restoring one directory and changing DNS (§13).
  Active-active would need inter-hub forwarding, since the hub a visitor lands on and the hub a node
  is attached to could differ.
- **Windows spends a platform thread on every socket two threads use at once** (§3.2). Its poller
  loses events when one socket is parked for read and for write together (JDK-8334574), so one side
  of each of those sockets is kept off the poller there. Measured at about 60 KB per concurrent
  connection more than the virtual thread it replaces (66.6 KB against 6.7 KB, and a smaller
  `stackSize` does not move it), so 60 MB at a thousand connections and nothing worth counting at
  ten. Linux and macOS are untouched. New code that gives a socket two threads has to remember to
  do the same.
- **The CLI copies a link to the clipboard only when its stdout is a terminal, and that is verified
  on two of the three platforms that have a clipboard.** `Console.isTerminal()` is the question
  asked, rather than `System.console() != null`, which since JDK 22 is non-null for a redirected
  stream as well. The tests assert the negative direction everywhere — piped, nothing is copied —
  and that is the direction that would still pass if the detection were broken and the feature
  simply dead, so the positive direction has to be checked by hand against a real terminal.
  Done on **darwin-arm64** and on **linux-arm64**, both on the native binary, the second under
  `xvfb-run` with `script -q FILE -c` so that stdout is genuinely the pty: the CLI printed
  `<- copied to clipboard`, `xclip` held the selection, and the clipboard contained exactly the
  link that was printed. **windows-amd64 is unverified.** It is the platform where the feature is
  most certainly live — `clip.exe` is in System32, so it is always found — and the hardest to test,
  since there is no `script` and driving a ConPTY from CI is more machinery than a convenience
  feature is worth. A Linux node is usually headless and has no `xclip` at all, so there the
  feature is normally inactive whatever `isTerminal()` answers.

- **A node's visitors are first come, first served, so one name can starve the others on it, and
  whether that is a delay or a blackout is decided by the neighbour's connection lifetime.** The
  bound of §9.3 is per node, and a node may serve up to `MAX_LINKS_PER_NODE` = 20 links; nothing
  shares the 450 between them. Measured in `docs/name-starvation`, one node bounded at 20 with two
  names on it, the quiet name trying 40 times:

  | the busy name | the quiet name gets |
  |---|---|
  | holds its connections (SSE, websockets, a large download) | **0 of 40, three runs of three** |
  | answers and releases (~1,500 requests in 5 s) | 34, 39, 35 of 40, at 4–27 ms |

  So a busy neighbour is survivable and a neighbour that *holds* connections is not: every other
  name on that node is dark for as long as it stays saturated, by ordinary product behaviour rather
  than by abuse. This is not new with the hub-side admission — it is how the node's own bound
  behaved from the day it existed, and before that the same load took the whole node down with an
  `OutOfMemoryError` — but it is now a deliberate first-come rule rather than an accident of where
  the allocation failed.

  **Nothing is built, and two of the three ways to fix it are wrong.** Static partitioning
  (`bound / links`) idles capacity in the common case, where one name is busy and the rest are not:
  450 split three ways stops the busy name at 150 with 300 free. Eviction has no defensible victim —
  §5.3's budget can point at a stream that has consumed nothing for two seconds, where every visitor
  on a node is making progress. What is left is holding back a few slots per name, paid for only
  while a node is saturated, which is already a degraded state. The measurement above does not size
  it: the fraction reserved is what matters, and 2 of 20 is not 2 of 450.

- **At its bound a node refuses well-behaved visitors and abusive ones alike**, because the hub
  cannot tell them apart before admitting them. That is the cost `FlowBudget` names in its argument
  for reclaiming rather than refusing (§5.3), and the node cannot take that way out: a visitor's TLS
  state is live for as long as the visitor is, so there is no stalled connection to pick. **The
  denial is also quieter than what it replaced.** Filling a node used to end in an
  `OutOfMemoryError`, a dropped hub connection and a reconnect — an outage, but a loud one. Now the
  node sits full, logs one line a minute, and turns everyone away. What it costs an attacker is
  bounded by `MAX_PER_IP` = 64, so filling a 450-visitor node takes eight addresses; that per-address
  cap is the only thing making it cost anything at all, and it was not written for this.

- **The hub believes what a node says about its capacity, and that is safe only because a lie is
  self-punishing.** A node that names a number larger than it can hold gets the behaviour of a node
  that names nothing: the hub stops refusing on its behalf and the node's own bound resets what it
  cannot take. A node that names a smaller one gets less traffic. Neither reaches another node's
  visitors, so nothing validates the figure — with one exception, which is that the hub sums it
  across nodes for a gauge, and that sum is a `long` so two hostile advertisements cannot wrap it
  negative onto the hub's own page.

- **What the node holds per visitor has a number now.** `jailscale status` reports
  `visitorsInFlight`, the visitor streams the node is serving at this instant, TLS and raw alike.
  It is the node's half of the hub's `jailhub_visitors_in_flight` (§6.3) and it exists because the
  node's cost is per visitor -- tens of kilobytes of TLS state each, below -- while the only number
  available was RSS, which cannot tell visitors from a leak or from the heap expanding into its
  ceiling. The count is taken around the whole of `Visitors.serve`, not around the `TlsEndpoint`:
  several paths abandon a visitor without closing the endpoint, and a count that leaked on those
  would invent visitors that are not there. It is now also what the bound of §9.3 is taken
  against, and `status` reports the bound (`visitorCeiling`) and how many it has turned away
  (`visitorsRefused`) beside it: in flight on its own cannot tell a busy node from a full one, and
  those are different problems with different answers.

- **What the kernel holds per stalled visitor is bounded on the node and not on the hub.** The node
  gives its app socket the stream window (§9.3). The hub's visitor sockets autotune, so a visitor
  that stops reading can leave the kernel's full send buffer behind on the hub's machine, and a
  thousand of them is gigabytes asked of a host with 969 MB -- which Linux answers machine-wide with
  `tcp_mem`, about 87 MB there, by making every socket wait. That is the failure the node just had,
  on the hub, and it is not fixed the same way because the same fix costs what the node's does not:
  pinning the send buffer caps a far visitor's download at the window over its round trip, 20 Mbit/s
  at 100 ms. The right bound scales with the visitor's measured round trip, and nothing measures it.
- **A visitor's handshake can wait on a machine that has run out of network memory, and nothing here
  says so.** This entry used to put that wait on the multiplexer -- a `SignResponse` queued
  behind other visitors' data inside `NoiseChannel`'s one write lock -- and name the fix as a writer
  that puts control frames in front of data. That writer was built (§5.3) and **the wait survived
  it**: under `SLOW=400` an ordinary visitor still took 12 to 17 s while the node's own socket write
  blocked for 3.2 s. The cause was the machine and not the session. The kernel's socket memory was at
  its cap, so every socket on the host froze while both processes' timers reported idle, which they
  were; §5.3 and §14 carry the measurements, and the multiplexer's own head-of-line cost with 400
  stalled streams behind one socket is 22 ms of queue wait and 16 ms of socket write over 81,000
  frames.

  What remains a limit is the blindness. Neither end can see that condition from the inside, because
  a write blocked on the machine looks exactly like a slow peer, so the only signals are indirect:
  the node logs a signature that took longer than `RemoteSigning.SLOW_SIGN_MS`, and `measure.sh`
  samples `netstat -m` through the phase and prints the peak and the allocations the kernel refused.
  Nothing gates on either. It was also intermittent at the occupancy that produced it, two of four
  runs on the same binaries, so one clean run says nothing about the next.
- **Node idle RSS is about 25.0 MB, not the 20 MB originally aimed at**, and about 34.4 MB as
  Linux counts it (§14: mostly the mapped binary, 2 MB of it anonymous). This entry used to say that
  roughly 7.6 MB of it was JSSE standing up one TLS client, and to price two levers against that
  figure. `docs/jsse-idle-cost` took the figure apart, and it is the wrong thing to aim at.

  **Almost none of it is memory the process owns.** From a daemon that has never built an
  `SSLContext` to one connected with a link open is 8.0 MB of RSS and **1.5 MB of written pages**;
  +3.7 MB is the binary's own `__TEXT` becoming resident with zero dirty pages in it, and +2.0 MB
  its image-heap mapping, 288 KB of that dirty. Standing JSSE up at all is 2.6 MB of RSS for
  **139 KB written**. The cost is code executing for the first time out of a 26 MiB binary, page by
  page, and those pages are clean, file-backed and evictable. There is no megabyte of dirty memory
  here for any TLS work to recover.

  **And it is not all TLS.** 2.0 MB of the 8.0 is the join — `/v1/key`, the join request, the first
  certificate — which `measure.sh` samples because it measures idle in the daemon that just
  performed it; the same node restarted idles at 23.1 MB. Another 3.2 MB covers the TLS handshake
  together with the Noise handshake, the multiplexer, the HTTP upgrade and the registration, and
  nothing separates them.

  So the levers this entry used to name are both mispriced. There is still no build-time
  initialisation whitelist to widen, because the build configures none (§3.1), and the classes worth
  moving would still be JSSE's, which is the neighbourhood JCE has to stay out of — but what a
  whitelist would move is initialisation work, and the measurement says the cost is layout. §14
  already measured the lever that does address that, from the other side: profile-guided builds
  carry idle RSS down about a fifth, which is the same code laid out so that less of it has to be
  resident. That gain was measured against the 25.0-line builds and is smaller against what ships
  now, and §14 gives the reasons PGO is not what releases use; the point here is only that the
  lever which moves this number is layout, not initialisation.
- **The idle budget measures a trust configuration nobody ships, and it is worth about half a
  megabyte.** `measure.sh` always joins with `--ca-file`, so every published idle figure describes a
  node whose trust manager holds two certificates. A node joined to a hub with an ordinary web-PKI
  certificate — every real deployment, the live hub included — leaves `caFile` null and JSSE builds
  its default trust manager over the store `native-image` baked into the binary.
  `docs/jsse-idle-cost/truststore.sh` measures that by building a second image whose embedded store
  also trusts the test certificate, so a loopback hub validates through the same path a public CA
  would: **+0.55 MB of RSS and no measurable written memory** (a second build against a larger store,
  sampled with a link open, read +0.81; the range is half a megabyte to eight tenths). Against the
  join's 2.0 MB the other way, a restarted node on a public-CA hub settles near 23.7 MB, below the
  25.0 published rather than above it.

  **The number was 2.5 MB here until that second binary existed**, from a pair of handshakes that
  were both rejected by PKIX and differed only in their anchors. Failing a path build is not the
  shipped path — it builds and abandons candidates and runs code a successful validation never does.
  A run-time `-Djavax.net.ssl.trustStore`, which the binary does honour, is wrong the other way and
  reads +5.7 MB, because it parses a PKCS12 file into the heap where the shipped node has its
  anchors in the image heap already. Both were believed; `truststore.sh` carries the reasons.

  What remains true is that no budget sees this, and that it is small. Dropping certificate
  validation on the control channel altogether — which the node could do, since it pins the hub's
  Noise static key (§5.2) and authenticates the channel with it — buys **1.06 MB**, 4% of idle RSS
  and none of it written, against giving up a layer the pin does not replace on first contact.
- **Per-visitor memory on the node is about 99 KB.** Live bytes after a full GC, from a heap
  histogram taken with a known number of visitors in flight. It is the only figure here that counts
  what JSSE keeps behind the `SSLEngine` as well as what this project allocates itself.

  What holds it: `TlsEndpoint`'s packet buffer (16,709 bytes) and application buffer (16,704), both
  for the life of the connection, one 16 KiB copy array for the local-to-visitor direction, the
  engine's own record buffers, and whatever frame is in flight. A **gated** link (§9.3) adds a 4 KB
  buffer for the request head, so 4 MB at the 1,024-visitor ceiling; against an ungated link under
  the same load it does not rise above the run-to-run variance of the figure in §14.

  **There are two scales in this entry and they do not agree.** Adding up the buffers this project
  allocates gives about 60 KB, and §14's `netInBuf`/`appInBuf`/engine estimate gives 50 to 60 KB;
  both count allocations made here and neither counts what the engine keeps behind itself, which is
  why they read low against the histogram. Use 99 KB for what a visitor costs the process, and the
  breakdown for what a change to these buffers can move.

  **It was 118 KB until the plaintext stopped being copied on its way to the local app**, on the
  histogram scale: 96 visitors held 11,343,672 bytes of arrays before and 9,769,672 after, which is
  16.4 KB each and exactly the buffer that went. On the counted scale the same kind of change had
  already taken it from about 67 KB to 60, when the wrap destination stopped being a third
  per-connection buffer. That one was **not** per-connection work: `wrapAndWrite` clears it on entry
  and has written every byte out before it returns, so it belongs to the wrap, and instrumenting the
  1,000-visitor load showed 256 wraps in flight at the busiest moment. The other 744 connections were
  each holding 16,709 bytes they were not using. Sharing them through a small pool moved the node's
  figure in §14 from a mean of 91.8 MB over seven runs to 84.8 MB, and — the larger effect — from a
  14.6 MB spread between runs to 1.1 MB, because the heap high-water no longer depends on where the
  GC happened to fall during the ramp. What remains is genuinely per-connection: a partly-arrived TLS
  record and plaintext nobody has read yet both have to survive between calls.

  **RSS does not move when these figures do** -- the node peaked at 85.5 and 82.0 MB under
  `SLOW=400`, against 83.3 to 86.8 before -- because a collector working to a 64 MB ceiling sizes its
  footprint from the ceiling and not from the live set. That is why per-visitor cost is counted here
  rather than weighed, and it is the same reason the relay buffer's size looked like a lever and was
  not (below).

  **Pooling the other two would not work, and the 256 KB stream window is not the lever either.**
  Buffers a connection holds between calls are needed by every open connection at once, so a pool
  of them is the same memory with a free list in front. That applies to `Relay`'s copy buffers in
  particular: they are the destination of a blocking `read`, held across the block, so every open
  direction needs its own at once and a pool cannot lower the live set. The levers there are the
  buffer's size, or not copying at all in the node-to-visitor direction -- the bytes are already a
  private array in the stream's queue, put there by `Frame.decode`, so they can go to the socket
  without an intermediate. The visitor-to-node direction has no such shortcut: a socket read needs
  somewhere to land.

  **The second lever is taken, and not for the reason it looked like.** `MuxStream.writeTo` writes a
  queued chunk straight to a socket and `Relay` uses it node-to-visitor. Throughput is unmoved --
  37,444 requests a second against 37,805 for the buffered copy, which is the run-to-run spread --
  because the warm measurement moves small responses, where a 16 KB `memcpy` is not what costs.
  What it buys is that **the bound stops lying**. `read` releases a chunk from the budget at the
  moment it copies it into the caller's buffer, so bytes waiting on a visitor that has stopped
  reading are still held, still costing the process, and no longer counted: one buffer per stalled
  visitor, megabytes at the concurrency §5.3 exists to survive. `writeTo` leaves the chunk queued
  and charged until the socket has taken it -- look under the lock, write outside it, then remove
  and account under the lock again -- so a write that throws leaves the chunk where it was.

  The price is a narrower contract than `in()` has: **one thread may drain a stream**, because a
  second would write a chunk the first has not removed yet. Both relays give a stream one thread per
  direction, and a second caller is refused rather than left to duplicate output.

  **Measured, the size is not a lever either.** At 4 KiB against 16 KiB the hub's peak under `SLOW=300`
  came out 92.0 MB, then 58.9 MB, against 63.9 MB for the buffer it ships -- the spread at one fixed
  size is several times the 7 MB the arithmetic says the change is worth, so RSS cannot see it. It is
  not only invisible: a smaller buffer drains the receive queue in smaller pieces, so the queue
  stays fuller, which pushes the number the other way. `LOAD=` cannot see it at all, and that is
  worth knowing about the harness: those visitors send `Connection: close`, so the app answers, the
  node closes, and **the relay is over before the sample** -- the hub is holding sockets in the
  linger wait (§8.1), not copy buffers. `jailhub_visitors_in_flight` reads 0 through the whole of
  `LOAD=1000` and 301 through `SLOW=300`, which is the two axes saying what each of them measures.

  The window caps what may sit queued (§5.3), not what is allocated, so a visitor whose reader keeps
  up holds none of it; shrinking it would lower single-stream throughput, which is bounded by the
  window divided by the round-trip time. **A visitor whose reader stalls is the case this paragraph
  used to miss.** It said the load measurement never fills the window, which was true of `LOAD=` and
  is why the gap survived: `SLOW=` fills it completely (§14), and what answers that is the receive
  budget of §5.3 rather than a smaller window, for the reasons given there.
