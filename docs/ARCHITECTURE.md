# jailscale architecture

A self-hosted HTTPS tunnel. A node runs `jailscale open 3000`, and
`https://<name>.<hub-domain>` starts serving whatever listens on that node's local port.
Visitors install nothing. The hub reads the TLS SNI and forwards ciphertext; the node
terminates TLS and asks the hub for one signature per handshake.

This document describes the system as it stands. It is organised by subsystem, not by
history. Section numbers are stable and can be linked to.

- [1. Scope](#1-scope)
- [2. Pieces and how they fit](#2-pieces-and-how-they-fit)
- [3. Modules and build discipline](#3-modules-and-build-discipline)
- [4. Keys and identity](#4-keys-and-identity)
- [5. Control channel](#5-control-channel)
- [6. Control API and hub state](#6-control-api-and-hub-state)
- [7. Certificates and ACME](#7-certificates-and-acme)
- [8. Public ingress](#8-public-ingress)
- [9. The node](#9-the-node)
- [10. Joining](#10-joining)
- [11. Security model](#11-security-model)
- [12. Threading and memory](#12-threading-and-memory)
- [13. Availability and hand-off](#13-availability-and-hand-off)
- [14. Current characteristics](#14-current-characteristics)
- [15. Limits](#15-limits)

---

## 1. Scope

### What it is

One server you own, one binary on it (`jailhub`), one binary on each machine that wants to
publish something (`jailscale`). It does what ngrok, Cloudflare Tunnel and Tailscale Funnel
do, without a third party in the path.

Three principles, in priority order.

1. **Lightweight.** The node is a resident daemon. Single executable, no runtime
   dependency, small idle footprint, CLI round trips in milliseconds. The numbers are
   measured and enforced by a CI gate (§14).
2. **Usability.** Publishing is one line (`jailscale open 3000`). Inviting is one line
   (`jailscale invite`). The hub operator sets three DNS records and opens two ports. Any
   change that lengthens that setup list is treated as a regression.
3. **Portability.** No root, no TUN device, no kernel module, no inbound port and no UDP on
   the node side. A pure-JVM fallback JAR ships alongside the native binaries for platforms
   the native build does not cover.

### What it is not

- A peer mesh VPN. Nodes do not reach each other privately.
- Wire compatible with Tailscale, ngrok or frp.
- HTTP/2 or HTTP/3 on the visitor side. Browsers speak HTTP/1.1 fine and local apps behind a
  node are usually HTTP/1.1 anyway.
- An Android or iOS client.

---

## 2. Pieces and how they fit

```
   visitor browser                       jailhub (one process)                     jailscale node
   https://myapp.hub.example.com     ┌──────────────────────────────────┐      ┌──────────────────────┐
          │                          │  :443  SNI router                │      │ TLS termination      │
          │  TLS ClientHello         │   ├ hub.example.com -> own HTTP  │ mux  │  ├ signing delegated │
          ├─────────────────────────>│   ├ *.hub...       -> node stream├─────>│  ├ visitor gate      │
          │  (ciphertext passes      │   └ user domain    -> node stream│Noise │  └ plaintext to      │
          │   through untouched)     │                                  │ in   │     127.0.0.1:3000   │
          │                          │  coordinator: invites, names     │ TLS  │                      │
          │                          │  ACME: wildcard via own DNS-01   │<─────│ CLI <-> daemon       │
          │                          │  :53  _acme-challenge TXT        │      │      (AF_UNIX)       │
          │                          │  admin: IPC + /admin web         │      └──────────────────────┘
          │                          │  signing service: wildcard key   │
          │                          └──────────────────────────────────┘
```

Three decisions shape everything else.

- **The hub only reads SNI.** It peeks the ClientHello on port 443, finds the name, and hands
  the byte stream to the node that owns it. It never parses visitor HTTP. The internet-facing
  attack surface of the hub is a TCP-level parser, and the hub sees only ciphertext.
- **The node terminates TLS but does not hold the key.** Every name under the hub domain is
  covered by one `*.hub.example.com` wildcard certificate. The private key never leaves the
  hub. The node asks the hub for the single handshake signature, and the hub only signs when
  the request is bound to a stream it delivered to that node (§9.2).
- **The node does not parse HTTP either.** It strips TLS and copies plaintext to the local
  port. HTTP/1.1, WebSocket, SSE and chunked bodies all pass because the local app handles
  them. The only HTTP parsers in the system are a small one for the control channel and the
  first-request-head read that the visitor gate needs.

**Ports.** TCP 443 for everything, UDP and TCP 53 for the ACME DNS-01 answers. TCP 80 is
optional (HTTPS redirect, and the http-01 relay that user domains need). Raw TCP/UDP
publishing adds one port range. The node needs outbound 443 and nothing else.

**Terminology.** A local port exposed to the internet is a **link**. Open one with
`jailscale open`, close it with `close`, list them with `ls`. An *invite link* (§10) and a
*visit link* (§9.4) are different things.

---

## 3. Modules and build discipline

Maven multi-module, dependencies flowing one way only. Java packages are `io.jailscale.*`.

| Module | Contents |
|---|---|
| `crypto` | BLAKE2s, HMAC, HKDF, X25519, ChaCha20-Poly1305, Noise IK, key encoding |
| `proto` | control messages and JSON codec, mux framing, minimal HTTP/1.1, SNI parser, ACME client, PROXY protocol, IPC, logging |
| `node` | daemon, CLI, local IPC, TLS termination, remote-signing provider, gate. Builds the `jailscale` binary |
| `hub` | SNI router, coordinator, ACME and DNS responder, signing service, admin IPC and web. Builds the `jailhub` binary |

Two binaries rather than one so that server code never lands in the client artifact. The
module boundary makes a dependency inversion a compile error rather than a review comment.

### 3.1 GraalVM Native Image rules

Every rule below is followed from the start, not retrofitted. Together they are the reason
the binaries are one file with no reachability metadata and no third-party jars.

| Item | Rule | Why |
|---|---|---|
| Reflection | Forbidden | Metadata upkeep and binary bloat |
| Dynamic proxies, dynamic class loading | Forbidden | Effectively impossible under native-image |
| DI framework | None; constructors wired by hand | Spring and Guice are reflection engines |
| JSON | Own parser and hand-written encoder (`proto`) | Jackson means reflection and megabytes; there are only about a dozen message schemas |
| HTTP server | Own minimal HTTP/1.1 (`hub`, five endpoints on its own name) | `com.sun.net.httpserver` will not hand the socket back after an Upgrade |
| HTTP client | Own HTTP/1.1 over `SSLSocket`, with chunked decoding | Needed for Upgrade; also keeps `java.net.http` out of both binaries |
| TLS | JDK JSSE. `SSLServerSocket` on the hub, `SSLEngine` on the node | Already in the binary |
| Remote signing | Own JCE `Provider`, opaque `PrivateKey`, `Signature` SPI | The same path PKCS#11 keys take. Registered by overriding `Provider.Service.newInstance`, so no reflection |
| ACME client and DNS responder | Own, in `proto` and `hub` | JWS ES256, JSON and HTTP are covered; only the PKCS#10 DER encoding and the DNS TXT answer are hand-written |
| Logging | Own small logger over `System.Logger` | SLF4J plus logback means ServiceLoader and reflection |
| Cryptography | JDK JCE for X25519 and ChaCha20-Poly1305; own BLAKE2s, HMAC, HKDF | BouncyCastle is large and awkward under native-image. The three hand-written pieces are forced: the JDK has no BLAKE2s, and Noise defines HMAC and HKDF over the chosen hash, so choosing BLAKE2s drags both in. Noise's HKDF also differs from RFC 5869 (an output counter byte instead of salt/info, at most three chained outputs) |
| AWT, `java.awt.Desktop` | Forbidden | Browsers are opened with `open`, `xdg-open` or `rundll32 url.dll,FileProtocolHandler` through `ProcessBuilder` |
| Inter-process communication | AF_UNIX (`UnixDomainSocketChannel`) on every platform | Windows 10 1803+ supports AF_UNIX; named pipes have no public JDK API |
| Threading | Virtual threads throughout | There is no packet hot path. One thread per stream direction is enough (§12) |
| Build-time initialisation | Whitelisted, carefully. JCE initialises at run time | Prevents freezing a SecureRandom seed into the image |

### 3.2 Build

- **Maven**, not Gradle. With zero third-party dependencies there is nothing for Gradle's
  dependency and build-logic flexibility to do, and a fixed lifecycle has less room to drift
  across five platforms. `native-maven-plugin` is maintained by the GraalVM team.
- `./mvnw` runs in **only-script** mode. Unlike the Gradle wrapper it commits no binary jar
  to the repository: a project that ships signed binaries should not carry a jar whose
  provenance it cannot check itself. The Maven distribution it downloads is pinned with
  `distributionSha256Sum`, and a wrong value makes the wrapper refuse to run. Keeping the
  supply-chain surface at zero is the point of this whole section.
- Default profile is a plain JVM build for fast `mvn test`. `-Pnative` produces the binaries;
  `crypto` and `proto` are skipped there.
- CI matrix: linux-amd64, linux-arm64, macos-arm64, macos-amd64, windows-amd64. Every release
  also ships a fallback `jailscale.jar` and `jailhub.jar` that need JVM 25.

### 3.3 Toolchain notes

- GraalVM CE 25.3.x (JDK 25.0.x) for native builds; JDK 25.0.3 or newer for ordinary builds.
- **Do not use JDK 25.0.0 through 25.0.2.** Moving virtual-thread timed park onto ForkJoinPool
  delayed tasks (JDK-8351927) introduced two regressions: cancelling a delayed task corrupts
  the scheduler heap so other threads' `Thread.sleep` wakes late or not at all (JDK-8370887),
  and virtual threads get stuck PARKED (JDK-8369227). Both are fixed in 25.0.3. Hand-off
  cancels the old connection's keepalive sleep by interrupt, which is exactly that path. The
  release workflow therefore builds on Liberica NIK (JDK 25.0.4+).
- **On Windows, virtual threads can miss a bidirectional loopback read.** The reader parks and
  never wakes. It reproduces without any jailscale code, so it is not fixable here; it is
  handled by detection and recovery instead. The 60 s read timeout on the mux socket (§5) and
  the 25 s keepalive (§5.3) close the session with `peer idle too long`, and the node
  reconnects. Repro and measurements live in `docs/windows-virtual-thread-stall/`.

---

## 4. Keys and identity

| Key | Held by | Purpose | Lifetime |
|---|---|---|---|
| **MachineKey** (`mkey:`) | node | Noise static key of the control channel client. The machine's identity, and its `/admin` login identity | Life of the machine |
| **hub key** (`hkey:`) | hub | Noise static key of the control channel server. Pinned by nodes | Rotatable (§5.2) |
| **Wildcard certificate key** | hub | ECDSA P-256 for `hub.example.com` and `*.hub.example.com`. **Never leaves the hub** | New key on each ACME renewal |
| **User domain key** | node | Certificate key for a domain the user brought (`myapp.com`). Not on the hub | New on each node-side renewal |

A node's identity is its MachineKey alone. Node id and name ownership hang off it; rejoining
through another user's invite changes only the owner.

**Encoding** is `prefix:base64url-nopad`. The prefix makes the key type visible in logs and
config files, and catches a key pasted into the wrong slot at parse time.

**Storage.** Node state is `node.json` (mode 0600) in `$XDG_CONFIG_HOME/jailscale/`, or
`%LOCALAPPDATA%\jailscale\` on Windows; `$JAILSCALE_HOME` overrides both. User domain keys and
certificates sit beside it under `domains/`. Hub state is described in §6.2.

---

## 5. Control channel

### 5.1 Noise inside TLS

Node to hub traffic is a Noise_IK channel opened inside a web-PKI TLS connection. The carrier
is an HTTP/1.1 Upgrade; after the 101 it is just a byte stream, and the multiplexer (§5.3)
rides on top.

```
TCP 443, SNI = hub.example.com
 └─ TLS 1.3, ALPN http/1.1        (web PKI: authenticates the hostname, bootstraps first trust)
     └─ HTTP/1.1 Upgrade          POST /v1/noise, Upgrade: jailscale-control-v1
         └─ Noise_IK              (MachineKey <-> hub key; holds without trusting any CA)
             └─ [2B len BE][Noise transport message]   <- one mux frame inside each
```

The JDK's HTTP stack cannot be used at either end: `com.sun.net.httpserver` does not give the
socket to the handler after an Upgrade, and `java.net.http.HttpClient` does not hand back the
connection after a 101. Both sides are therefore hand-written. The hub's front is about 300
lines and serves `/v1/key`, `/v1/noise`, `/join/<token>`, `/admin/*` and a root page. The
node's client is about 40 lines.

WebSocket was rejected as the carrier: the JDK client's convenience does not survive contact
with a 40-line client, the 4-byte client-to-server masking would touch every visitor byte one
more time, and frame headers, fragmentation and close semantics come with it. It would also
only help behind proxies that pass `Upgrade: websocket`, and SNI passthrough already rules out
an HTTP proxy in front of the hub (§7.2).

ALPN is pinned to `http/1.1` through `SSLParameters`, because HTTP/2 has no Upgrade.

**Noise parameters.** `Noise_IK_25519_ChaChaPoly_BLAKE2s`, prologue `jailscale-control-v1`.
The version string in the prologue is mixed into the handshake hash, so incompatible versions
fail the handshake outright rather than later. A Noise transport message is at most 65535
bytes, which is why the length prefix is two bytes.

**Why keep the TLS.** Noise alone authenticates the control channel. TLS stays for three
reasons: the hub key bootstrap needs some reason to trust a first contact, and web PKI is it;
`/join` and `/admin` are browser paths; and corporate firewalls pass TLS on 443 while dropping
unidentifiable binary streams. The hub obtains the certificate itself, so this costs the
operator nothing.

**Why put Noise inside it anyway.** The web PKI threat model still contains CA compromise and
the corporate MITM proxy with its root installed. Both defeat TLS; neither defeats a Noise
handshake against a pinned hub key. This is the same shape as Tailscale's ts2021. It matters
here because **signature delegation flows over this channel** (§9.2): requests and responses
for the wildcard key need authentication that does not depend on a CA.

### 5.2 Hub key bootstrap and rotation

A node needs to know one hostname, which the invite link carries.

```
1. jailscale up --invite https://hub.example.com/join/...
2. GET https://hub.example.com/v1/key            (plain TLS, verified against web PKI)
     -> { "hubKey": "hkey:...", "nextHubKey": null, "notAfter": 1789000000 }
3. the node pins that key in node.json
4. POST https://hub.example.com/v1/noise         (HTTP/1.1 Upgrade inside TLS)
     -> Noise_IK against the pinned key
5. every later connection uses the pinned key. A mismatch is a hard failure with a warning
```

Rotation. `jailhub key rotate --grace 30d` generates a next key. Every connected node is told
over the control channel with `HubKeyRotation{nextHubKey, activatesAt}`; it arrives inside a
channel already authenticated by the old key, so it needs no separate signature. During the
grace period the hub accepts handshakes under either key (the responder simply tries each
candidate static key against message 1; only the right one decrypts). The node tries the
current key and falls back to the next. After `activatesAt` the hub drops the old key. A node
that never connected during the grace period fails with both, and only then is the operator
asked to re-trust the hub and re-bootstrap through `/v1/key`. An unattended node stays in the
failed state and logs why.

`--hub-key hkey:...` skips the `/v1/key` fetch for air-gapped or PKI-distrusting deployments.
Since Noise then completes server authentication on its own, relaxing TLS verification for the
control channel loses nothing there. Passing the hub key as a clickable `https://...?key=` URL
is deliberately not supported: people do not verify things that look like links. An invite is a
secret, so a link is the right carrier; a hub public key must be checked, so a link is the
wrong one.

### 5.3 Stream multiplexer

One Noise channel carries many byte streams. One visitor connection is one stream. The
protocol is roughly at the level of yamux and is about 500 lines.

Frame layout: `[4B streamId][1B type][1B flags][2B len][payload]`. Exactly one frame goes
inside one Noise message. DATA payloads are capped at 16 KB; filling 65535 would let one stream
monopolise the channel. A stream whose `DGRAM` flag is set treats one DATA frame as one
datagram (§8.4).

| Type | Payload | Direction | Meaning |
|---|---|---|---|
| `OPEN` | `{linkId, kind, sni, visitorAddr, visitorPort, keyId}` JSON | H->N | The hub delivers a visitor connection |
| `DATA` | bytes | both | Stream data |
| `WINDOW` | `[4B delta]` | both | Flow-control window increase |
| `CLOSE` | none | both | Half close (a FIN) |
| `RST` | `[1B reason]` | both | Forced teardown |
| `CTRL` | JSON | both | **Stream 0 only.** The messages of §6 |
| `KEEPALIVE` | none | both | Every 25 s; the socket read timeout is 60 s |

- **Flow control** is per stream: a 256 KB receive window, refilled with a `WINDOW` frame once
  half of it has been consumed. A sender out of credit stops. This is what stops one slow
  visitor from stalling the others. There is no retransmission, because this runs over TCP.
- **Stream ids.** The hub opens even ids, the node odd ones. Zero is control. The node does not
  currently open any; the parity rule is enforced on receipt so a peer cannot claim ids that
  are not its to allocate.
- **Multiple connections per node.** Putting every stream on one TCP+TLS connection means
  head-of-line blocking on loss and a ceiling of one TCP flow's throughput. A node may open
  N connections, default 1 and up to 4 with `--connections`. Each is a complete Noise channel
  and announces its index in `Hello{conn}`. The hub treats all connections with the same
  MachineKey as one **group**. Stream 0 exists only on connection 0. A visitor stream goes to
  the least loaded connection in the group. Stream ids are globally disambiguated as
  `(conn << 24) | localId`, so the hub always knows which connection a stream belongs to. If
  connection 0 dies, the whole group is torn down and the node reopens it.
- A second connection with the same MachineKey and the same `conn` index wins; the old one is
  closed with `Goodbye{shutdown}` and its streams are reset.
- `TCP_NODELAY` is set on the connection socket.

---

## 6. Control API and hub state

### 6.1 Messages

JSON on **stream 0** of the multiplexer. Every message is `{"t": "<type>", ...}`.

| Message | Direction | Role |
|---|---|---|
| `Hello` | N->H | First message after the handshake. `proto`, `version`, `os`, `conn` |
| `HelloResponse` | H->N | `proto`, `minProto`, `version`, `dnsSuffix` |
| `Goodbye` | both | `reason`: `upgrade-required`, `revoked`, `shutdown`, `draining`, plus optional human `detail` |
| `RegisterRequest` | N->H | hostname, os, self-chosen user, and one of `invite` / `code` / `authKey`, or none to knock |
| `RegisterResponse` | H->N | `approved{nodeId, user}`, `pending`, or `rejected{reason}` |
| `CertUpdate` | H->N | Wildcard chain (public part) and its `keyId`. On connect and on renewal |
| `LinkOpen` | N->H | `kind: https\|tcp\|udp`, optional `name`, `domain`, `port`, the local target, and for user domains the certificate chain |
| `LinkOpened` | H->N | `linkId`, `name`, `url` or `hubPort`, or a rejection reason |
| `LinkClose` | N->H | Stop serving (name and port ownership survive) |
| `LinkRevoked` | H->N | A name, domain or port is no longer served by this node (§11.5) |
| `SignRequest` / `SignResponse` | N->H / H->N | `streamId`, `keyId`, `alg`, `digest`; then the signature or a reason (§9.2) |
| `ChallengeSet` / `ChallengeClear` | N->H | Register or drop a user-domain http-01 token (§8.3) |
| `InviteCreate` / `InviteCreated` | N->H / H->N | A member node issuing an invite (§10.2) |
| `AdminLinkRequest` / `AdminLink` | N->H / H->N | One-shot `/admin` login URL for an admin node |
| `HubKeyRotation` | H->N | §5.2 |
| `Ping` / `Pong` | both | On-demand round-trip measurement (`jailscale netcheck`) |
| `Ack` / `Error` | H->N | Generic replies for requests with no result of their own |

**Versioning.** `proto` versions the message schema and the frame set together. The hub accepts
`minProto` and above. Below that it answers `Goodbye{upgrade-required}` **as the handshake
reply**, which means the node never sees a `HelloResponse` and cannot learn `minProto` or the
hub version from it. So `detail` carries the required protocol number, the hub version and what
to do next; the node prints it verbatim, stores it in `jailscale status` as `lastError`, and
stops reconnecting. A one-word reason in a log leaves the user with nothing to act on. A node
that announces a newer `proto` than the hub drops to the hub's. The number in the Noise
prologue changes only when the Noise parameters change.

### 6.2 Storage

File based: an append-only JSON Lines event log plus in-memory state, replayed at startup.

```
$JAILHUB_STATE/            (default /var/lib/jailhub, else ~/.local/share/jailhub)
├── hub.key                hub static private key (0600); hub.key.next during a rotation
├── state.jsonl            event log (node-registered, name-claimed, invite-created, ...)
├── state.snapshot         periodic snapshot (log compaction)
├── jailhub.lock           process lock; a second `jailhub serve` fails immediately
├── jailhub.sock           admin IPC socket (§6.3)
└── tls/                   account.key, wildcard.key, wildcard.pem, wildcard.key.prev (0600)
```

Events are fsynced. Snapshots are written to a temporary file and renamed into place.
`jailhub serve` is the only writer; admin commands ask the running server over IPC.

**Format version.** The snapshot carries a `v`, and the hub **refuses to start** when it is
higher than the version it understands. Adding fields or new events within a version is
compatible in both directions, and unknown events are skipped with a warning, so a rollback is
safe within that range. `v` is bumped only for changes that would make an older binary
*misread existing data*. A hub that cannot read its state should stop rather than come up
holding part of it.

In-memory state is maps: nodes by MachineKey, names, user domains, raw port assignments, invite
and auth-key hashes, admins, the pending queue, and undelivered revocation notices. Maps are
overwhelmingly the simplest thing up to thousands of names.

### 6.3 Admin IPC and admin web

`jailhub node approve`, `jailhub invite create`, `jailhub key rotate` and friends run as
separate processes, and the state is in memory, so they talk to the running server.

- Transport: AF_UNIX socket `$JAILHUB_STATE/jailhub.sock`, mode 0600. The socket file
  permission *is* the authorisation.
- Protocol: line-delimited JSON requests and responses, reusing the `proto` codec.
- Commands: `node list|approve|deny|remove|rename`, `name list|reassign|release`,
  `domain list|release`, `user list|remove`, `invite create|list|revoke`,
  `authkey create|list|revoke`, `admin add|remove|login-link`, `key rotate`,
  `setting <key> <value>`, `status`, `handoff`.
- **Settings that can change at run time** (invite policy, registration mode, knocking) live in
  the store. `serve` flags only seed them on first start; afterwards `/admin` or
  `jailhub setting` owns them, and the value survives restarts.

`/admin` exists because an approval queue that can only be drained from a shell on the hub
violates the usability principle.

- Authentication has no password and no IdP: **an admin node's MachineKey is the identity.**
  `jailscale admin` on that node asks for an `AdminLink` over stream 0, the hub returns a
  60-second one-shot URL, and the CLI opens a browser. The visit sets a session cookie
  (`__Host-` prefixed, `HttpOnly; Secure; SameSite=Lax`, 12 hours). With no node available
  (first install, recovery) the hub shell has `jailhub admin login-link`.
- Functions: approve or deny the queue, list and remove nodes, names and domains, issue invites
  and auth-keys, toggle the three settings. That is all.
- Implementation: server-rendered HTML, no JavaScript, inline CSS, string concatenation instead
  of a template engine, a session-bound CSRF token on every form.

---

## 7. Certificates and ACME

### 7.1 One wildcard, obtained through the hub's own DNS

**Certificates are not issued per name.** Let's Encrypt allows 50 new certificates per
registered domain per week. With a UX where `jailscale open 3000` mints a fresh random name,
that is exhausted in a day, and every new name would stall for the seconds an ACME round trip
takes. One wildcard means issuance twice a month and a new name that opens in zero seconds.

A wildcard requires dns-01. Normally that means a DNS provider API token; here **the hub is the
authoritative DNS server for the `_acme-challenge` name** (the acme-dns pattern). The operator
creates three records:

```
hub.example.com.                  A   203.0.113.10     (direct, no proxy; Cloudflare must be DNS-only)
*.hub.example.com.                A   203.0.113.10
_acme-challenge.hub.example.com.  NS  hub.example.com. (the NS target is outside the delegated zone, so no glue)
```

When the CA asks for the TXT at `_acme-challenge.hub.example.com`, the delegation sends it to
the hub's port 53, and the hub answers with the challenge value of the moment. This one name
validates both SANs.

**That is the entire operator setup.**

| # | Step | Note |
|---|---|---|
| 1 | The three DNS records above | Creatable in any DNS UI |
| 2 | Firewall: TCP 443, UDP 53, TCP 53 | Port 80 is optional (HTTPS redirect, user-domain http-01 relay). Raw publishing adds `--port-range`, default 10000-10999, TCP and UDP |

The first run is `jailhub serve --base-url https://hub.example.com`, which prints the first
invite link on the console (§10.5).

### 7.2 Issuance and renewal

```
jailhub serve --base-url https://hub.example.com
 │
 ├─0. a still-fresh wildcard in $JAILHUB_STATE/tls/ is installed at once; skip to 8
 ├─1. start the port 53 responder. It answers TXT, NS and SOA for _acme-challenge.<hub>
 │     and REFUSED for everything else. Bind a specific address to avoid systemd-resolved
 ├─2. self-check (must pass before issuance; on failure it prints the diagnosis and retries
 │     every 60 s). It sets a random TXT value and asks 1.1.1.1 and 8.8.8.8 for it, which
 │     separates a missing NS delegation from a blocked port 53 from a cached answer.
 │     Skippable with --no-selfcheck where hairpinning does not work
 ├─3. account key (EC P-256) created if absent -> tls/account.key, newAccount, terms accepted
 ├─4. newOrder { identifiers: [dns: hub.example.com, dns: *.hub.example.com] }
 ├─5. for each authorization, the dns-01 token becomes TXT = base64url(SHA-256(keyAuthorization)),
 │     registered with the responder as two TXT records under the same name
 ├─6. POST the challenges as ready; the CA validates from several vantage points; poll
 ├─7. new certificate key (EC P-256), PKCS#10 CSR encoded by hand, finalize, download chain
 │     -> tls/wildcard.key and tls/wildcard.pem (0600, written to temp files and renamed)
 ├─8. open 443 and push the chain to every connected node with CertUpdate
 └─9. renewal: checked once a day, repeated when less than a third of the lifetime is left.
        The previous key stays usable for 24 hours so in-flight handshakes still complete
```

- **JWS.** Protected header `{alg: ES256, nonce, url, jwk|kid}`. The JDK's `SHA256withECDSA`
  produces DER, and JWS wants the raw 64-byte `R||S`; without that conversion the CA rejects
  every request.
- **CSR.** The JDK has no public PKCS#10 API, so a small DER writer builds
  `CertificationRequestInfo{version 0, subject CN, SubjectPublicKeyInfo, extensionRequest[SAN x2]}`
  and signs it with ECDSA.
- **DNS responder.** Query parsing plus TXT/SOA/NS assembly, about 150 lines, UDP and TCP. EDNS0
  is ignored safely because the answers are under 512 bytes.
- **Why ECDSA.** So that the private-key operation the node delegates is exactly one signature.
  RSA key exchange would require a decryption, so those suites are off (§9.2).
- **Supported scope.** ACME v2, dns-01 only. External Account Binding is out of scope.
- **Bring your own certificate.** `--tls-cert/--tls-key` covers internal CAs and hosts that
  cannot open port 53. The certificate must carry the wildcard SAN, and it must be ECDSA.
- **Binding privileged ports.** On Linux, 443 and 53 need root or `CAP_NET_BIND_SERVICE`. The
  reference systemd unit runs as a dedicated `jailhub` user with `AmbientCapabilities`. macOS
  allows unprivileged binding.
- **No HTTP proxy in front, TCP proxy is fine.** SNI passthrough needs raw TCP 443, so an HTTP
  reverse proxy that terminates TLS (nginx `http`, Caddy, Cloudflare Proxied) cannot work. A
  layer-4 proxy that only copies bytes (nginx `stream`, HAProxy `mode tcp`) is supported and has
  reference configs in the distribution (§8.5).
- A node started with `--ca-file` keeps that path in its state, so it will not recover on its
  own if the hub later serves a certificate from a different CA. Re-running `jailscale up --hub
  <name>` without the flag clears it. This is the usual snag when moving from ACME staging to
  production.

---

## 8. Public ingress

### 8.1 SNI router

A single `ServerSocket` accepts on 443. Without opening TLS, the router reads the ClientHello
(5-second timeout), parses the SNI, and branches. The parser walks record header, handshake,
extension list, `server_name` in about 100 lines.

| SNI | Handling |
|---|---|
| `hub.example.com` | Handed to the hub's own `SSLServerSocket`: control channel, `/join`, `/admin`, `/v1/*` |
| `<name>.hub.example.com`, active | Open an `OPEN` stream on the owning node and replay the ClientHello bytes already read |
| `<name>.hub.example.com`, claimed but offline | Wait up to 3 s for the node to come back (covers hand-off and restarts), then serve a short "not open" page under the wildcard certificate, which the hub can do because it holds the key |
| A registered user domain | Stream to the owning node with `keyId = domain:<domain>`. The hub has no key for it |
| Anything else, or no SNI | Closed immediately |

After that the hub copies bytes both ways. It does not look at TLS records or HTTP. Visitor
socket to stream `DATA`, stream `DATA` to visitor socket; a visitor half-close becomes `CLOSE`,
an error becomes `RST`.

**Limits.** 64 concurrent connections per visitor IP, 1,024 per name
(`SniRouter.MAX_PER_NAME`), 5 seconds to produce a ClientHello, listen backlog 1,024 (capped by
the OS `somaxconn`). SYN flood defence is the kernel's job. Loopback connections are exempt from
the per-IP limit: behind a local proxy without PROXY protocol every visitor folds into one
address, and while `--proxy-protocol` (§8.5) is the right answer there, this exemption is the
safety net.

**What the hub can see.** The SNI, the visitor IP, byte counts and connection times. Not the
content.

**Anything with TLS and SNI works, not just HTTP.** Since neither end parses HTTP, any TLS
client that sends SNI can reach a name. `psql "sslmode=require host=db.hub.example.com"`, MQTT
over TLS and gRPC all work, and `jailscale open 5432` behaves exactly like an HTTP app. Only
clients that do not speak TLS need the raw ports of §8.4.

**Visitors that never close.** Both directions are half-closes, so the hub would wait for the
visitor to close its own half after the node is done, and a visitor is under no obligation to do
that. A 10-second timer therefore starts **when the node closes its side**. Because the clock
only starts then, streams that are meant to stay open (WebSocket, SSE, long downloads) never
reach it. Without it a socket, the thread reading it and a half-open stream would be pinned
indefinitely.

### 8.2 Names

- **Format.** `<name>.hub.example.com`, lower-case letters, digits and hyphens, up to 40
  characters, not starting or ending with a hyphen. Reserved labels (`hub`, `admin`, `www`,
  `api`, `ns`, `_acme-challenge`, `join`, ...) are refused.
- **Random names.** `jailscale open 3000` gets a five-character name such as `q7x2k` from a
  30-character alphabet with look-alikes removed. The same node reopening the same local target
  gets the same name back, so the URL survives restarts.
- **Chosen names.** `--name myapp`. The name belongs to the first requester's *user*, and that
  user's other nodes may use it too. Another user gets `taken`. An admin can move it with
  `name reassign`.
- **Active.** A name routes only while the node has the link open and is connected. When the
  node disconnects, the name stays claimed and visitors see the "not open" page.
- **No ACME on the name path.** Opening a name costs one `LinkOpen` round trip, because the
  wildcard already covers it.
- A node may hold at most 20 name and domain links (`Links.MAX_LINKS_PER_NODE`).

### 8.3 User domains

`jailscale open 3000 --domain myapp.com` publishes a domain the user owns.

- The user points `myapp.com` at the hub with a CNAME or A record.
- If the node has no certificate for it, or renewal is due, the node runs ACME **http-01 with
  its own key**. Since DNS points at the hub, the CA's request for
  `http://myapp.com/.well-known/acme-challenge/...` arrives on the hub's port 80. The node
  uploads `ChallengeSet{token, keyAuthorization}` (at most 10 per node, 10 minutes each), the
  hub answers on its behalf, and `ChallengeClear` removes it afterwards. The hub learns the
  token and the response string and nothing about the node's key.
- Then `LinkOpen{domain, chainPem}`. **The certificate chain is the proof of ownership.** The
  hub binds the domain to the node only when the chain validates against public roots and its
  SAN is that domain. Rejections are `domain-unverified`, `domain-cert-name-mismatch`,
  `domain-cert-untrusted`, and `bad-domain` for a name under the hub's own domain. If another
  node later presents a valid certificate for the same domain, that node wins, because being
  able to obtain the certificate is evidence of controlling the domain.
- After that it is pure SNI passthrough. The certificate and key exist only on the node, the hub
  forwards ciphertext, and there is no `SignRequest`.
- Rate limits are counted against the user's own registered domain, so they are independent of
  the hub domain's.
- The node renews on the same one-third-of-lifetime rule, checked hourly. An offline node does
  not renew.
- **Port 80 on the hub is a precondition.** A hub started with `--http-listen none` refuses
  user domains.

### 8.4 Raw TCP and UDP ports

Clients that do not speak TLS (SSH, game servers, plaintext databases, DNS, WireGuard) send no
SNI and cannot be told apart by name. The hub assigns **a port instead of a name**, the same
shape as ngrok's tcp mode or frp's tcp/udp types.

```
$ jailscale open 22 --tcp
tcp://hub.example.com:10042  ->  127.0.0.1:22
$ jailscale open 51820 --udp
udp://hub.example.com:10043  ->  127.0.0.1:51820
$ jailscale open 22 --tcp --port 10022        # request a specific port in the range
```

- **Port range.** `--port-range 10000-10999` by default, `none` to disable the feature. The
  range must be open in the firewall for both TCP and UDP, and its size is the ceiling on
  concurrent raw links. An assignment is remembered per node, kind and local target.
- **TCP.** The hub opens a `ServerSocket` on the assigned port and opens one stream per visitor
  connection. No SNI parsing, no TLS.
- **UDP.** The hub opens a `DatagramChannel`. Each new visitor address gets a stream with the
  `DGRAM` flag, and every later datagram from that address becomes one DATA frame. The node
  creates one local UDP socket per stream. A visitor address idle for 60 seconds is dropped. The
  datagram size ceiling is the 16 KB frame cap, well above ordinary MTU-sized traffic. Ordering
  and delivery are stronger than UDP semantics promise, never weaker, because the carrier is TCP.
- **Where the plaintext is.** Visitor to hub is exactly what the client sent, and hub to node is
  still Noise-encrypted, so plaintext exists **only inside the hub process**, and only for apps
  that do not encrypt themselves. SSH, WireGuard and a TLS-enabled database are effectively
  end-to-end because the hub sees only the app's ciphertext. Plaintext protocols are visible to
  the hub. This cannot be fixed from our side without the visitor's client cooperating, and it is
  the same for ngrok and frp. `open --tcp/--udp` says so in its output. A client that can speak
  TLS should use the 443 path of §8.1, which is end-to-end.
- Ports outside the configured range are not offered. The hub's low ports are the hub's.

### 8.5 Behind a TCP proxy, and PROXY protocol

An operator whose server already runs nginx or HAProxy on 443 can put the hub behind it,
provided the proxy **forwards TCP bytes without opening TLS**.

- Reference configs ship in `deploy/nginx-stream.conf` and `deploy/haproxy.cfg`, including an
  `ssl_preread` example that routes only the hub's names to the hub and leaves the rest to the
  existing service.
- The hub runs as `--listen 127.0.0.1:8443 --proxy-protocol`. With that flag it reads a PROXY v1
  or v2 header at the start of each connection to learn the visitor address. Since the header is
  only trustworthy from a trusted proxy, `--proxy-protocol` is accepted only when `--listen` is
  on loopback or `--trusted-proxy <cidr>[,<cidr>]` is given. Otherwise anyone could forge a
  visitor address. Connections from untrusted peers are refused outright.
- The parser takes v1 text and v2 binary (IPv4, IPv6, LOCAL). v1 addresses must be **literals**:
  allowing hostnames would put a DNS lookup on the accept path, where an attacker could stall the
  hub. Fuzzing found that one.
- A hub with `--proxy-protocol` on rejects header-less connections, so the node's control
  connection has to go through the proxy too.
- The address the router derives from the header is what the rate limits, the knock queue and the
  session logs use, so nodes behind one proxy are not collapsed into a single address.
- The self-check of §7.2 works unchanged behind a proxy, since it tests whether the public name
  ultimately reaches the hub.

---

## 9. The node

### 9.1 Publishing

```sh
$ jailscale open 3000
https://q7x2k.hub.example.com  ->  127.0.0.1:3000        (copied to the clipboard)

$ jailscale open 3000 --name myapp        # chosen name
$ jailscale open 3000 --gate              # visitor gate; prints a visit link too
$ jailscale open 3000 --domain myapp.com  # user domain (§8.3)
$ jailscale open 22 --tcp                 # raw TCP, hub assigns a port (§8.4)
$ jailscale open 51820 --udp              # raw UDP
$ jailscale open 8080 --host 192.168.1.20 # another machine on the same LAN
$ jailscale ls
$ jailscale close q7x2k
```

The daemon remembers open links and reopens them with the same name or port after a reboot.

### 9.2 TLS termination with hub-side signing

A visitor stream is a byte stream, not a socket, so `SSLSocket` cannot be layered on it. The node
drives an `SSLEngine` directly: stream to `unwrap` to plaintext to the local socket, and local
socket to `wrap` to stream.

```
visitor ──ClientHello──> hub ──OPEN + bytes──> node (SSLEngine)
                                                  │  transcript hash h
                                                  ├──SignRequest{streamId, keyId, ECDSA-P256-SHA256, h}──> hub
                                                  │                                    checked, then signed
                                                  <──SignResponse{streamId, sig}───────────────────────────┘
                                                  │  ServerHello ... CertificateVerify(sig) ... Finished
visitor <──────────────── hub <──bytes──────────  node
```

The `SSLContext` is built from the chain the hub sent in `CertUpdate` and an **opaque
`PrivateKey`** that holds no bytes, only a `keyId`. A small JCE provider offers
`Signature.SHA256withECDSA` for that key type; JSSE's delayed provider selection picks it, which
is the same mechanism PKCS#11 keys rely on. `engineSign()` sends a `SignRequest` on stream 0 and
blocks for the reply, which costs nothing on a virtual thread. The service is registered by
subclassing `Provider.Service` and overriding `newInstance`, so no reflection is involved.

**The four conditions that stop a signing oracle.** The hub sees only a transcript hash, so it
cannot tell which SNI a handshake belongs to. Signing unconditionally would give every member
node an oracle for the entire wildcard, and anyone able to spoof a visitor's DNS could then
impersonate someone else's name. So the hub signs only when all of the following hold:

1. `streamId` names **a stream this hub opened on this connection**, and it is still open.
2. The `sni` recorded in that stream's `OPEN` maps to a name currently **assigned to this node**.
3. That stream has used fewer than 4 signatures. A normal TLS 1.3 handshake uses one, and two
   covers HelloRetryRequest.
4. The node is within its signing rate: a token bucket of 2,000 with 1,000 per second sustained,
   sized from a load test where 1,000 visitors handshake at once. Session resumption needs no
   signature.

Both peers' randoms are in the transcript, so a signature cannot be replayed on another
connection. The result is that a node can only get signatures for connections the hub delivered
to it, and the only name it can impersonate is its own.

**Keeping it to one signature.** The certificate is ECDSA P-256 (§7.2). In TLS 1.3 and in TLS 1.2
ECDHE suites the private-key operation is a single signature; RSA key exchange, which would need
a decryption, is excluded by the key type. Session tickets are generated by the node and kept in
memory, so a resumed handshake does not touch the hub at all. 0-RTT is off. ALPN offers only
`http/1.1`, because negotiating h2 would break a local app that speaks h1.

**Key rotation.** `CertUpdate` carries a `keyId` (a certificate fingerprint). The node starts new
handshakes with the newest `keyId` and echoes it in `SignRequest`. The hub keeps the previous key
for 24 hours (§7.2), so a handshake begun just before a renewal still completes.

**Cost.** Each first handshake from a visitor adds one node-to-hub round trip. This is the same
cost Cloudflare Keyless SSL pays.

A user-domain stream arrives with `keyId = domain:<domain>` and is terminated with the node's own
real key, with no hub involvement.

### 9.3 Relaying

Once TLS is off, the node **copies bytes**: visitor plaintext to `127.0.0.1:<port>`, local
responses back. HTTP/1.1 keep-alive, chunked bodies, WebSocket upgrades and SSE all pass through
because the local app handles them.

`open --proxy-protocol` prepends a PROXY v1 line so the local app learns the visitor address; the
hub supplies `visitorAddr` and `visitorPort` in the stream metadata, and the destination is the
local target. Raw TCP links behave the same way.

A refused or reset local connection is retried five times with 50 ms doubling (about 1.5 s total)
before giving up. A burst of visitors really does overflow a small listen backlog (macOS defaults
to 128), and it surfaces as an immediate refusal.

Only after that does the visitor get a 502 page. That page and the gate are the only two places
where the node *writes* HTTP, and only on https links. A raw TCP stream copies bytes with no TLS,
and a raw UDP stream turns one DATA frame into one datagram.

### 9.4 Visitor gate

A link that should not be public is locked behind a visit link. The capability model is the same
as for invites.

```
$ jailscale open 3000 --gate
https://q7x2k.hub.example.com                          (gate on)
visit link: https://q7x2k.hub.example.com/?jail=8Hq... (24 h, copied to the clipboard)
$ jailscale gate q7x2k --new-link --ttl 7d
$ jailscale gate q7x2k --off
```

- Immediately after TLS termination the node reads only **the first request head** of the
  connection (request line and headers, at most 16 KB). A valid `Cookie: jail=<token>` lets the
  whole connection through; the same TCP connection is the same client.
- A valid `?jail=<token>` query gets `Set-Cookie: jail=...; Path=/; Secure; HttpOnly;
  SameSite=Lax` with a 302 to the same path without the token, then the connection closes.
- Neither one gets a 403 page and a close.
- Tokens are 128-bit; the node stores only a SHA-256 hash. The hub knows nothing about gates,
  because it only sees ciphertext. Keeping the gate on the node is the position consistent with
  end-to-end encryption.
- Bodies are never read. HTTP parsing stops at the blank line.

### 9.5 Daemon and CLI

`jailscale` is one binary with two roles. `jailscale daemon` (or a registered service) stays
resident; every other subcommand talks to it over **local IPC**.

- Transport: AF_UNIX at `$XDG_RUNTIME_DIR/jailscale.sock`, otherwise next to the config file
  (0600). Windows uses AF_UNIX as well.
- Protocol: line-delimited JSON with streaming replies for progress output, sharing the codec
  with the hub's admin IPC.
- Commands: `up`, `down`, `status`, `open`, `close`, `ls`, `gate`, `invite`, `admin`, `netcheck`,
  `verify` (§11.4), `leave`, `service install|uninstall|status`.
- **Service registration** uses only what the OS already has: a launchd agent in
  `~/Library/LaunchAgents` on macOS, a `systemctl --user` unit on Linux (a system unit when
  root), and a logon scheduled task on Windows. The command is the binary's own path, or
  `java -jar <jar>` when running from the fallback JAR. There is no service wrapper.
- `jailscale up` starts the daemon if it is not running. `jailscale open` asks for an invite link
  if the node has not joined.

### 9.6 What the node does not do

No WireGuard, no userspace TCP/IP, no STUN, no SOCKS5, no MagicDNS. It makes one outbound 443
connection, receives streams, strips TLS and hands plaintext to a local port. It opens no inbound
port, uses no UDP locally and needs no root.

---

## 10. Joining

There is no IdP. The right to join is carried as a **capability**: an invite link, a short code
and an auth-key are all secrets where possession is the permission, and the hub registers
whichever MachineKey arrives with one. Joining is the right to publish. Visitors never join.

### 10.1 Why no IdP

- An IdP answers "who is this person", not "may they publish", so an invite and approval queue
  would be needed anyway. The IdP ends up being a name tag stapled to someone who was invited.
- The cost is real: an app registration for every hub operator, on the order of a thousand lines
  of security-sensitive code, and collaborators without an account in that IdP are excluded.
- Putting the user name in the invite solves the name-tag problem directly. Tailscale auth-keys,
  headscale pre-auth keys and Syncthing device approval are all this model.

What is given up: there is no externally verified identity, so a leaked link lets someone else in
under that name. The countermeasures are one-use and short TTL defaults, and removal from the
admin list.

### 10.2 Issuing invites

Invites are **not admin-only**. By default any member can issue one from their own node. The
issuer is recorded, and an admin can narrow it with `--invite-policy admins`.

```
$ jailscale invite
  link:  https://hub.example.com/join/9f1cQ2...     (copied to the clipboard)
  code:  7F3K-92QX                                  (for reading out over the phone)

$ jailscale invite --user bob --uses 3 --ttl 7d     # name fixed, three of bob's machines
$ jailscale invite --self                           # another machine of my own
$ jailhub invite create ...                         # the same options from the hub shell
```

- The **link** carries a 128-bit token (22 base64url characters). Default one use, 24 hours.
- The **code** is an alias for the same invite: 40 bits in Crockford base32 as `XXXX-XXXX`, valid
  10 minutes. Typed codes are normalised (upper case, hyphen dropped, `O` to `0`, `I`/`L` to `1`).
- Without `--user`, the joiner supplies the name, defaulting to the OS user name.
- Clipboard copying shells out to `pbcopy`, `xclip` or `clip.exe`, and is skipped if absent.
- Issuance goes IPC to stream 0 `InviteCreate` to the hub. The hub stores only hashes.

### 10.3 Joining

```
$ jailscale up --invite https://hub.example.com/join/9f1cQ2...
 │        (or --hub hub.example.com --code 7F3K-92QX, or --auth-key jk_...)
 ├─1. take the hostname from the link and pin the hub key through /v1/key (§5.2)
 ├─2. open the Noise channel, negotiate versions with Hello (§6.1)
 ├─3. "joining hub.example.com. Name [wq]:"   (asked only when the invite fixes no name)
 ├─4. RegisterRequest{ hostname, os, invite }
 ├─5. hub: match the token hash, check expiry and remaining uses, decrement, assign a node id
 └─6. RegisterResponse{ approved } then CertUpdate. `jailscale open` now works
```

No browser opens, so a headless server runs the same command. Opening `/join/<token>` in a
browser shows install instructions and a copyable command, and never consumes a use.

**Phishing.** An attacker can hand out an invite to their own hub. The CLI prints which hub it is
about to join and asks for confirmation. Even if the victim joins, nothing local is exposed until
they run `open`.

### 10.4 Knocking and the approval queue

With only the hostname, a node can knock.

```
$ jailscale up --hub hub.example.com
waiting for admin approval... (hostname wq-macbook, mkey:0J3B...)
```

The hub records MachineKey, hostname, OS, source address and self-chosen name in a `pending`
queue. When an admin approves through `/admin` or `jailhub node approve 0J3B... --user wq`,
completion is pushed over the already-open stream 0. Knocking is unauthenticated, so pending
entries are capped at 5 per source address. `--knock off` disables it.

**`--registration open`** suits a personal hub or a small team where the gate is overhead: a
knocking node is approved immediately and picks its own name. The default is still invite-only,
and turning it on prints the consequence, which is that anyone who knows the hostname can open
names under `*.hub.example.com`. There is deliberately no web signup form, because that would be
the same thing with more code.

### 10.5 Auth-keys and first bootstrap

An **auth-key** is an invite for unattended registration: CI jobs, containers and servers.

```
jailhub authkey create --owner alice                  # a node belonging to alice
jailhub authkey create --tag ci --uses 20 --ttl 7d    # a tagged node with no human owner
jailscale up --hub hub.example.com --auth-key jk_...
```

It is `jk_` plus 128 bits, stored as a hash. A tagged node's names belong to the tag.

**First bootstrap.** When `jailhub serve` finds no admin in the state directory it prints a
one-use 24-hour invite on the console, and the user who joins with it becomes an admin. Further
admins come from `jailhub admin add <user>` or `/admin`. If every admin node is lost,
`jailhub admin login-link` on the hub shell recovers access: shell access is the top of the
authority chain.

Nodes do not expire by default; an admin removes them with `node remove`.

---

## 11. Security model

Four axes. None of them implies any other.

| Axis | Question | Answer |
|---|---|---|
| **Transport** | Who can read between visitor and node | Nobody, the hub included. It sees SNI, IP, byte counts, timing (§8.1) |
| **Right to publish** | Who can open a name | Only nodes that joined through an invite, auth-key or approval. No open registration by default |
| **Right to visit** | Who can reach a published link | Public by default; with `--gate`, only holders of the visit link (§9.4) |
| **Name identity** | Who vouches that `myapp.hub.example.com` is alice's node | **The hub.** It owns the routing table and the wildcard key (§11.3) |

### 11.1 The boundary of signature delegation

The wildcard private key exists only on the hub. A node gets a signature only for a stream the
hub delivered to it, and only when that stream's SNI is one of its own names (the four conditions
of §9.2). Therefore:

- A compromised member node gains impersonation of **its own names**, which were already its own.
- Because the control channel is pinned to the hub key by Noise, a MITM proxy that defeats TLS
  still cannot intercept or forge signing requests (§5.1).
- The hub checks every request against stream, name, count and rate, and logs refusals. A node
  that keeps being refused is disconnected and flagged to the admin.

### 11.2 A node exposes nothing by default

Joining opens no port on the node. Only the port named in `jailscale open` is reachable, and only
while that link is open. There is no TUN device, so there is no OS routing path to leak through.
A visitor can reach exactly the one `host:port` the node named, never the node's other services or
its LAN.

### 11.3 The hub is trusted

Stated plainly. If the hub is compromised:

| It cannot | It can |
|---|---|
| Read visitor traffic to an honest node (the node terminates it) | **Reassign a name to an attacker node** and sign with the wildcard key, intercepting that name entirely. This cannot be prevented, but it is detectable (§11.4) |
| Obtain a node's MachineKey or user-domain keys (it never has them) | Register arbitrary nodes and issue invites at will |
| Reach local services a node has not published | See who connected to which name, when, and how much |

The hub is the TLS authority for its own domain, so its compromise is impersonation of every name
under it. User domains (§8.3) are the exception: their keys live on the node, so a compromised hub
can only stop routing them. For a self-hosted deployment where the hub operator *is* the
organisation this matches the usual threat model, and names that need more than that should be
user domains.

**Preventing and knowing are different.** The hub decides who owns a name, so it cannot be stopped
from reassigning one. §11.4 therefore makes the node notice instead.

### 11.4 Self-probe

The node connects to its own public name and checks whether it terminated that TLS session itself.
The command is `jailscale verify`.

The mechanism is RFC 5705 exported keying material. Both ends of a TLS 1.3 session derive the same
bytes from a label, and a third party that did not terminate the session cannot.

1. The node records the exported value of every visitor session it terminates, immediately after
   the handshake. It keeps the last 120 seconds, at most 4,096 entries.
2. `jailscale verify` connects to each open https link **by its public name**, at the hub address,
   so it genuinely traverses the hub.
3. It sends `GET /` and waits for the response. A response means the server side already finished
   its handshake and recorded it, which removes the race between steps 1 and 4.
4. If the value the client exported is in the record, the verdict is `terminated by this node`;
   otherwise `TERMINATED ELSEWHERE`. The comparison uses `MessageDigest.isEqual`.

If a hub holding the wildcard key terminates the name itself or hands it to another node, the
certificate the visitor sees is still valid, but the session is a different one and its exported
value is not in the record. A hub that decrypts and re-encrypts is caught for the same reason: the
re-encrypted session is a different session.

**Limits.** The probe leaves the node's own address, so a hub that singles those connections out
and routes only them correctly is not caught. Doing that requires discriminating between visitors,
which is itself a detectable behaviour. `--tls-insecure` or a stale `--ca-file` blinds the probe
along with everything else. TLS 1.2 and below cannot export the material, and the verdict is then
`keying material unavailable`.

**How this relates to §11.1.** The four signing conditions are enforced by **the hub**, so they
stop a rogue *node* and say nothing about a rogue *hub*. The self-probe runs on **the node**. The
two do not overlap; they face opposite directions.

### 11.5 Name revocation notices

The self-probe only runs when someone types `jailscale verify`. So an **honest hub announces a
name change in advance**, with `LinkRevoked{linkId, name, reason, at}`, where `reason` is
`reassigned` (another node opened the same name) or `released` (an operator took it back).

What this does not do: a compromised hub simply does not send it. This is incident notification,
not attack detection. Catching a compromised hub is §11.4, and the two have different jobs.

**The trigger is stored ownership, not a live link.** This distinction is the whole design. A node
losing a name is usually **offline**, and being offline is exactly why someone else took the name,
so at that moment there is no live link to look at. `Links.open` therefore watches for the stored
claim's MachineKey changing, and notifies the previous one. Domains and raw ports use the same
rule against their own records.

**Delivery.** If the node is connected, the notice goes out immediately. If not, it is stored
(`notice-added`) and handed over on the node's next connection, then cleared (`notices-cleared`).
Clearing happens only after everything has been sent, so a node that dies mid-delivery hears it
again. A node that never returns is capped at 20 stored notices, oldest dropped first.

**On the node.** The name is removed from local state, because leaving it would silently reopen it
on the next reconnect and make the notice pointless. It is also recorded under `revoked` so
`status` keeps saying so after the log line has scrolled away. Deliberately reopening the name
clears the warning, since that is the answer to it.

**Operator release.** `name release` and `domain release` now take the live link down and send the
notice, rather than quietly clearing ownership while the old node keeps serving. Release is not a
ban: the name is free, so the same node may reopen it. Banning a node is `node remove`.

### 11.6 Abuse and rate limits

A public link can host a phishing page. The operator can release the name and remove the node.
Random names are five characters, so they are hard to guess, and chosen names exist only for
members. Structural limits are 1,024 connections per name (§8.1) and 20 links per node (§8.2).
Beyond that, abuse response is the operator's job.

Unauthenticated work is metered with per-source token buckets (`RateLimiter`):

| Target | Burst | Sustained | On excess |
|---|---|---|---|
| `/v1/noise` handshake | 30 | 1/s | HTTP 429, Upgrade refused |
| Credential presentation (invite token, code, auth-key) | 20 | 0.2/s (12 a minute) | `rejected{reason: rate-limited}` |
| Knock queue | 5 entries per address | n/a | `rejected{reason: too-many-pending}` |

A node the hub already knows returns before the credential check, so reconnections never touch the
bucket. The bursts are generous because a node opens up to four connections and a NAT can hide
many nodes behind one address; the sustained rate is what limits abuse. To stop an attacker
inflating the map by rotating addresses, once more than 10,000 keys are tracked the full buckets
are dropped: a full bucket is indistinguishable from one that never existed, so nothing is lost.

**`/admin` sessions.** The login link is one-shot and lives 60 seconds; the session cookie lasts
12 hours; every POST carries a CSRF token. On top of that, **admin status is rechecked on every
request**, because checking only at link issuance would leave `admin remove` ineffective for 12
hours. A link issued over the IPC socket is exempt from that recheck, since socket permission is
the authorisation (§6.3). The cookie uses the `__Host-` prefix, which forbids a `Domain`
attribute, so a node controlling a sibling subdomain under `*.<hub>` cannot plant an admin cookie.
Logout deletes the session immediately, and expired login tokens and sessions are swept on each
request.

Auth-keys, invite tokens, codes, gate tokens and admin login URLs are never written to logs.

---

## 12. Threading and memory

There is no packet hot path, so there is no reason to insist on platform threads. Almost
everything runs on virtual threads.

| Role | Threads |
|---|---|
| Hub accept on 443 | 1 platform thread |
| Hub visitor connection (SNI peek, byte copy) | 2 virtual threads per connection, one per direction |
| Hub node connection | 1 virtual reader plus 1 virtual keepalive per connection; writes happen on the producing thread under a lock |
| Hub own HTTP, ACME, port 80, DNS | One virtual thread per request; the DNS listeners have their own threads |
| Node mux session | Same shape as the hub side |
| Node visitor stream (`SSLEngine` plus local socket) | 2 virtual threads per stream |
| Node remote signing | Blocks on the calling thread, which is free on a virtual thread |
| Local IPC | One virtual thread per request |

Writes into a Noise channel are serialised by a lock rather than queued through a writer thread,
because the transport nonce counter has to advance in wire order. Buffers are 16 KB per direction,
allocated per stream. Per stream the flow-control window is 256 KB (§5.3).

Memory is bounded by the connection limits, not by a heap cap. There is deliberately **no fixed
heap maximum** in the images. Concurrency scales with the number of names: the hub accepts 1,024
per name and a node can hold 20 names, so one node's ceiling is 20,480 concurrent streams and the
hub's is that multiplied by the number of names it serves. No single byte figure covers that
range correctly. A memory-tight host sets its own limit, for example `jailhub serve -Xmx256m`.

Two consequences worth knowing. Serial GC does not return the heap to the OS, so RSS stays at its
high-water mark after a load burst; that is headroom, not a leak. And idle RSS is unrelated to
heap size: the node daemon alone is about 16.7 MB and reaches about 24.3 MB the moment it connects
to the hub, so roughly 7.6 MB is JSSE initialisation for one TLS client. Lowering the heap cap
does not move that number.

---

## 13. Availability and hand-off

The hub is one process on one host. The main deployment is a single self-hosted VPS, and at
scale one hub handles thousands of nodes and tens of thousands of streams, because all it does is
copy bytes and sign. What remains is availability, and the answer is fast recovery.

| Item | Target |
|---|---|
| Hub process restart | Under 5 s including state replay. Nodes reconnect with 1, 2, 4, 8, 16, 30 s backoff |
| What a visitor sees | Connections refused during the restart; streams in flight are cut |
| Backup unit | The `$JAILHUB_STATE` directory. `hub.key`, `tls/` and `state.*` are all of it |
| Host replacement | Copy the directory to the new host and change DNS. Nodes notice nothing, because the hub key and the wildcard key are the same |

### 13.1 Hand-off

Updating the hub binary does not need a restart. `jailhub serve --takeover` starts a new process
that takes over from the old one.

1. The new process sends `handoff` to the old process's IPC socket.
2. The old process closes the 443 listener, the raw ports, port 80, the DNS responder and ACME,
   snapshots its state, releases the state lock, and sends `Goodbye{draining}` to every node.
   Visitor streams already in flight keep flowing on those connections (**draining connections**).
   No new visitor streams are opened on them.
3. The new process takes the lock, replays the state and opens 443. For the few hundred
   milliseconds in between, new visitors are refused. `SO_REUSEADDR` means there is no bind wait.
4. On `draining`, a node immediately opens a fresh connection and reopens its links. It keeps the
   old connection until its open streams finish, then closes it. A signing request goes to the
   connection that owns the stream, which is what makes a draining stream's signature findable.
5. The old process exits once the draining connections are empty, or after 60 seconds. It deletes
   the IPC socket file only if it is still its own (compared by inode), so it cannot remove the
   new process's socket.

A visitor sees a few hundred milliseconds of refused connections, and downloads and WebSockets in
flight are not cut. Nodes reconnect with no backoff. The deploy script is one line, and so is the
rollback.

The router also waits up to 3 seconds for a claimed but momentarily offline name (§8.1), which is
what stops the gap in step 3 from turning into an error page.

---

## 14. Current characteristics

Measured on arm64 macOS with the native binaries, through `./measure.sh`, which starts a real hub
and two node daemons on loopback, joins them with the real CLI and opens a link.

| Measurement | Current | Budget |
|---|---|---|
| Binary size | 25.0 MiB (`jailhub`), 25.3 MiB (`jailscale`) | 30 MiB |
| Node idle RSS | about 24.7 MB | 28 MB |
| Hub idle RSS | about 24.7 MB | 30 MB |
| RSS with 1,000 visitor sessions held open | node 87 MB, hub 77 MB | node 192 MB, hub 160 MB |
| CLI cold start | about 6 ms (`jailscale status`, median of 10, IPC round trip included) | 50 ms |

`./measure.sh --check` fails when a number exceeds its budget, and the same script runs in CI. The
budget values live at the top of the script and must match this table. They are changed only by a
PR that states a reason.

**Load is measured with the connections held open.** An earlier gate fired 1,000 short requests
with `curl --parallel` and finished, which means 1,000 were never alive at the same time and the
figure was roughly a third of the real number. `tools/hold-visitors.py` now keeps all 1,000 open
and samples the peak RSS during that time. Bursts larger than the kernel accept queue are reset
before they reach jailscale, so the visitors are ramped in batches of 100.

Structural ceilings that go with these numbers: 1,024 concurrent visitors per name
(`SniRouter.MAX_PER_NAME`), 20 links per node, and up to 4 control connections per node.

---

## 15. Limits

Known and unresolved, stated as facts rather than plans.

- **The self-probe is manual.** §11.4 runs only when someone types `jailscale verify`. Nothing
  detects a hub-side interception in between. Running it periodically is the obvious next step,
  and the interval has to scale with the number of open names, since a short interval adds
  self-traffic to the hub and a long one delays detection.
- **The self-check does not verify A records.** The startup check (§7.2) proves the
  `_acme-challenge` delegation reaches this process, but not that `hub.example.com` and
  `*.hub.example.com` resolve to this hub's public address, because the hub does not know its own
  public address. A deployment where only the wildcard record is proxied (Cloudflare's orange
  cloud) is caught today only by the first visitor handshake failing.
- **A compromised hub can impersonate every name under its domain.** §11.3. It is detectable
  (§11.4) but not preventable, because the hub is what decides name ownership. Names that need
  more than this should be user domains, whose keys never leave the node.
- **Raw TCP and UDP links are not end to end unless the app encrypts itself.** §8.4. Plaintext
  exists inside the hub process for protocols that carry no encryption of their own.
- **User domains require port 80 on the hub.** The http-01 relay is the only verification path
  implemented; tls-alpn-01 would remove that requirement.
- **Certificate expiry is not warned about in advance.** Renewal is automatic on both sides (a
  third of the lifetime remaining), but a node that stays offline simply stops renewing, and
  nothing counts down for the operator.
- **There is no standby hub.** Recovery is restoring one directory and changing DNS (§13).
  Active-active would need inter-hub forwarding, because the hub a visitor lands on and the hub a
  node is attached to could differ.
- **Windows virtual threads can stall on bidirectional loopback reads.** §3.3. Not fixable from
  here; the keepalive and read timeout turn it into a reconnect.
- **Node idle RSS is about 24.7 MB, not the 20 MB originally aimed at.** Roughly 7.6 MB of it is
  JSSE initialisation for a single TLS client (§12), so the remaining levers are a wider
  build-time initialisation whitelist and removing unused TLS suites and protocols.
- **Per-visitor memory is about 60 KB on the node.** Mostly the three `ByteBuffer`s a
  `TlsEndpoint` allocates per connection plus the mux stream buffers. Buffer pooling and a smaller
  stream window are the candidates for reducing it.
