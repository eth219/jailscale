# jailscale architecture

A self-hosted HTTPS tunnel. A node runs `jailscale open 3000` and
`https://<name>.<hub-domain>` starts serving whatever listens on that node's local port.
Visitors install nothing. The hub reads the TLS SNI and forwards ciphertext; the node terminates
TLS and asks the hub for one signature per handshake.

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

One server you own runs `jailhub`. Every machine that publishes something runs `jailscale`. It
does what ngrok, Cloudflare Tunnel and Tailscale Funnel do, with no third party in the path.

Three principles, in priority order.

1. **Lightweight.** The node is a resident daemon: one executable, no runtime dependency, small
   idle footprint, millisecond CLI round trips. Measured and gated in CI (§14).
2. **Usability.** Publishing is one line, inviting is one line, and the hub operator sets three
   DNS records and opens two ports. Lengthening that setup list counts as a regression.
3. **Portability.** No root, no TUN device, no kernel module, no inbound port and no UDP on the
   node. A pure-JVM fallback JAR ships beside the native binaries.

Not in scope: a peer mesh VPN, wire compatibility with Tailscale or ngrok or frp, HTTP/2 and
HTTP/3 on the visitor side, mobile clients.

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

Three decisions shape everything else.

- **The hub only reads SNI.** It peeks the ClientHello on 443, finds the name, and hands the byte
  stream to the node that owns it. It never parses visitor HTTP, so its internet-facing attack
  surface is a TCP-level parser and it sees only ciphertext.
- **The node terminates TLS without holding the key.** Every name under the hub domain is covered
  by one `*.hub.example.com` wildcard certificate whose private key never leaves the hub. The node
  asks for the single handshake signature, and the hub signs only when the request is bound to a
  stream it delivered to that node (§9.2).
- **The node does not parse HTTP either.** It strips TLS and copies plaintext to the local port, so
  HTTP/1.1, WebSocket, SSE and chunked bodies all pass. The only HTTP parsers in the system are a
  small one for the control channel and the first-request-head read the visitor gate needs.

**Ports.** TCP 443 for everything, UDP and TCP 53 for ACME DNS-01. TCP 80 is optional (HTTPS
redirect, and the http-01 relay user domains need). Raw TCP/UDP publishing adds one port range. The
node needs outbound 443 and nothing else.

**Terminology.** A local port exposed to the internet is a **link**, opened with `jailscale open`.
Invite links (§10) and visit links (§9.4) are different things.

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
| Reflection, dynamic proxies, dynamic class loading | Forbidden. Metadata upkeep, binary bloat, and effectively impossible under native-image |
| DI framework | None; constructors wired by hand. Spring and Guice are reflection engines |
| JSON | Own parser and hand-written encoder. Jackson means reflection and megabytes for about a dozen schemas |
| HTTP server | Own minimal HTTP/1.1 in `hub`. `com.sun.net.httpserver` will not hand back the socket after an Upgrade |
| HTTP client | Own HTTP/1.1 over `SSLSocket` with chunked decoding. Needed for Upgrade, and it keeps `java.net.http` out of both binaries |
| TLS | JDK JSSE: `SSLServerSocket` on the hub, `SSLEngine` on the node. Already in the image |
| Remote signing | Own JCE `Provider`, opaque `PrivateKey`, `Signature` SPI: the path PKCS#11 keys take. Registered by overriding `Provider.Service.newInstance`, so no reflection |
| ACME client, DNS responder | Own. Only PKCS#10 DER and the DNS answers are genuinely hand-written |
| Logging | Own small logger over `System.Logger`. SLF4J plus logback means ServiceLoader and reflection |
| Cryptography | JDK JCE for X25519 and ChaCha20-Poly1305; own BLAKE2s, HMAC and HKDF. BouncyCastle is large and awkward here, and the three hand-written pieces are forced: the JDK has no BLAKE2s, and Noise defines HMAC and HKDF over the chosen hash. Noise's HKDF also differs from RFC 5869 (an output counter byte instead of salt and info, at most three chained outputs) |
| AWT, `java.awt.Desktop` | Forbidden. Browsers open through `ProcessBuilder` |
| IPC | AF_UNIX on every platform. Windows 10 1803+ supports it; named pipes have no public JDK API |
| Threading | Virtual threads throughout. There is no packet hot path (§12) |
| Build-time initialisation | Whitelisted carefully; JCE initialises at run time, so no SecureRandom seed is frozen into the image |

### 3.2 Build and toolchain

**Maven**, not Gradle: with zero third-party dependencies there is nothing for Gradle's dependency
and build-logic flexibility to do, and a fixed lifecycle drifts less across five platforms.
`native-maven-plugin` is maintained by the GraalVM team. `./mvnw` runs in **only-script** mode, so
no binary jar is committed, because a project that ships signed binaries should not carry a jar
whose provenance it cannot check; the Maven distribution it fetches is pinned with
`distributionSha256Sum` and a wrong value makes the wrapper refuse to run. Keeping the supply-chain
surface at zero is the point of this section. The default profile is a plain JVM build, `-Pnative`
produces the binaries, CI covers linux/macos on amd64 and arm64 plus windows-amd64, and each
release also ships `jailscale.jar` and `jailhub.jar` for JVM 25.

**JDK 25.0.0 through 25.0.2 must not be used.** Moving virtual-thread timed park onto ForkJoinPool
delayed tasks (JDK-8351927) introduced two regressions: cancelling a delayed task corrupts the
scheduler heap so other threads' `Thread.sleep` wakes late or never (JDK-8370887), and virtual
threads get stuck PARKED (JDK-8369227). Both are fixed in 25.0.3. Hand-off cancels the old
connection's keepalive sleep by interrupt, which is exactly that path, so the release workflow
builds on Liberica NIK (JDK 25.0.4+).

**On Windows, virtual threads can miss a bidirectional loopback read**: the reader parks and never
wakes. It reproduces without any jailscale code, so it is handled by detection and recovery. The
60 s socket read timeout (§5.1) and the 25 s keepalive (§5.3) close the session with `peer idle too
long` and the node reconnects. Repro in `docs/windows-virtual-thread-stall/`.

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

The JDK's HTTP stack cannot be used at either end: `com.sun.net.httpserver` does not release the
socket after an Upgrade and `java.net.http.HttpClient` does not hand back the connection after a
101. The hub's front is about 300 lines serving `/v1/key`, `/v1/noise`, `/join/<token>`,
`/admin/*` and a root page; the node's client is about 40. The socket read timeout is 60 s.

WebSocket was rejected as the carrier: the JDK client's convenience does not survive contact with a
40-line client, the 4-byte client-to-server masking would touch every visitor byte again, and frame
headers, fragmentation and close semantics come along with it. It would only help behind proxies
that pass `Upgrade: websocket`, and SNI passthrough already rules out an HTTP proxy in front of the
hub (§7.2). ALPN is pinned to `http/1.1`, because HTTP/2 has no Upgrade.

**Noise parameters.** `Noise_IK_25519_ChaChaPoly_BLAKE2s`, prologue `jailscale-control-v1`. The
version string is mixed into the handshake hash, so incompatible versions fail the handshake itself
rather than something later. A Noise transport message is at most 65535 bytes, which is why the
length prefix is two bytes.

**Why keep the TLS.** Noise alone authenticates the channel. TLS stays because the hub-key
bootstrap needs some reason to trust a first contact and web PKI is it, because `/join` and
`/admin` are browser paths, and because corporate firewalls pass TLS on 443 while dropping
unidentifiable binary streams. The hub obtains the certificate itself, so this costs the operator
nothing.

**Why put Noise inside it anyway.** The web PKI threat model still contains CA compromise and the
corporate MITM proxy with its root installed. Both defeat TLS; neither defeats a Noise handshake
against a pinned hub key. This is the same shape as Tailscale's ts2021, and it matters here because
**signature delegation flows over this channel** (§9.2): requests for the wildcard key need
authentication that does not depend on a CA.

### 5.2 Hub key bootstrap and rotation

A node needs one hostname, which the invite link carries. It fetches `GET /v1/key` over ordinary
verified TLS, pins the returned `hkey:` in `node.json`, and from then on every `/v1/noise`
handshake uses the pinned key. A mismatch is a hard failure with a warning.

`jailhub key rotate --grace 30d` generates a next key and announces it as
`HubKeyRotation{nextHubKey, activatesAt}`. It arrives inside a channel already authenticated by the
old key, so it needs no separate signature. During the grace period the hub's responder tries each
candidate static key against message 1 and only the right one decrypts; the node tries current then
next. After `activatesAt` the old key is dropped. A node that never connected during the grace
period fails with both keys, and only then is the operator asked to re-trust the hub; an unattended
node stays failed and logs why.

`--hub-key hkey:...` skips the `/v1/key` fetch for air-gapped or PKI-distrusting deployments, since
Noise then completes server authentication on its own. Passing the hub key as a clickable
`https://...?key=` URL is deliberately unsupported: people do not verify things that look like
links. An invite is a secret, so a link is the right carrier; a hub public key must be checked, so a
link is the wrong one.

### 5.3 Stream multiplexer

One Noise channel carries many byte streams, one per visitor connection. The protocol sits at
roughly the level of yamux, about 500 lines. Frames are
`[4B streamId][1B type][1B flags][2B len][payload]`, exactly one frame per Noise message. DATA
payloads are capped at 16 KB, because filling 65535 would let one stream monopolise the channel. A
stream with the `DGRAM` flag treats one DATA frame as one datagram (§8.4).

| Type | Payload | Meaning |
|---|---|---|
| `OPEN` | `{linkId, kind, sni, visitorAddr, visitorPort, keyId}` | Hub to node: a visitor connection is delivered |
| `DATA` | bytes | Stream data |
| `WINDOW` | `[4B delta]` | Flow-control window increase |
| `CLOSE` / `RST` | none / `[1B reason]` | Half close (a FIN) / forced teardown |
| `CTRL` | JSON | **Stream 0 only.** The messages of §6.1 |
| `KEEPALIVE` | none | Every 25 s |

- **Flow control** is per stream: a 256 KB receive window refilled with a `WINDOW` frame once half
  has been consumed. A sender out of credit stops, which is what keeps one slow visitor from
  stalling the others. There is no retransmission, because the carrier is TCP.
- **Stream ids.** The hub opens even ids, the node odd ones, 0 is control. The node opens none
  today; the parity rule is enforced on receipt so a peer cannot claim ids that are not its to
  allocate.
- **Multiple connections per node.** One connection for every stream means head-of-line blocking on
  loss and a ceiling of one TCP flow's throughput. A node may open N connections, default 1 and up
  to 4 with `--connections`. Each is a complete Noise channel announcing its index in
  `Hello{conn}`, and the hub treats connections sharing a MachineKey as one **group**. Stream 0
  exists only on connection 0; a visitor stream goes to the least loaded connection. Stream ids are
  globally disambiguated as `(conn << 24) | localId`, so the hub always knows which connection owns
  a stream. If connection 0 dies the whole group is torn down and the node reopens.
- A second connection with the same MachineKey and `conn` index wins; the old one gets
  `Goodbye{shutdown}` and its streams are reset. `TCP_NODELAY` is set.

---

## 6. Control API and hub state

### 6.1 Messages

JSON on **stream 0**, each `{"t": "<type>", ...}`.

| Message | Role |
|---|---|
| `Hello` / `HelloResponse` | Version negotiation: `proto`, `version`, `os`, `conn`; the reply adds `minProto` and `dnsSuffix` |
| `Goodbye` | `upgrade-required`, `revoked`, `shutdown`, `draining`, plus an optional human `detail` |
| `RegisterRequest` / `RegisterResponse` | hostname, os, self-chosen user, and one of `invite` / `code` / `authKey` or none to knock. Reply is `approved{nodeId, user}`, `pending` or `rejected{reason}` |
| `CertUpdate` | Wildcard chain (public part) and its `keyId`, on connect and on renewal |
| `LinkOpen` / `LinkOpened` | `kind: https\|tcp\|udp`, optional name, domain, port, local target, and for user domains the certificate chain. Reply carries `linkId` and a URL or hub port, or a reason |
| `LinkClose` | Stop serving; name and port ownership survive |
| `LinkRevoked` | A name, domain or port is no longer served by this node (§11.5) |
| `SignRequest` / `SignResponse` | `streamId`, `keyId`, `alg`, `digest`; then a signature or a reason (§9.2) |
| `ChallengeSet` / `ChallengeClear` | Register or drop a user-domain http-01 token (§8.3) |
| `InviteCreate` / `InviteCreated` | A member node issuing an invite (§10) |
| `AdminLinkRequest` / `AdminLink` | One-shot `/admin` login URL for an admin node |
| `HubKeyRotation`, `Ping` / `Pong`, `Ack` / `Error` | §5.2; on-demand round trip; generic replies |

**Versioning.** `proto` versions the message schema and the frame set together, and the hub accepts
`minProto` and above. Below that it answers `Goodbye{upgrade-required}` **as the handshake reply**,
so the node never sees a `HelloResponse` and cannot learn `minProto` or the hub version from it.
`detail` therefore carries the required protocol number, the hub version and what to do next; the
node prints it verbatim, keeps it in `status` as `lastError`, and stops reconnecting. A one-word
reason in a log leaves the user with nothing to act on. A node announcing a newer `proto` drops to
the hub's. The prologue number changes only when the Noise parameters change.

### 6.2 Storage

An append-only JSON Lines event log plus in-memory state, replayed at startup. Events are fsynced;
snapshots go to a temporary file and are renamed. `jailhub serve` is the only writer, and admin
commands ask the running server over IPC.

```
$JAILHUB_STATE/            (default /var/lib/jailhub, else ~/.local/share/jailhub)
├── hub.key                hub static private key (0600); hub.key.next during a rotation
├── state.jsonl            event log (node-registered, name-claimed, invite-created, ...)
├── state.snapshot         periodic snapshot (log compaction)
├── jailhub.lock           process lock; a second `jailhub serve` fails immediately
├── jailhub.sock           admin IPC socket (§6.3)
└── tls/                   account.key, wildcard.key, wildcard.pem, wildcard.key.prev (0600)
```

**Format version.** The snapshot carries a `v`, and the hub **refuses to start** when it is higher
than the version it understands. Adding fields or events within a version is compatible both ways
and unknown events are skipped with a warning, so a rollback is safe in that range. `v` is bumped
only for changes that would make an older binary *misread existing data*. A hub that cannot read its
state should stop rather than come up holding part of it.

In-memory state is maps: nodes by MachineKey, names, user domains, port assignments, invite and
auth-key hashes, admins, the pending queue, and undelivered revocation notices. Maps are the
simplest thing that works up to thousands of names.

### 6.3 Admin IPC and admin web

Admin commands are separate processes and the state is in memory, so they talk to the running server
over an AF_UNIX socket at `$JAILHUB_STATE/jailhub.sock`, mode 0600. **The socket file permission is
the authorisation.** The protocol is line-delimited JSON reusing the `proto` codec, covering `node`,
`name`, `domain`, `user`, `invite`, `authkey`, `admin`, `key rotate`, `setting`, `status` and
`handoff`. Settings that change at run time (invite policy, registration mode, knocking) live in the
store; `serve` flags only seed them on first start.

`/admin` exists because an approval queue that can only be drained from a shell on the hub violates
the usability principle. There is no password and no IdP: **an admin node's MachineKey is the
identity**. `jailscale admin` asks for an `AdminLink` over stream 0, the hub returns a 60-second
one-shot URL, and the CLI opens a browser; the visit sets a `__Host-` prefixed session cookie
(`HttpOnly; Secure; SameSite=Lax`, 12 hours). With no node available there is
`jailhub admin login-link` on the hub shell. The pages approve or deny the queue, list and remove
nodes, names and domains, issue invites and auth-keys, and toggle the three settings. It is
server-rendered HTML with no JavaScript, inline CSS, no template engine, and a session-bound CSRF
token on every form.

---

## 7. Certificates and ACME

### 7.1 One wildcard through the hub's own DNS

**Certificates are not issued per name.** Let's Encrypt allows 50 new certificates per registered
domain per week; with a UX that mints a fresh random name on every `open` that is gone in a day, and
each new name would stall for the seconds an ACME round trip takes. One wildcard means issuance
twice a month and a new name that opens in zero seconds.

A wildcard needs dns-01, which normally means a DNS provider API token. Instead **the hub is the
authoritative DNS server for the `_acme-challenge` name** (the acme-dns pattern). The operator
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
for everything else, UDP and TCP), runs the self-check, then issues.

The **self-check** must pass before issuance and retries every 60 seconds on failure. It sets a
random TXT value and asks 1.1.1.1 and 8.8.8.8 for it, which separates a missing NS delegation from a
blocked port 53 from a cached answer. `--no-selfcheck` skips it where hairpinning does not work.

Issuance creates an EC P-256 account key if absent, orders both names, publishes each dns-01 token
as `base64url(SHA-256(keyAuthorization))` in a TXT record, polls the authorizations, generates a new
EC P-256 certificate key, hand-encodes the PKCS#10 CSR, finalizes, downloads the chain, writes it
through temporary files, opens 443 and pushes the chain to every connected node with `CertUpdate`.
Renewal is checked daily and runs when less than a third of the lifetime is left; the previous key
stays usable for 24 hours so in-flight handshakes complete.

- **JWS.** The JDK's `SHA256withECDSA` produces DER and JWS wants the raw 64-byte `R||S`; without
  that conversion the CA rejects every request.
- **CSR.** The JDK has no public PKCS#10 API, so a small DER writer builds the
  `CertificationRequestInfo` with both SANs and signs it with ECDSA.
- **Why ECDSA.** So the delegated private-key operation is exactly one signature. RSA key exchange
  would need a decryption, and the key type excludes those suites (§9.2).
- **Scope.** ACME v2, dns-01 only; no External Account Binding. `--tls-cert/--tls-key` covers
  internal CAs and hosts that cannot open 53, and that certificate must be ECDSA with the wildcard
  SAN.
- **Privileged ports.** On Linux 443 and 53 need root or `CAP_NET_BIND_SERVICE`; the reference
  systemd unit uses a dedicated user with `AmbientCapabilities`. macOS binds unprivileged.
- **No HTTP proxy in front, TCP proxy is fine.** SNI passthrough needs raw TCP 443, so nginx `http`,
  Caddy or Cloudflare Proxied cannot work. A layer-4 proxy that only copies bytes is supported
  (§8.5).
- A node started with `--ca-file` keeps that path in its state and will not recover on its own if
  the hub later serves a certificate from a different CA. Re-running `jailscale up --hub <name>`
  without the flag clears it. This is the usual snag moving from ACME staging to production.

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

After that the hub copies bytes both ways and looks at neither TLS records nor HTTP. A visitor half
close becomes `CLOSE`, an error becomes `RST`. What the hub can see is the SNI, the visitor IP, byte
counts and timing. Not the content.

**Limits.** 64 concurrent connections per visitor IP, 1,024 per name (`SniRouter.MAX_PER_NAME`),
5 seconds to produce a ClientHello, listen backlog 1,024 capped by `somaxconn`. SYN flood defence is
the kernel's job. Loopback is exempt from the per-IP limit, because behind a local proxy without
PROXY protocol every visitor folds into one address; `--proxy-protocol` (§8.5) is the right answer
there and this exemption is the safety net.

**Anything with TLS and SNI works, not just HTTP.** Neither end parses HTTP, so any TLS client that
sends SNI reaches a name: `psql "sslmode=require host=db.hub.example.com"`, MQTT over TLS, gRPC.
Only clients that cannot speak TLS need the raw ports of §8.4.

**Visitors that never close.** Both directions are half closes, so the hub would wait for a visitor
under no obligation to close its own half. A 10-second timer therefore starts **when the node closes
its side**. Because the clock only starts then, streams meant to stay open (WebSocket, SSE, long
downloads) never reach it. Without it a socket, its reader thread and a half-open stream would be
pinned indefinitely.

### 8.2 Names

Format is `<name>.hub.example.com`: lower-case letters, digits and hyphens, up to 40 characters, not
starting or ending with a hyphen, and reserved labels (`hub`, `admin`, `www`, `api`, `ns`,
`_acme-challenge`, `join` and others) are refused. `jailscale open 3000` gets a five-character random
name from a 30-character alphabet with look-alikes removed, and the same node reopening the same
local target gets the same name back, so the URL survives restarts. `--name myapp` binds the name to
the first requester's *user*, so that user's other nodes may use it and another user gets `taken`;
an admin moves it with `name reassign`. A name routes only while the node holds the link open and is
connected; otherwise it stays claimed and visitors see the "not open" page. Opening a name costs one
`LinkOpen` round trip, because the wildcard already covers it. A node may hold at most 20 name and
domain links.

### 8.3 User domains

`jailscale open 3000 --domain myapp.com` publishes a domain the user owns, pointed at the hub with a
CNAME or A record.

When the node has no certificate for it, or renewal is due, the node runs ACME **http-01 with its
own key**. Since DNS points at the hub, the CA's `http://myapp.com/.well-known/acme-challenge/...`
request arrives on the hub's port 80; the node uploads `ChallengeSet{token, keyAuthorization}` (at
most 10 per node, 10 minutes each), the hub answers on its behalf, and `ChallengeClear` removes it.
The hub learns the token and the response string and nothing about the node's key.

Then comes `LinkOpen{domain, chainPem}`. **The certificate chain is the proof of ownership**: the
hub binds the domain only when the chain validates against public roots and its SAN is that domain.
Rejections are `domain-unverified`, `domain-cert-name-mismatch`, `domain-cert-untrusted`, and
`bad-domain` for a name under the hub's own domain. If another node later presents a valid
certificate for the same domain that node wins, because obtaining the certificate is evidence of
controlling the domain.

After that it is pure SNI passthrough: certificate and key exist only on the node, the hub forwards
ciphertext, and there is no `SignRequest`. Rate limits count against the user's own registered
domain, so they are independent of the hub domain's. The node renews on the same third-of-lifetime
rule, checked hourly, and an offline node does not renew. **Port 80 on the hub is a precondition**;
`--http-listen none` means user domains are refused.

### 8.4 Raw TCP and UDP ports

Clients that do not speak TLS (SSH, game servers, plaintext databases, DNS, WireGuard) send no SNI
and cannot be told apart by name, so the hub assigns **a port instead of a name**, the same shape as
ngrok's tcp mode or frp's tcp and udp types.

```
$ jailscale open 22 --tcp
tcp://hub.example.com:10042  ->  127.0.0.1:22
$ jailscale open 51820 --udp
udp://hub.example.com:10043  ->  127.0.0.1:51820
$ jailscale open 22 --tcp --port 10022        # request a specific port in the range
```

- **Port range** `--port-range 10000-10999` by default, or `none` to disable. It must be open for
  both TCP and UDP, its size is the ceiling on concurrent raw links, and an assignment is remembered
  per node, kind and local target. Ports outside the range are not offered; the hub's low ports are
  the hub's.
- **TCP** opens a `ServerSocket` on the assigned port, one stream per visitor connection, no SNI
  parsing and no TLS.
- **UDP** opens a `DatagramChannel`. Each new visitor address gets a `DGRAM` stream and every later
  datagram from that address becomes one DATA frame; the node makes one local UDP socket per stream.
  A visitor address idle for 60 seconds is dropped. The size ceiling is the 16 KB frame cap, well
  above ordinary MTU-sized traffic. Ordering and delivery are stronger than UDP semantics promise,
  never weaker, because the carrier is TCP.
- **Where the plaintext is.** Visitor to hub is exactly what the client sent and hub to node is
  still Noise-encrypted, so plaintext exists **only inside the hub process**, and only for apps that
  do not encrypt themselves. SSH, WireGuard and a TLS-enabled database are effectively end to end
  because the hub sees only the app's ciphertext; plaintext protocols are visible to the hub. This
  cannot be fixed without the visitor's client cooperating, and it is the same for ngrok and frp.
  `open --tcp/--udp` says so in its output; a client that can speak TLS should use the 443 path.

### 8.5 Behind a TCP proxy, and PROXY protocol

An operator whose server already runs nginx or HAProxy on 443 can put the hub behind it, provided
the proxy **forwards TCP bytes without opening TLS**. Reference configs ship in
`deploy/nginx-stream.conf` and `deploy/haproxy.cfg`, including an `ssl_preread` example that routes
only the hub's names to the hub.

The hub runs as `--listen 127.0.0.1:8443 --proxy-protocol` and reads a PROXY v1 or v2 header at the
start of each connection to learn the visitor address. Because the header is only trustworthy from a
trusted proxy, `--proxy-protocol` is accepted only when `--listen` is on loopback or
`--trusted-proxy <cidr>` is given, and connections from untrusted peers are refused outright.
Otherwise anyone could forge a visitor address. The parser takes v1 text and v2 binary (IPv4, IPv6,
LOCAL), and v1 addresses must be **literals**: allowing hostnames would put a DNS lookup on the
accept path where an attacker could stall the hub (fuzzing found that one).

A hub with `--proxy-protocol` on rejects header-less connections, so the node's control connection
must also come through the proxy. The address derived from the header is what the rate limits, the
knock queue and the session logs use, so nodes behind one proxy are not collapsed into one address.
The self-check of §7.2 works unchanged, since it tests whether the public name reaches the hub.

---

## 9. The node

### 9.1 Publishing

```sh
$ jailscale open 3000
https://q7x2k.hub.example.com  ->  127.0.0.1:3000        (copied to the clipboard)

$ jailscale open 3000 --name myapp         # chosen name
$ jailscale open 3000 --gate               # visitor gate; prints a visit link too
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
                                                  │  transcript hash h
                                                  ├──SignRequest{streamId, keyId, alg, h}──> hub
                                                  │                          checked, then signed
                                                  <──SignResponse{streamId, sig}─────────────┘
                                                  │  ServerHello ... CertificateVerify(sig) ... Finished
visitor <──────────────── hub <──bytes──────────  node
```

The `SSLContext` is built from the chain the hub sent in `CertUpdate` and an **opaque `PrivateKey`**
holding no bytes, only a `keyId`. A small JCE provider offers `Signature.SHA256withECDSA` for that
key type, and JSSE's delayed provider selection picks it, which is the mechanism PKCS#11 keys rely
on. `engineSign()` sends a `SignRequest` on stream 0 and blocks for the reply, which costs nothing
on a virtual thread. The service is registered by subclassing `Provider.Service` and overriding
`newInstance`, so no reflection is involved.

**The four conditions that stop a signing oracle.** The hub sees only a transcript hash, so it
cannot tell which SNI a handshake belongs to. Signing unconditionally would give every member node
an oracle for the whole wildcard, and anyone able to spoof a visitor's DNS could then impersonate
someone else's name. So the hub signs only when all of these hold:

1. `streamId` names **a stream this hub opened on this connection**, still open.
2. The `sni` recorded in that stream's `OPEN` maps to a name currently **assigned to this node**.
3. That stream has used fewer than 4 signatures. A normal TLS 1.3 handshake uses one, and two covers
   HelloRetryRequest.
4. The node is within its signing rate: a token bucket of 2,000 with 1,000 per second sustained,
   sized from a load test where 1,000 visitors handshake at once. Resumption needs no signature.

Both peers' randoms are in the transcript, so a signature cannot be replayed on another connection.
A node therefore gets signatures only for connections the hub delivered to it, and the only name it
can impersonate is its own.

**Keeping it to one signature.** The certificate is ECDSA P-256, so in TLS 1.3 and TLS 1.2 ECDHE the
private-key operation is a single signature and RSA key exchange is excluded by the key type.
Session tickets are generated by the node and kept in memory, so a resumed handshake never touches
the hub. 0-RTT is off, and ALPN offers only `http/1.1`, because negotiating h2 would break a local
app that speaks h1.

**Key rotation.** `CertUpdate` carries a `keyId` (a certificate fingerprint); the node starts new
handshakes with the newest one and echoes it in `SignRequest`. The hub keeps the previous key for 24
hours, so a handshake begun just before a renewal still completes.

Each first handshake from a visitor adds one node-to-hub round trip, the same cost Cloudflare
Keyless SSL pays. A user-domain stream arrives with `keyId = domain:<domain>` and is terminated with
the node's own real key, with no hub involvement.

### 9.3 Relaying

Once TLS is off the node **copies bytes**: visitor plaintext to `127.0.0.1:<port>` and local
responses back. HTTP/1.1 keep-alive, chunked bodies, WebSocket upgrades and SSE all pass through
because the local app handles them. `open --proxy-protocol` prepends a PROXY v1 line so the local
app learns the visitor address, using the `visitorAddr` and `visitorPort` the hub put in the stream
metadata; raw TCP links behave the same way.

A refused or reset local connection is retried five times with 50 ms doubling (about 1.5 s) before
giving up, because a burst of visitors really does overflow a small listen backlog (macOS defaults
to 128) and it surfaces as an immediate refusal. Only after that does the visitor get a 502 page.
That page and the gate are the only two places where the node *writes* HTTP, and only on https
links: a raw TCP stream copies bytes with no TLS, and a raw UDP stream turns one DATA frame into one
datagram.

### 9.4 Visitor gate

A link that should not be public is locked behind a visit link, with the same capability model as
invites. `jailscale open 3000 --gate` prints
`https://q7x2k.hub.example.com/?jail=<token>` alongside the public URL, and
`jailscale gate <name> --new-link --ttl 7d` or `--off` manages it afterwards.

Immediately after TLS termination the node reads only **the first request head** of the connection
(request line and headers, at most 16 KB). A valid `Cookie: jail=<token>` lets the whole connection
through, because the same TCP connection is the same client. A valid `?jail=<token>` query gets
`Set-Cookie: jail=...; Path=/; Secure; HttpOnly; SameSite=Lax` and a 302 to the same path without
the token, then closes. Neither one gets a 403 page and a close.

Tokens are 128-bit and the node stores only a SHA-256 hash. The hub knows nothing about gates,
because it only sees ciphertext; keeping the gate on the node is the position consistent with
end-to-end encryption. Bodies are never read, so HTTP parsing stops at the blank line.

### 9.5 Daemon and CLI

`jailscale` is one binary with two roles. `jailscale daemon`, or a registered service, stays
resident; every other subcommand talks to it over **local IPC**: an AF_UNIX socket at
`$XDG_RUNTIME_DIR/jailscale.sock` or next to the config file (0600), Windows included, carrying
line-delimited JSON with streaming replies for progress output. Commands are `up`, `down`, `status`,
`open`, `close`, `ls`, `gate`, `invite`, `admin`, `netcheck`, `verify` (§11.4), `leave` and
`service install|uninstall|status`. Service registration uses only what the OS already has (a
launchd agent, a `systemctl --user` unit, or a logon scheduled task) with no service wrapper.

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

**Invites are not admin-only.** By default any member issues one from their own node, the issuer is
recorded, and an admin can narrow it with `--invite-policy admins`. `jailscale invite` prints a link
carrying a 128-bit token (one use, 24 hours by default) and a short code that is an alias for the
same invite: 40 bits in Crockford base32 as `XXXX-XXXX`, valid 10 minutes, normalised on entry.
Without `--user` the joiner supplies the name. The hub stores only hashes. An **auth-key**
(`jk_` plus 128 bits) is the unattended form for CI jobs, containers and servers, optionally bound
to a tag instead of a person.

**Joining.** `jailscale up --invite <link>` takes the hostname from the link, pins the hub key
through `/v1/key` (§5.2), opens the Noise channel, negotiates versions, asks for a name only when
the invite does not fix one, and sends `RegisterRequest`. The hub matches the token hash, checks
expiry and remaining uses, decrements, assigns a node id, and replies `approved` followed by
`CertUpdate`. No browser opens, so a headless server runs the same command; opening `/join/<token>`
in a browser shows install instructions and never consumes a use. An attacker can hand out an invite
to their own hub, so the CLI prints which hub it is about to join and asks for confirmation, and
even if the victim joins nothing local is exposed until they run `open`.

**Knocking.** With only the hostname a node can knock: the hub queues MachineKey, hostname, OS,
source address and self-chosen name, and an admin approves through `/admin` or `jailhub node
approve`, which is pushed over the already-open stream 0. Knocking is unauthenticated, so pending
entries are capped at 5 per source address, and `--knock off` disables it. `--registration open`
suits a personal hub or small team where the gate is overhead: a knocking node is approved
immediately. The default is still invite-only, and turning it on prints the consequence, which is
that anyone who knows the hostname can open names under `*.hub.example.com`. There is deliberately
no web signup form, because that would be the same thing with more code.

**First bootstrap.** When `jailhub serve` finds no admin it prints a one-use 24-hour invite on the
console, and whoever joins with it becomes an admin. If every admin node is lost,
`jailhub admin login-link` on the hub shell recovers access, because shell access is the top of the
authority chain. Nodes do not expire by default; an admin removes them with `node remove`.

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

The wildcard private key exists only on the hub, and a node gets a signature only for a stream the
hub delivered to it whose SNI is one of its own names (§9.2). So a compromised member node gains
impersonation of **its own names**, which were already its own. Because the control channel is
pinned to the hub key by Noise, a MITM proxy that defeats TLS still cannot intercept or forge
signing requests. The hub checks every request against stream, name, count and rate and logs
refusals; a node that keeps being refused is disconnected and flagged.

Separately, joining opens no port on the node. Only the port named in `jailscale open` is reachable,
and only while that link is open. There is no TUN device, so there is no OS routing path to leak
through: a visitor reaches exactly the one `host:port` the node named, never its other services or
its LAN.

### 11.3 The hub is trusted

Stated plainly. If the hub is compromised:

| It cannot | It can |
|---|---|
| Read visitor traffic to an honest node (the node terminates it) | **Reassign a name to an attacker node** and sign with the wildcard key, intercepting that name entirely. Not preventable, but detectable (§11.4) |
| Obtain a node's MachineKey or user-domain keys (it never has them) | Register arbitrary nodes and issue invites at will |
| Reach local services a node has not published | See who connected to which name, when, and how much |

The hub is the TLS authority for its own domain, so its compromise is impersonation of every name
under it. User domains are the exception, since their keys live on the node and a compromised hub
can only stop routing them. For a self-hosted deployment where the hub operator *is* the
organisation this matches the usual threat model, and names needing more should be user domains.

**Preventing and knowing are different.** The hub decides who owns a name, so it cannot be stopped
from reassigning one. §11.4 makes the node notice instead.

### 11.4 Self-probe

The node connects to its own public name and checks whether it terminated that TLS session itself.
The command is `jailscale verify`. The mechanism is RFC 5705 exported keying material: both ends of
a TLS 1.3 session derive the same bytes from a label, and a third party that did not terminate the
session cannot.

1. The node records the exported value of every visitor session it terminates, immediately after the
   handshake, keeping the last 120 seconds and at most 4,096 entries.
2. `jailscale verify` connects to each open https link **by its public name**, at the hub address,
   so it genuinely traverses the hub.
3. It sends `GET /` and waits for the response. A response means the server side already finished
   its handshake and recorded it, which removes the race between steps 1 and 4.
4. If the exported value is in the record the verdict is `terminated by this node`; otherwise
   `TERMINATED ELSEWHERE`. The comparison uses `MessageDigest.isEqual`.

If a hub holding the wildcard key terminates the name itself or hands it to another node, the
certificate the visitor sees is still valid but the session is a different one, so its exported
value is not in the record. A hub that decrypts and re-encrypts is caught for the same reason.

**Limits.** The probe leaves the node's own address, so a hub that singles those connections out and
routes only them correctly is not caught, though doing so requires discriminating between visitors,
which is itself detectable. `--tls-insecure` or a stale `--ca-file` blinds the probe. TLS 1.2 and
below cannot export the material, and the verdict is then `keying material unavailable`.

**Relation to §11.1.** The four signing conditions are enforced by **the hub**, so they stop a rogue
*node* and say nothing about a rogue *hub*. The self-probe runs on **the node**. They do not
overlap; they face opposite directions.

### 11.5 Name revocation notices

The self-probe only runs when someone types `jailscale verify`, so an **honest hub announces a name
change in advance** with `LinkRevoked{linkId, name, reason, at}`, where `reason` is `reassigned`
(another node opened the same name) or `released` (an operator took it back). A compromised hub
simply does not send it: this is incident notification, not attack detection. Catching a compromised
hub is §11.4, and the two have different jobs.

**The trigger is stored ownership, not a live link.** That distinction is the whole design. A node
losing a name is usually **offline**, and being offline is exactly why someone else took the name,
so at that moment there is no live link to look at. `Links.open` therefore watches for the stored
claim's MachineKey changing and notifies the previous one; domains and raw ports use the same rule
against their own records.

**Delivery.** A connected node gets the notice immediately, otherwise it is stored and handed over
on the node's next connection, then cleared. Clearing happens only after everything has been sent,
so a node that dies mid-delivery hears it again, and a node that never returns is capped at 20
stored notices, oldest dropped first.

**On the node.** The name is removed from local state, because leaving it would silently reopen it
on the next reconnect and make the notice pointless. It is also recorded under `revoked` so `status`
keeps saying so after the log line has scrolled away, and deliberately reopening the name clears the
warning, since that is the answer to it. `name release` and `domain release` take the live link down
and send the notice rather than quietly clearing ownership while the old node keeps serving. Release
is not a ban: the name is free, so the same node may reopen it. Banning a node is `node remove`.

### 11.6 Abuse and rate limits

A public link can host a phishing page. The operator can release the name and remove the node.
Random names are five characters and hard to guess, chosen names exist only for members, and the
structural limits are 1,024 connections per name and 20 links per node. Beyond that, abuse response
is the operator's job.

Unauthenticated work is metered with per-source token buckets:

| Target | Burst | Sustained | On excess |
|---|---|---|---|
| `/v1/noise` handshake | 30 | 1/s | HTTP 429, Upgrade refused |
| Credential presentation (invite token, code, auth-key) | 20 | 0.2/s | `rejected{reason: rate-limited}` |
| Knock queue | 5 entries per address | n/a | `rejected{reason: too-many-pending}` |

A node the hub already knows returns before the credential check, so reconnections never touch the
bucket. The bursts are generous because a node opens up to four connections and a NAT can hide many
nodes behind one address; the sustained rate is what limits abuse. To stop an attacker inflating the
map by rotating addresses, once more than 10,000 keys are tracked the full buckets are dropped: a
full bucket is indistinguishable from one that never existed, so nothing is lost.

**`/admin` sessions.** The login link is one-shot and lives 60 seconds, the session cookie lasts 12
hours, and every POST carries a CSRF token. On top of that, **admin status is rechecked on every
request**, because checking only at issuance would leave `admin remove` ineffective for 12 hours; a
link issued over the IPC socket is exempt, since socket permission is the authorisation. The cookie
uses the `__Host-` prefix, which forbids a `Domain` attribute, so a node controlling a sibling
subdomain under `*.<hub>` cannot plant an admin cookie. Auth-keys, invite tokens, codes, gate tokens
and admin login URLs are never written to logs.

---

## 12. Threading and memory

There is no packet hot path, so there is no reason to insist on platform threads. The hub's 443
accept loop is the one platform thread. A visitor connection uses two virtual threads, one per
direction, at both ends. Each mux connection has a virtual reader plus a virtual keepalive, and
writes run on the producing thread under a lock, because the Noise nonce counter must advance in
wire order. The hub's own HTTP, ACME, port 80, DNS and both IPC servers use one virtual thread per
request. Remote signing blocks on the calling thread, which is free on a virtual thread.

Buffers are 16 KB per direction, allocated per stream, and the per-stream flow-control window is
256 KB.

Memory is bounded by the connection limits, not by a heap cap, and the images deliberately set **no
fixed heap maximum**. Concurrency scales with the number of names: the hub accepts 1,024 per name
and a node can hold 20, so one node's ceiling is 20,480 concurrent streams and the hub's is that
times the number of names it serves. No single byte figure covers that range correctly. A
memory-tight host sets its own limit, for example `jailhub serve -Xmx256m`.

Two consequences worth knowing. Serial GC does not return the heap to the OS, so RSS stays at its
high-water mark after a load burst; that is headroom, not a leak. And idle RSS is unrelated to heap
size: the node daemon alone is about 16.7 MB and reaches about 24.3 MB the moment it connects, so
roughly 7.6 MB is JSSE initialisation for one TLS client. Lowering the heap cap does not move it.

---

## 13. Availability and hand-off

The hub is one process on one host. The main deployment is a single self-hosted VPS, and at scale
one hub handles thousands of nodes and tens of thousands of streams, because all it does is copy
bytes and sign. What remains is availability, and the answer is fast recovery.

| Item | Target |
|---|---|
| Hub process restart | Under 5 s including state replay. Nodes reconnect with 1, 2, 4, 8, 16, 30 s backoff |
| What a visitor sees | Connections refused during the restart; streams in flight are cut |
| Backup unit | The `$JAILHUB_STATE` directory. `hub.key`, `tls/` and `state.*` are all of it |
| Host replacement | Copy the directory and change DNS. Nodes notice nothing, since the hub key and wildcard key are unchanged |

**Hand-off.** Updating the binary does not need a restart. `jailhub serve --takeover` starts a new
process that asks the old one to hand off over the IPC socket. The old process closes the 443
listener, the raw ports, port 80, the DNS responder and ACME, snapshots its state, releases the
state lock, and sends `Goodbye{draining}` to every node; visitor streams already in flight keep
flowing on those connections, and no new ones are opened on them. The new process takes the lock,
replays the state and opens 443, and for the few hundred milliseconds in between new visitors are
refused (`SO_REUSEADDR` means no bind wait). On `draining` a node immediately opens a fresh
connection and reopens its links, keeping the old connection until its open streams finish, and a
signing request goes to the connection that owns the stream, which is what makes a draining stream's
signature findable. The old process exits when the draining connections are empty or after 60
seconds, and deletes the IPC socket file only if it is still its own (compared by inode) so it
cannot remove the new process's socket.

A visitor sees a few hundred milliseconds of refused connections, and downloads and WebSockets in
flight are not cut. Nodes reconnect with no backoff, and deploy and rollback are the same one line.
The router's 3-second wait for a claimed but momentarily offline name (§8.1) keeps the gap from
becoming an error page.

---

## 14. Current characteristics

Measured on arm64 macOS with the native binaries by `./measure.sh`, which starts a real hub and two
node daemons on loopback, joins them with the real CLI and opens a link.

| Measurement | Current | Budget |
|---|---|---|
| Binary size | 25.0 MiB (`jailhub`), 25.3 MiB (`jailscale`) | 30 MiB |
| Node idle RSS | about 24.7 MB | 28 MB |
| Hub idle RSS | about 24.7 MB | 30 MB |
| RSS with 1,000 visitor sessions held open | node 87 MB, hub 77 MB | node 192 MB, hub 160 MB |
| CLI cold start | about 6 ms (`jailscale status`, median of 10, IPC round trip included) | 50 ms |

`./measure.sh --check` fails when a number exceeds its budget and runs in CI. The budget values live
at the top of the script and must match this table; they change only by a PR that states a reason.

**Load is measured with the connections held open.** An earlier gate fired 1,000 short requests with
`curl --parallel` and finished, which means 1,000 were never alive at once and the figure was
roughly a third of the real number. `tools/hold-visitors.py` now keeps all 1,000 open and samples
peak RSS during that time, ramping in batches of 100 because bursts larger than the kernel accept
queue are reset before they reach jailscale.

Structural ceilings that go with these numbers: 1,024 concurrent visitors per name
(`SniRouter.MAX_PER_NAME`), 20 links per node, up to 4 control connections per node.

---

## 15. Limits

- **The self-probe is manual.** §11.4 runs only when someone types `jailscale verify`, so nothing
  detects a hub-side interception in between. The interval for running it periodically has to scale
  with the number of open names: short adds self-traffic, long delays detection.
- **The self-check does not verify A records.** It proves the `_acme-challenge` delegation reaches
  this process, but not that `hub.example.com` and `*.hub.example.com` resolve to this hub, because
  the hub does not know its own public address. A deployment where only the wildcard record is
  proxied is caught today only by the first visitor handshake failing.
- **A compromised hub can impersonate every name under its domain** (§11.3). Detectable (§11.4) but
  not preventable, because the hub is what decides name ownership.
- **Raw TCP and UDP links are not end to end unless the app encrypts itself** (§8.4).
- **User domains require port 80 on the hub.** The http-01 relay is the only verification path
  implemented; tls-alpn-01 would remove that requirement.
- **Certificate expiry is not warned about in advance.** Renewal is automatic on both sides at a
  third of the lifetime remaining, but a node that stays offline stops renewing and nothing counts
  down for the operator.
- **There is no standby hub.** Recovery is restoring one directory and changing DNS (§13).
  Active-active would need inter-hub forwarding, since the hub a visitor lands on and the hub a node
  is attached to could differ.
- **Windows virtual threads can stall on bidirectional loopback reads** (§3.2). Not fixable from
  here; the keepalive and read timeout turn it into a reconnect.
- **Node idle RSS is about 24.7 MB, not the 20 MB originally aimed at.** Roughly 7.6 MB is JSSE
  initialisation for a single TLS client (§12), so the remaining levers are a wider build-time
  initialisation whitelist and removing unused TLS suites and protocols.
- **Per-visitor memory is about 60 KB on the node**, mostly the three `ByteBuffer`s a `TlsEndpoint`
  allocates per connection plus mux stream buffers. Buffer pooling and a smaller stream window are
  the candidates for reducing it.
