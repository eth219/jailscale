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
3. **Portability.** No root, no TUN device, no kernel module, no inbound port and no UDP on the
   node. A pure-JVM fallback JAR ships beside the native binaries.

Out of scope: a peer mesh VPN, wire compatibility with Tailscale or ngrok or frp, HTTP/2 and HTTP/3
on the visitor side, mobile clients.

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
| Threading; build-time initialisation | Virtual threads throughout, because there is no packet hot path (§12); whitelisted carefully, with JCE initialising at run time so no SecureRandom seed is frozen into the image |

### 3.2 Build and toolchain

**Maven**, not Gradle: with zero third-party dependencies there is nothing for Gradle's dependency
and build-logic flexibility to do, and a fixed lifecycle drifts less across five platforms. `./mvnw`
runs in **only-script** mode so no binary jar is committed, because a project that ships signed
binaries should not carry a jar whose provenance it cannot check, and the Maven distribution it
fetches is pinned with `distributionSha256Sum`. Keeping the supply-chain surface at zero is the point
of this section. `-Pnative` produces the binaries, CI covers linux and macos on amd64 and arm64 plus
windows-amd64, and each release also ships `jailscale.jar` and `jailhub.jar` for JVM 25.

**Two workflows, two jobs each way round.** `ci` is the gate: the tests on ubuntu and macos for
every push and pull request, the §14 budget on main and nightly, and Windows nightly rather than
per push, because the Windows stall below fails about 2% of runs through no fault of ours and a
gate that is red 2% of the time teaches people to ignore it. `release` builds the five native
targets on a tag. The container images build with `-DskipTests`, deliberately: they are packaging,
not verification.

Two toolchain hazards are load-bearing. **JDK 25.0.0 to 25.0.2 must not be used**: moving
virtual-thread timed park onto ForkJoinPool delayed tasks (JDK-8351927) made cancelling a delayed
task corrupt the scheduler heap, so other threads' `Thread.sleep` wakes late or never (JDK-8370887),
and virtual threads get stuck PARKED (JDK-8369227). Hand-off cancels the old connection's keepalive
sleep by interrupt, which is exactly that path, so the release workflow builds on Liberica NIK (JDK
25.0.4+). And **on Windows a virtual thread can miss a bidirectional loopback read**, parking and
never waking; it reproduces without any jailscale code, so it is handled by detection and recovery,
with the 60 s socket read timeout (§5.1) and 25 s keepalive (§5.3) turning it into `peer idle too
long` and a reconnect. Repro in `docs/windows-virtual-thread-stall/`.

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
  retransmission, because the carrier is TCP.
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
ignores what it does not recognise, so an older build reads the message as it always did. Adding a
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

A link that should not be public is locked behind a visit link, the same capability model as invites.
`jailscale open 3000 --gate` prints `https://q7x2k.hub.example.com/?jail=<token>` alongside the
public URL, and `jailscale gate <name> --new-link --ttl 7d` or `--off` manages it afterwards.
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
Windows included, carrying line-delimited JSON with streaming replies for progress output. Commands
are `up`, `down`, `status`, `open`, `close`, `ls`, `gate`, `invite`, `admin`, `netcheck`, `verify`
(§11.3), `leave`, `update` and `service install|uninstall|status`; service registration uses only
what the OS already has (a launchd agent, a `systemctl --user` unit, or a logon scheduled task) with
no service wrapper.

**`update` reports; it does not install.** It reads the published release index and prints the
version and where to get it, and the daemon does the same once a day so `status` carries the answer
without anyone asking. Replacing the running binary is not implemented and is not a small thing:
`/usr/local/bin` is root-owned while the daemon deliberately runs without root, Windows cannot
replace a running `.exe` in place, a package manager or a container image must not find a second
owner of its file, and a downloaded binary is only worth as much as the signature checked over it —
a checksum published beside it by the same account proves corruption did not happen, not that the
publisher was not compromised. Until that is answered, saying "0.2.0 is out" is the honest amount to
do. The check runs in the CLI process, so it answers while the daemon is down, and a check that could
not be made is an error like any other command's: the reason goes to stderr and the exit status is 1,
so a script can tell "up to date" from "could not tell".

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


## 12. Threading and memory

There is no packet hot path, so there is no reason to insist on platform threads. The hub's 443
accept loop is the one platform thread; a visitor connection uses two virtual threads, one per
direction, at both ends; each mux connection has a virtual reader plus a virtual keepalive, with
writes running on the producing thread under a lock because the Noise nonce counter must advance in
wire order; and the hub's own HTTP, ACME, port 80, DNS and both IPC servers use one virtual thread
per request. Remote signing blocks on the calling thread, which is free on a virtual thread. Buffers
are 16 KB per direction, allocated per stream, and the per-stream flow-control window is 256 KB.

Memory is bounded by the connection limits, not by a heap cap, and the images deliberately set **no
fixed heap maximum**. Concurrency scales with the number of names: the hub accepts 1,024 per name and
a node can hold 20, so one node's ceiling is 20,480 concurrent streams and the hub's is that times
the number of names it serves. No single byte figure covers that range correctly, and a memory-tight
host sets its own limit, for example `jailhub serve -Xmx256m`. Two consequences: Serial GC does not
return the heap to the OS, so RSS stays at its high-water mark after a load burst, which is headroom
and not a leak; and idle RSS is unrelated to heap size, since the node daemon alone is about 16.7 MB
and reaches about 24.3 MB the moment it connects, so roughly 7.6 MB is JSSE initialisation for one
TLS client and lowering the heap cap does not move it.

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

**Readiness is reported, which is a different thing.** The unit is `Type=notify`, so `systemctl
start` returns when the hub is serving rather than when the process exists; on a first boot those
are minutes of ACME apart, and until now systemd called the unit active while there was no
certificate. The notification is sent by running `systemd-notify`, because `NOTIFY_SOCKET` is an
AF_UNIX *datagram* socket and the JDK will not open one, which is why the unit carries
`NotifyAccess=all`: the notification arrives from a child process. It says the hub is up. It does
not make the hand-off compose with a unit, and nothing about the upgrade path changes.

---

## 14. Current characteristics

Measured with the native binaries by `./measure.sh`, which starts a real hub and two node daemons on
loopback, joins them with the real CLI and opens a link. Both columns are measured, on the two
platforms CI can run the gate on; the budgets differ per platform for the reason below the table.

| Measurement | arm64 macOS | linux-amd64 | Budget (macOS / linux) |
|---|---|---|---|
| Binary size | 25.0 MiB (`jailhub`), 25.3 MiB (`jailscale`) | 31.6 MiB, 31.9 MiB | 30 / 36 MiB |
| Node idle RSS | about 24.7 MB | about 39.7 MB | 28 / 46 MB |
| Hub idle RSS | about 24.7 MB | about 40.0 MB | 30 / 46 MB |
| RSS with 1,000 visitor sessions held open | node 93 MB, hub 80 MB | node 90 MB, hub 90 MB | node 192 MB, hub 160 MB |
| CLI cold start | about 7 ms (`jailscale status`, median of 10, IPC round trip included) | about 4.5 ms | 50 ms |

**Linux is not 15 MB heavier; it counts differently.** Of the hub's 40.1 MB there, **6.1 MB is
anonymous** — the heap, the stacks, everything the process actually owns — and the rest is the
31.6 MiB binary's own text and rodata mapped in: clean pages, shared with the page cache, which the
kernel can take back. macOS's `ps` attributes far fewer of those to the process, and the amd64
binary is 6.5 MiB larger than the arm64 one to begin with.

The live hub shows what that means under pressure. On a GCP e2-micro with 969 MB of RAM, after a
day of service, `smaps_rollup` reports 41.1 MB of RSS split into 15.0 MB anonymous and 26.2 MB of
file-backed pages — and only 25.7 MB of the 31.6 MiB binary is still resident, the kernel having
already dropped the rest with no effect anyone can see. The same RSS total came off a 16 GB CI
runner as off the 969 MB instance, so this is accounting and not heap sizing. `measure.sh` prints
the anonymous share on Linux next to RSS, and still gates on RSS so that the two platforms are
gated on the same measurement.

`./measure.sh --check` fails when a number exceeds its budget. The budget values live at the top of
the script and must match this table; they change only by a PR that states a reason. The `budget` job
of the `ci` workflow runs it with `LOAD=1000` on linux-amd64 for every push to main and once a
night; the macOS column is what `./measure.sh` reports on the machine this is developed on.

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
- **User domains require port 80 on the hub.** The http-01 relay is the only verification path
  implemented; tls-alpn-01 would remove that requirement.
- **Upgrading is manual.** `jailscale update`, and the daemon's daily check behind `status`, say that
  a newer release exists and where it is; nothing installs it, for the reasons in §9.4.
- **A certificate that stops renewing is reported, not prevented.** Renewal is automatic on both
  sides at a third of the lifetime remaining. When it does not happen the node logs the name and
  the time left once a day inside the last fortnight, the hub says how long the installed wildcard
  has next to every issuance failure and on its status page, and `ls` marks the link. None of that
  helps a node that stays offline: renewal needs the hub, so the node that cannot renew is the one
  nobody hears from, and its domain goes dark when the certificate runs out.
- **Hand-off does not work under systemd** (§13). Upgrading a unit-managed hub is a restart, so it
  is not zero-downtime. Readiness is reported (`Type=notify`), which is only about when systemd
  calls the unit started; the listening sockets are still rebound rather than handed over.
- **There is no standby hub.** Recovery is restoring one directory and changing DNS (§13).
  Active-active would need inter-hub forwarding, since the hub a visitor lands on and the hub a node
  is attached to could differ.
- **Windows virtual threads can stall on bidirectional loopback reads** (§3.2). Not fixable from
  here; the keepalive and read timeout turn it into a reconnect. In CI it shows up as a
  Windows-only timeout with no assertion failure, seen in both `MuxSessionTest` and `RawPortTest`,
  and any end-to-end test that moves bytes both ways is exposed.
- **Node idle RSS is about 24.7 MB, not the 20 MB originally aimed at**, and about 39.7 MB as
  Linux counts it (§14: mostly the mapped binary, 5 MB of it anonymous). Roughly 7.6 MB is JSSE
  initialisation for a single TLS client (§12), so the remaining levers are a wider build-time
  initialisation whitelist and removing unused TLS suites and protocols.
- **Per-visitor memory is about 60 KB on the node**, mostly the three `ByteBuffer`s a `TlsEndpoint`
  allocates per connection plus mux stream buffers. Buffer pooling and a smaller stream window are the
  candidates for reducing it.
