# Hub redundancy: control plane, relays, and an uptime figure

A design, of which step 1 below is built ([ARCHITECTURE.md §13.1 and §13.2](../ARCHITECTURE.md)):
the hub-to-hub channel, the standby, promotion, and the availability figures. Steps 2 to 4 are not,
and this file is what they would be. It records the shape a two-host hub takes and why, cut so
that each step leaves the single-host hub untouched. Before step 1, §13's answer to losing the host
was "copy the state directory and change DNS"; the standby is that sentence done by the hub itself,
and the DNS change is still the operator's.

## What the split borrows from Tailscale, and what it cannot

Tailscale separates a coordination server, which holds keys and policy and signs the network map,
from DERP relays, which hold nothing and forward encrypted packets. Losing the coordination server
leaves every existing connection working. The part worth taking is the rule **control signs, relay
verifies**: a relay needs no copy of the control plane's state if what it must know arrives signed
by the control plane and is checked with a public key.

Three things do not carry over.

1. **Visitors are browsers.** Both ends of a Tailscale connection run Tailscale, pick a relay by
   latency and route around a dead one. Here one end is whatever `curl` or Chrome does with a DNS
   answer, so which relay a visitor reaches, and what happens when that relay is gone, is a DNS
   question that the split does not touch.
2. **Somebody signs a handshake per visitor.** DERP carries WireGuard packets and is trusted with
   nothing. A jailscale relay delivers a visitor's ClientHello to the node, and the node then needs
   one `CertificateVerify` signature under the wildcard key (§9.2). That signature is bound to the
   stream the relay delivered, which is what keeps a member node from impersonating another name.
   So the wildcard key is on the visitor path once per fresh handshake, and where it lives decides
   what a relay is trusted with. The answer below is: not on the relay.
3. **The control plane still holds the only durable state.** It needs a standby regardless.

Funnel is the closer analogue, and it is worth knowing why it gets a pure relay: each Funnel node
obtains a certificate for its own name, so the ingress routes by SNI and never signs. jailscale's
wildcard exists so that a random name opens in zero seconds rather than after an ACME round trip
(§7.1), and the price of that choice is the signing oracle. User domains (§8.3) already take the
Funnel path -- key on the node, hub only routes -- and a `--name` link could optionally take it too,
since the name already points at the hub and http-01 rides the existing relay path. That is a
separate decision; the design here does not depend on it and does not block it.

## Roles

One binary, two roles, both on by default so `jailhub serve` on one host is exactly what it is now.

**Control.** Owns the state directory: `hub.key`, `tls/`, `state.*`. Approves joins, assigns names,
ports and domains, issues invites and auth-keys, bans, and issues and renews the wildcard through
its own `_acme-challenge` responder. Signs handshakes. Signs *leases* (below). Serves the hub's own
name: control channel, `/join`, `/admin`, `/v1/status`. There is one **primary** control host that
writes, and one **standby** that follows the primary's event log over a hub-to-hub channel, receives
each new certificate the way nodes do (`CertUpdate`), signs handshakes, verifies leases, and can be
promoted. Signing is not a write, so the standby signs while standing by.

**Relay.** Accepts on 443 for the wildcard, reads the SNI, verifies the lease the node presented for
that name, opens a stream on that node, copies bytes. Forwards a node's `SignRequest` to a control
host with the ClientHello it delivered attached. Holds the public certificate chain, the control
plane's public key, and a Noise static key of its own. Nothing durable, no secret whose loss matters
beyond that relay's own identity, and nothing to synchronise before it can serve.

The recommended minimum is **two hosts, each running both roles**, one of them primary:

```
                       jailscale.example.com  A → hostA            control: join, admin, status, control channel
                     *.jailscale.example.com  A → hostA, hostB     relays: visitors
              relay1.jailscale.example.com    A → hostA            the relay name nodes connect to
              relay2.jailscale.example.com    A → hostB
     _acme-challenge.jailscale.example.com    NS → jailscale.example.com.   unchanged; issuance is the primary's

  hostA: control C1 (primary: writes)          + relay R1
  hostB: control C2 (standby: reads, signs)    + relay R2
         C1 ⇄ C2   hub-to-hub channel: event log tail, certificate push, revocations, mutual probes
         R1, R2 → C1 and C2  both: a signing request goes to whichever answers
  node:  control channel to the apex (C1); Hello returns the relay and control lists;
         the node connects to every relay and keeps its leases
```

The apex stays the control plane on purpose. Every existing node has `--hub jailscale.example.com`,
every join link is under it, and the alternative -- `hub.` for control and the apex for relays --
would put every control connection through a relay first for nothing. Paths cannot split traffic:
a relay never reads HTTP, only the SNI, so hostnames are the only fork. `relay`, `relay1`.. need
adding to the reserved labels in `Links.RESERVED`, which has `hub`, `hubs`, `ns1`, `ns2` but not these.

## Where each secret is

| Item | Primary | Standby | Relay | Node |
|---|---|---|---|---|
| `hub.key` (Noise static nodes pin) | yes | copy | own key instead | pins control's; learns relays' from the list |
| Wildcard private key | yes | copy | **no** | no (opaque key, as today) |
| Wildcard chain, public | yes | yes | yes | yes |
| `state.*` | writes | follows | no | -- |
| Lease signing key | yes | verify only | verify only | holds its leases |

Key copies are therefore bounded by the number of control hosts, two, and do not grow with relays.
The argument is the one behind keeping the release key in KMS rather than federating it: a relay that
is compromised can ask for signatures for as long as it is compromised, through a channel the
control plane logs per relay, rate-limits, and can cut. A relay holding a key copy could impersonate
every name silently until the certificate is rotated.

## Leases

A `LinkOpened` from the primary carries a lease: `{name, mkey, expires}` signed with the control
plane's key. The node stores it with the link and presents it to each relay when it reopens the
link there. The relay verifies the signature with the control public key and routes. A lease is
what lets a relay serve with the control plane down and a fresh relay serve with nothing synced.

Lifetime is set by how long an operator is allowed to take before promoting the standby: on the
order of 7 days, renewed daily by the node while the primary answers. Reassignment and revocation
are pushed to relays over the hub-to-hub channel while the primary is up; while it is not, expiry is
the bound, and §11.4's notice on reconnect still tells the node afterwards.

## The signing path

Today: node sends `SignRequest` on stream 0 of the connection that owns the stream; the hub checks
content, stream, name, transcript, count and rate (§9.2) and signs. Of those six, only two are known
to the relay alone: that the stream is open, and which SNI and ClientHello it delivered on it. Name
ownership is control-plane knowledge, and the transcript recomputation needs only the ClientHello.

Split: the relay attaches its ClientHello (both, around a HelloRetryRequest), the SNI and the node's
mkey, and forwards the request to a control host over the hub-to-hub channel. The control host
checks the lease or the store for ownership, recomputes the hash from the relay's ClientHello, signs,
logs `relay, name, mkey`. It trusts the relay to say which ClientHello it delivered, which is the
one thing only the party that saw the visitor can say; that trust is what makes a compromised relay
an oracle for its own lifetime and no longer.

Cost: one relay-to-control round trip per fresh handshake, in addition to the node-to-hub round trip
that exists now. Resumed sessions need no signature and are untouched. On a two-host layout the
relay's local control host answers, so the added trip is on loopback except when that host's control
process is the one that is down.

**The relay's own TLS.** A relay terminates TLS itself in exactly two places, and needs no key for
either. Nodes open TLS to `relayN.<hub>` before Noise IK; the relay terminates that the way a node
terminates a visitor -- an `SSLContext` over an opaque key, `SignRequest` to a control host -- since
the wildcard already covers `relayN`. Node connections are rare next to visitor handshakes, so the
round trip is not a cost worth avoiding. The "not open" page for a claimed name with no node takes
the same path, or the relay hands that stream to a control host as if it were a node. `TlsEndpoint`
and `RemoteSigning` move from the node module to `proto` for this; that is the concrete cost.

## What survives what

| Failure | Keeps working | Stops | Operator |
|---|---|---|---|
| Process restart on either host | as today | seconds | nothing |
| hostB lost | everything; visitors fall over to hostA | nothing | replace, start with `--peer`, it syncs |
| hostA (primary) lost | streams in flight; new visitors to existing names (C2 signs); nodes reconnecting to relays on their leases | joins, `open`, admin, lease renewal, certificate renewal | promote C2, move the apex A record |
| Both lost | nothing | everything | restore the state directory from backup |

The property this is for: losing the primary stops nothing on the visitor side, because relays are
connected to both control hosts and signing moves without a DNS change. What stops is what can wait
for a person: opening new names and administering. Certificate renewal has the slack §7.2 gives it,
a third of the lifetime.

A further step, not in the first version: two A records on the apex too, with the standby accepting
control connections and forwarding writes to the primary. That makes the node side fail over without
DNS as well, at the price of a moment during promotion where both hosts may write.

**A node that is not on every relay.** A visitor reaching relay B for a name whose node is connected
only to relay A gets the "not open" page after the 3-second hold. Until every node runs a build that
connects to every relay, the wildcard A record for a new relay must not be added, and the admin page
should list the nodes that are not on all relays so the operator can see when it may be. The
alternative is the relay forwarding the stream to the relay that has the node, which is DERP's mesh
and is not in this design; the control plane knows which relays each node is on, so it could be
added behind the same lease.

**Relay loss is the weak side, and it is DNS.** With two A records a browser moves to the next
address within a few hundred milliseconds when the dead host answers RST, and only after a full TCP
connect timeout per new connection when it is black-holed. A health-checked DNS product fixes that
and costs a provider token, which the project has declined to need. The alternative that keeps the
principle is the hub becoming authoritative for the whole subdomain -- the `_acme-challenge`
responder already exists -- with each host answering short-TTL A records for itself and its live
peer and dropping a dead one; resolvers skip a dead NS on their own. That needs the responder
brought up to public-authoritative quality and adds NS and glue records for two-host operators only.
Deferred.

## Wire changes

All additive, following the `host` and `visitors` precedent so the live hub and its nodes need not
move together:

- `Hello` from the hub gains optional `relays` (name, address, Noise public key) and `controls`.
  A node that does not know the fields behaves as today against a hub that is also a relay.
- `LinkOpened` gains an optional `lease`.
- A hub-to-hub channel, Noise IK between control hosts and from relays to control hosts, carrying
  the event-log tail, `CertUpdate`, revocations, forwarded `SignRequest`/`SignResponse`, and
  status probes.

## Uptime as a number

A hub cannot measure the time it was not running, so two figures with different names, never
combined into one:

- **Process uptime**, for a single host. A timestamp rewritten to one small file every minute; on
  start, the gap between the last stamp and now counts as down. Not the event log: 1,440 events a
  day would ride the fsync path and trip the snapshot cadence. It counts a hub whose 443 is
  firewalled as up, and says so.
- **Observed from the peer**, once there is a hub-to-hub channel. Each control host probes the
  other's `/v1/status` and each relay's, and keeps the result. This is reachability, and it is
  what a status page means by the word.

Shown on `/` and `/v1/status` over 24 hours, 7 days and 30 days, public for the reason §6.3 makes
the status endpoint public. Anyone scraping `/metrics` already computes availability from `up`;
this is for the operator with no scraper.

## Order

1. **Built.** Hub-to-hub channel and the standby: log tail, certificate and key push, a promote
   command, and the availability figures. Host loss goes from rebuild-from-backup to a DNS change.
   The channel is authenticated by the hub key itself -- the standby's Noise static is the copy of
   `hub.key` the operator made -- and rides 443 under the hub's own name. "Mutual probes" became
   the channel's own up and down intervals, which cost nothing and measure the same thing.
2. Leases and the relay list: `LinkOpened.lease`, `Hello.relays`, `Hello.controls`. Nodes store
   leases and connect to every relay.
3. The relay role: SNI router and signing forwarder separable from the store, `TlsEndpoint` and
   `RemoteSigning` shared through `proto`, relay names reserved, wildcard A records on both hosts.
4. Optional: authoritative DNS for the subdomain, for relay failover without a provider token.

## What this does not fix

A name has one node behind it. When that node's host is down the name is down whatever the hub
count is, so redundancy at the hub pays only where the hub is the less available of the two. README's
Limits and §13 should say so when this lands.
