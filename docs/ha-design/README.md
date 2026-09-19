# Hub redundancy: control plane, relays, and an uptime figure

A design, all of which is built for two hosts ([ARCHITECTURE.md §13.1 to §13.5](../ARCHITECTURE.md)):
the hub-to-hub channel, the standby, promotion, the availability figures, the hubs answering their
own DNS, the standby serving visitors through relay connections with per-name DNS, and promotion
without a person with the nodes as witnesses. What is not built is the signed lease and the
relay-only role, which only a third, stateless relay would need. The steps landed in the order
1, 4, 2+3, 5.
It records the shape a two-host hub takes and why, cut so that each step leaves the single-host hub
untouched. Before step 1, §13's answer to losing the host was "copy the state directory and change
DNS"; the standby is that sentence done by the hub itself, and after step 4 the DNS change is the
hub's as well.

Two constraints were settled after step 1 shipped and hold for everything below. **No load balancer
in front**: it would take the DNS problem away for one cloud's price and one cloud's API, and the
project's answer to that class of dependency is to not have it. **Running two hubs must feel like
running one plus a file and a line**: the operator copies `hub.key` and adds `--peer`; anything more
that a step asks of them is a regression against §1's setup list.

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
ports and domains, issues invites, bans, and issues and renews the wildcard through
its own `_acme-challenge` responder. Signs handshakes. Signs *leases* (below). Serves the hub's own
name: control channel, `/join`, `/v1/status`. There is one **primary** control host that
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
  at the parent (Cloudflare), for a two-host operator -- four records, and the hub answers the rest:
                       jailscale.example.com  NS → ns1.jailscale.example.com.
                       jailscale.example.com  NS → ns2.jailscale.example.com.
                   ns1.jailscale.example.com  A  → hostA   (glue)
                   ns2.jailscale.example.com  A  → hostB   (glue)
  answered by the hubs themselves (step 4):
                       jailscale.example.com  A → the hosts serving right now   control channel, join, admin, status
                     *.jailscale.example.com  A → the hosts serving right now, or per name the relays that node is on
              relay1.jailscale.example.com    A → hostA            the relay name nodes connect to
              relay2.jailscale.example.com    A → hostB
       _acme-challenge.jailscale.example.com  TXT                  as today

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
| hostA (primary) lost | streams in flight; new visitors to existing names (C2 signs); nodes reconnecting to relays on their leases | joins, `open`, admin, lease renewal, certificate renewal | `jailhub promote` on C2, nothing else (step 4); nothing at all once step 5 is in |
| Both lost | nothing | everything | restore the state directory from backup |

The property this is for: losing the primary stops nothing on the visitor side, because relays are
connected to both control hosts and signing moves without a DNS change. What stops is what can wait
for a person: opening new names and administering. Certificate renewal has the slack §7.2 gives it,
a third of the lifetime.

A further step, not in the first version: two A records on the apex too, with the standby accepting
control connections and forwarding writes to the primary. That makes the node side fail over without
DNS as well, at the price of a moment during promotion where both hosts may write.

**A node that is not on every relay** is answered by DNS rather than by forwarding: once the hub
answers per name (step 4, below), `myapp.<hub>` resolves only to the relays that node is on, so a
visitor never reaches a relay that cannot serve the name. No mesh forwarding, and no rule about when
a second relay may be added to a wildcard record, because there is no wildcard record.

## Step 4: the hubs answer their own DNS

Relay loss was the weak side, and it was DNS: with two A records at the parent, a browser moves to
the next address within a few hundred milliseconds when the dead host answers RST, and only after a
full TCP connect timeout per new connection when it is black-holed. A health-checked DNS product
fixes that for a provider token, which the project has declined to need. What keeps the principle is
the hub becoming authoritative for the whole subdomain: the `_acme-challenge` responder already is
one, for one name. Decided as follows.

**Delegation.** The operator delegates the whole subdomain at the parent: two `NS` records naming
`ns1.<hub>` and `ns2.<hub>`, and a glue `A` for each. The apex `A`, the wildcard `A` and the
`_acme-challenge` `NS` go away, because everything under the cut is the hubs' to answer. A single-host
operator keeps today's three records; the hub always answers the whole zone, so which cut to make at
the parent is the operator's choice and needs no flag. Ports do not change: 53 is already open on
every hub host.

**What is answered.** `SOA` and `NS` for the zone with an hour's TTL; `_acme-challenge` `TXT` as
today; `relayN` `A` as each host's fixed address; and, with a 30-second TTL, the apex and every
name under it as **the set of hosts serving right now** -- the primary alone before step 3, both
relays after it -- and, after step 3, each open name as **the relays its node is connected to**,
falling back to the serving set for a claimed name with no node so the "not open" page is reached.
Everything else is NXDOMAIN or NODATA as the zone's contents dictate. That is the part the
responder does not do today and has to: correct negative answers, case-insensitive matching, EDNS,
TCP (it has it), `ANY` refused, recursion refused, answers kept small so the server is no use as an
amplifier. DNSSEC is not needed; the CA does not require it.

**Liveness.** A host is in the serving set while its hub-to-hub channel to this host is up, and this
host is in its own set while it is serving. Nothing else is probed: the channel is the signal, and
its up and down intervals are already what the availability figure (§13.2) records. A dead host is
dropped by its peer within the channel's idle timeout, and resolvers skip the dead `NS` on their own.
In a partition where both hosts live and only the link between them is down, each answers with
itself alone, so a resolver reaches a working host whichever `NS` it asked. **No consensus is
involved in the DNS layer and no split-brain is possible in it.** Which host writes is a separate
question, answered by promotion.

**Knowing one's own address, without asking the operator.** A `--advertise` flag would be a new
line in every hub's unit, which is exactly the regression the second constraint above forbids. The
address is already written down by the operator, in the glue: the hub asks a public resolver for
`ns1` and `ns2`, publishes a random `TXT` the way the dns-01 self-check does, and asks each glue
address on port 53 directly for it; the one that answers with the hub's own token is the hub. A
peer's address is the remote address of the hub-to-hub channel. `--advertise` exists only as an
override for hosts whose public address is not the one any resolver can see.

**What this changes in the order.** Step 4 depends on nothing in steps 2 and 3, and it moves the
whole visitor-side failover onto `jailhub promote`: when the primary dies, the standby stops
advertising it, and the moment it is promoted it advertises itself, so visitors arrive within the
TTL with nothing touched at the parent. That is the gain a load balancer would have bought, without
one. So step 4 comes next.

## Step 5: promotion without a person, with the nodes as witnesses

Two hosts cannot elect: a majority of two is two. Raft buys nothing below three, and the usual third
party -- a witness host, or a cloud object with conditional writes as a lease -- is a cost or a
dependency the design does not want. jailscale has a third party of its own: after step 2 every node
is connected to both hubs. The nodes are the witnesses.

**The rule.** A standby that has lost its channel to the primary asks every approved node it holds
for proof that the primary is reachable. If any node returns a valid proof within the window, this
is a partition: no promotion. If none does, the primary is dead or isolated from everyone, which
for serving purposes is the same thing: the standby promotes itself. The primary runs the mirror
rule: a primary that has lost its standby and every node steps down. Each promotion increments an
**epoch**, carried in the hub-to-hub hello; a former primary that reconnects and sees a higher epoch
becomes the standby without being told, so both units can carry `--peer` naming the other and be
identical but for their addresses, and "restart the old primary with `--peer`" stops being a chore.

**Proof, not testimony.** A node's word is not asked for. The standby hands the node a nonce; the
node passes it up its own control connection; the primary answers with a MAC over the nonce, the
epoch and the time under a key derived from `hub.key`, which both hubs hold and no node does; the
node carries the bytes back. "I can see the primary" therefore cannot be forged, which leaves a
lying node exactly one lie -- "I cannot" -- and one honest node with a valid proof outvotes any
number of those. The vote is not a majority but an existence proof.

**What a hostile node can still do.** On a hub with open registration it can be every node, at an
hour when the honest ones are off, and force a promotion by silence. The result is two primaries
until the link heals, at which point the higher epoch wins and the writes made in between --
names claimed, nodes joined, small in number by construction -- are merged with the later epoch
winning. Visitors notice nothing throughout; the attacker gains the ability to make that merge
happen, which a rate limit of one automatic promotion per interval and a loud line on the page and
in the log make worthless. Witnesses are approved nodes only, one vote per user however many
machines, and on a hub with `registration open` automatic promotion is off by default and the
operator turns it on knowing what it means. What a node can do outside this vote is what §11.1
already bounds: signatures for its own names over its own streams, and nothing else.

**What this is and is not.** A lease with fencing and an epoch, not a replicated log with consensus.
The writes it protects are rare and small, and the worst outcome is a merge, not corruption. That
is the trade the size of the state allows, and why step 4 lands first with `promote` still manual.

## Wire changes

All additive, following the `host` and `visitors` precedent so the live hub and its nodes need not
move together:

- `Hello` from the hub gains optional `relays` (name, address, Noise public key) and `controls`.
  A node that does not know the fields behaves as today against a hub that is also a relay.
- `LinkOpened` gains an optional `lease`.
- A hub-to-hub channel, Noise IK between control hosts and from relays to control hosts, carrying
  the event-log tail, `CertUpdate`, revocations, forwarded `SignRequest`/`SignResponse`, and
  status probes. Built in step 1 for the first three; the hello gains the sender's role and epoch
  in step 5.
- Step 5 adds a liveness proof on the node's control connection: a nonce from a hub, answered by
  the other hub with a MAC the node cannot make.

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
2. **Built for two hosts, without the lease.** `HelloResponse.relays` and `RelaysChanged` name the
   serving hosts; nodes open a relay connection to each and reopen their links there. Ownership
   on the second host comes from the replicated store, not from a signed lease: both hosts are
   control hosts and hold the store, so a lease would sign what the standby already knows. The
   lease, and its own signing key, are what a third, stateless relay would need, and wait for one.
3. **Built for two hosts.** The standby serves: it relays and signs with the key it holds, answers
   `LinkOpen` as a reopen and everything else as `primary-only`, and DNS answers each name with
   the hosts its node is on (`PeerNodes`). Not built: a relay-only role without the store,
   `TlsEndpoint`/`RemoteSigning` shared through `proto`, `relayN` names (nodes are told addresses
   instead). Raw TCP and UDP ports stay with the primary.
4. **Built.** The hubs answer their own DNS: whole-subdomain delegation, the serving set as the
   answer, liveness from the channel, the host's own address found from the glue, the challenge
   values replicated. Makes `jailhub promote` the whole of a failover. Per-name answers wait for
   step 3, which is when there is more than one host to name.
5. **Built.** Promotion without a person: nodes as witnesses with an unforgeable proof, epochs in a
   `role` file, units that may name each other, off by default on hubs with open registration.

## What this does not fix

A name has one node behind it. When that node's host is down the name is down whatever the hub
count is, so redundancy at the hub pays only where the hub is the less available of the two. README's
Limits says so, and [ARCHITECTURE.md §13.2](../ARCHITECTURE.md) says it where the availability
figure is defined, so that the number is not read as a statement about someone's link.
