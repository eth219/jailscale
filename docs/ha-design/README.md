# Redundancy: what was built, what it cost, and what a third hub would have needed

**None of this is in the code any more.** The two-hub design described here was built, shipped in
five stages, and removed in the maintenance cut of 2026-09-22 ([#274]): the hub-to-hub channel, the
standby, promotion, the availability figures, the standby serving visitors over relay connections
with per-name DNS, and promotion without a person using the nodes as witnesses. One hub is the
design now, and [ARCHITECTURE.md §13](../ARCHITECTURE.md) says what that gives up.

This file is kept as the record: the questions redundancy asks here, and the answers this project
reached, so that whoever brings it back does not start from nothing. The part that was never built —
a **third host in a store-less relay role** — was decided against on 2026-09-18 ([#72], closed with
#255) and is below as well.

The two constraints in the next section held through all of it, and hold for anything that comes
after.

## Two constraints that still hold

They were settled while the two-host work shipped and they apply to anything in this area.

**No load balancer in front.** It would take the DNS problem away for one cloud's price and one
cloud's API, and the project's answer to that class of dependency is to not have it.

**Running two hubs must feel like running one, plus a file and a line.** The operator copies
`hub.key` and adds `--peer`; anything more a change asks of them is a regression against §1's setup
list.

## What a third host would need

A relay role that holds nothing durable: it accepts on 443 for the wildcard, reads the SNI, verifies
that the node may serve that name, opens a stream on that node and copies bytes. It holds the public
chain, the control plane's public key and a Noise static key of its own — no secret whose loss
matters beyond its own identity, and nothing to synchronise before it can serve.

Three things stand between that and the code as it is.

**A signed lease.** `LinkOpened` would carry `{name, mkey, expires}` signed with the control plane's
key. The node stores it with the link and presents it to each relay; the relay verifies it against
the control public key and routes. The lease is what lets a relay serve while the control plane is
down, and a fresh relay serve with nothing synced. Lifetime is set by how long an operator may take
to promote a standby — on the order of 7 days, renewed daily while the primary answers. Revocation
is pushed over the hub-to-hub channel while the primary is up; while it is not, expiry is the bound,
and §11.4's notice on reconnect still tells the node afterwards.

**A split signing path.** Of the six things the hub checks before signing a handshake (§9.2), only
two are known to a relay: that the stream is open, and which SNI and ClientHello it delivered on it.
So the relay would attach its ClientHello, the SNI and the node's mkey and forward the request to a
control host, which checks the lease for ownership, recomputes the hash and signs. It trusts the
relay to say which ClientHello it delivered — the one thing only the party that saw the visitor can
say — and that trust is what bounds a compromised relay to being an oracle for its own lifetime.
The cost is one relay-to-control round trip per fresh handshake, on loopback in a two-host layout.

**A module move.** A relay terminates TLS in two places and needs no key for either, taking the same
`SignRequest` path a node does. `TlsEndpoint` and `RemoteSigning` would move from the `node` module
into `proto` for that. It is the one concrete code cost that can be named in advance.

## Why two hosts is where it stops

The standby holds the store, so it can serve *and* be promoted; that is what makes two hosts worth
the complexity a third would not add proportionally. §15 records what two does not buy: streams in
flight on a host that dies are cut with its sockets, raw TCP and UDP ports live on the primary
alone, and a promotion with no node attached to the standby waited for a person.

Active-active is a separate and larger thing — it needs inter-hub forwarding, since the hub a
visitor lands on and the hub a node is attached to could differ — and merging writes made on the
losing side of a partition is not supported at all (§1.3, §15): a merge needs a lineage the two
stores do not share, so the loser's writes are discarded and named.

## What none of it fixes

A name has one node behind it. When that node's host is down the name is down whatever the hub count
is, so redundancy at the hub pays only where the hub is the less available of the two. The availability figure said so
where the availability figure is defined, precisely so that the number is not read as a statement
about someone's link.

[#72]: https://github.com/eth219/jailscale/issues/72
