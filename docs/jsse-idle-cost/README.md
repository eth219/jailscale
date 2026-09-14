# What the node's idle memory is made of

[§12](../ARCHITECTURE.md) used to say that the node daemon alone was about 16.7 MB and reached about
24.3 MB the moment it connected, "so roughly 7.6 MB is JSSE initialisation for one TLS client", and
[§15](../ARCHITECTURE.md) and the README carried that as the reason idle memory is 25 MB against the
20 MB aimed at. It was one delta between two processes, attributed whole to JSSE. This file is why
all three now say something else.

`decompose.sh` beside this file holds one daemon in eight states and measures each three ways: RSS,
the pages the process has actually written, and the resident pages of the binary's own code. Three
runs, `darwin-arm64`, GraalVM CE 25.3.4.1, `-O2`, the release toolchain. The spread between runs is
0.1 MB, so the differences below are real at one decimal place.

| state | | RSS | written | code |
|---|---|---|---|---|
| `A` | fresh home, never joined — no `SSLContext` is ever built | 17.1 MB | 2,316 KB | 4,560 KB |
| `Bpin` | joined with `--ca-file`, hub down: context built, no handshake | 19.6 | 2,454 | 6,112 |
| `Bsys` | same with `caFile` removed: context built, default trust manager not yet demanded | 18.4 | 2,422 | 5,312 |
| `Dpin` | pinned *wrong* CA, hub up: handshake attempted and rejected | 22.5 | 3,148 | 7,712 |
| `Dsys` | `caFile` removed, hub up: rejected too, but the platform store is loaded to reject it | 23.7 | 3,388 | 7,760 |
| `C` | restarted daemon, connected | 22.8 | 2,961 | 8,096 |
| `E` | `C` with one link open | 23.1 | 3,132 | 8,144 |
| `J` | joined **and** opened within one daemon's life — what `measure.sh` samples | 25.0 | 3,862 | 8,272 |

## What it found

**The 7.6 MB is 8.0 MB here, and about a fifth of it is memory.** From `A` to `J` the process gains
8.0 MB of RSS, and of that **1.5 MB is written** — pages it owns and has dirtied. The binary's own
`__TEXT` accounts for **+3.7 MB resident with zero dirty pages**, and the binary's image-heap
mapping for a further **+2.0 MB resident, 288 KB of it dirty**. What the connect costs is mostly not
allocation. It is **code being executed for the first time**, page by page, out of a 26 MiB binary
the kernel can evict and re-read at will.

The one place where the regions add up exactly is within a single process, which is the only place
they can: held across the connect, one daemon's RSS goes from 20,080 KB to 23,536 KB, and
`vmmap` attributes the 3,456 KB to `__TEXT` +1,968 (dirty 0), the image-heap mapping +896 (dirty
144) and the Java heap +592, which is the whole of it and nothing else. Comparing two *different*
daemons region by region does not work — the shared-library mappings differ between processes by
more than the figure being measured — so the cross-state numbers above are only the three that are
about this binary: RSS, written, and the binary's own mappings.

The heap agrees. `-XX:+PrintGCSummary` on each state reports **zero collections** and the heap
growing from 0.50 MB of chunks to 1.00 MB across the whole sequence, against 0.78 MB of objects ever
allocated. §12 already says lowering the heap cap does not move idle RSS; the reason is that at idle
there is no heap to speak of.

**It is not all JSSE, and the shape of it says which part is.**

| | RSS | written | code |
|---|---|---|---|
| `A → Bpin` stand JSSE up, no bytes moved | +2.6 MB | +139 KB | +1,552 KB |
| `Bpin → C` handshake, Noise, mux, registration | +3.2 | +507 | +1,984 |
| `C → E` open one link | +0.2 | +171 | +48 |
| `E → J` having performed the join in this process | +2.0 | +731 | +128 |

Only the first row is JSSE alone, and it is 2.6 MB of RSS for 139 KB of written memory: standing up
a TLS client is almost entirely first-touch of code. The second row is the TLS handshake *and* the
Noise handshake, the multiplexer, the HTTP upgrade, the JSON and the registration, and nothing here
separates them. So JSSE's share of the 8.0 MB is somewhere between 2.6 MB and 5.8 MB, and the
7.6 MB §15 used to publish is the high end of that range plus two things that are not TLS at all.

**The join is 2.0 MB of the published figure, and a node only pays it once.** `E` and `J` differ by
nothing except which process did the join — `/v1/key`, the join request, the first certificate.
`measure.sh` samples idle in the daemon that just performed it, so 25.0 MB describes a node's first
minutes. The same node restarted idles at **23.1 MB**. This is the one line in the table that is
purely an artefact of how the budget is measured.

**The platform root store costs 2.5 MB, and the gate has never measured it.** `measure.sh` always
joins with `--ca-file`, so every published figure describes a node with a pinned CA and a
two-certificate trust manager. A node joined to a hub with an ordinary web-PKI certificate — which
is every real deployment, including `jailscale.sinabro.io` — passes `caFile: null`, and JSSE builds
its default trust manager over the platform store instead. `(Dsys − Bsys) − (Dpin − Bpin)` isolates
it: both sides attempt a handshake, both are rejected by PKIX, and what is left between them is
**+2.5 MB of RSS, 272 KB of it written**. It cannot be measured with a successful handshake here,
because nothing local has a publicly trusted certificate, but a failing path build loads the anchors
before it rejects the chain, which is all this needs.

It nearly cancels against the join, which is why neither correction showed up as a surprise in the
budget: a restarted node against a public-CA hub should settle around **25.6 MB** against the 25.0
published — by addition, since the whole of it cannot be measured in one process here. Two
corrections in opposite directions is a poor reason to leave either one unwritten, and only one of
the two configurations is gated.

## What this says about replacing JSSE

The question this was run for was whether writing our own TLS would move the figure, and the
measurement changes what the answer rests on.

- The lever is **pages of code touched**, not bytes allocated. A hand-written TLS 1.3 really would
  touch fewer of them, and this is the only mechanism by which it could help.
- But those pages are clean, file-backed and evictable, which is the cheapest memory in the process.
  The memory the node actually owns after standing JSSE up is **139 KB**, and after the entire
  connect, link and join, 1.5 MB. There is no version of this rewrite that recovers a megabyte of
  dirty memory, because there is not a megabyte of dirty memory to recover.
- It is also consistent with what [§14](../ARCHITECTURE.md) measured from the other side:
  profile-guided builds carry idle RSS down about a fifth, which is the same mechanism — the same
  code, laid out so that less of it has to be resident — bought without writing a line of TLS.
  (Against the 25.0-line builds it was measured on; smaller against what ships. §14 also has the
  reasons releases do not use it.)

The cheap levers this leaves, in order: measure the shipped trust configuration rather than the
pinned one; decide whether a node that pins its hub's Noise key ([§5.2](../ARCHITECTURE.md)) needs
the whole platform store behind its transport as well; and, if the number still matters after that,
spend the effort on code layout rather than on a TLS stack.

## What this does not cover

`darwin-arm64` only, because the split rests on `vmmap`. Linux reports the same two quantities as
`Rss` and `RssAnon` in `smaps_rollup`, and the README already prints the anonymous share beside RSS
— 2 MB against 34.4, which is the same story this file tells in more detail.

It also measures one TLS client and no visitors. Everything about what a *visitor* costs is
[§15](../ARCHITECTURE.md)'s 99 KB figure and a different measurement.
