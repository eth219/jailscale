# What the node's idle memory is made of

[§12](../ARCHITECTURE.md) used to say that the node daemon alone was about 16.7 MB and reached about
24.3 MB the moment it connected, "so roughly 7.6 MB is JSSE initialisation for one TLS client", and
[§15](../ARCHITECTURE.md) and the README carried that as the reason idle memory is 25 MB against the
20 MB aimed at. It was one delta between two processes, attributed whole to JSSE. This file is why
all three now say something else.

`decompose.sh` beside this file holds one daemon in five states and measures each three ways: RSS,
the pages the process has actually written, and the resident pages of the binary's own code — four
on Linux, which can also report the anonymous resident share §14 publishes beside RSS. Three
runs, `darwin-arm64`, GraalVM CE 25.3.4.1, `-O2`, the release toolchain. The spread between runs is
0.1 MB, so the differences below are real at one decimal place. The same five states on
`linux-arm64` are further down, and they say the same thing.

| state | | RSS | written | code |
|---|---|---|---|---|
| `A` | fresh home, never joined — no `SSLContext` is ever built | 17.1 MB | 2,316 KB | 4,560 KB |
| `Bpin` | joined with `--ca-file`, hub down: context built, no handshake | 19.6 | 2,454 | 6,112 |
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

**The gate measures a trust configuration nobody ships, and it is worth about half a megabyte.**
`measure.sh` always joins with `--ca-file`, so every published figure describes a node with a pinned
CA and a two-certificate trust manager. A node joined to a hub with an ordinary web-PKI certificate
— every real deployment, including `jailscale.sinabro.io` — leaves `caFile` null and JSSE builds its
default trust manager over the store `native-image` baked into the binary.

`truststore.sh` beside this file measures that by building a second image whose embedded store also
trusts the test certificate, so a loopback hub validates through the same path a public CA would.
Within that one binary, five runs each, handshakes that succeed:

| trust configuration | RSS | written |
|---|---|---|
| `tlsInsecure`, `TrustAll`, no PKIX at all | 21.95 MB | 2,887 KB |
| `--ca-file`, two anchors — what the gate uses | 22.47 | 2,942 |
| `caFile` null, the image's own 112 anchors — what ships | 23.01 | 2,929 |

**+0.55 MB for the shipped configuration, and no measurable written memory at all.** (A second
build against a 119-anchor store, sampled with a link open, read +0.81 MB; the honest range is half
a megabyte to eight tenths.) Dropping certificate validation on the control channel altogether would
buy **1.06 MB**, which is the ceiling on anything that can be done here.

**Two cheaper-looking methods answered this wrongly first, and both were believed.** They are
written up in `truststore.sh` because the shapes recur:

- *A failing handshake.* Point a `caFile`-null node at the test hub; PKIX loads the anchors in order
  to reject the chain, so the difference against a pinned-CA node that also fails should be the
  store. It reads **+2.5 MB** — because failing a path build is not the shipped path. It builds and
  abandons candidate paths and runs code a successful validation never does.
- *A run-time store.* The binary does honour `-Djavax.net.ssl.trustStore`, so a full-size store can
  be handed to the shipped binary and the handshake succeeds. It reads **+5.7 MB, 4.9 MB of it
  written** — wrong in the other direction, because it parses a PKCS12 file into the heap where the
  shipped node has its anchors in the image heap already, mapped from the binary and mostly clean.

The first of those was in this file, and in §15 and the README, before the second build existed.

Against the join, which is 2.0 MB the other way, a restarted node on a public-CA hub settles around
**23.7 MB** against the 25.0 published — below it, not above.

## The same five states on `linux-arm64`

`decompose.sh` takes a sampler per kernel: `vmmap` on darwin, `/proc/PID/smaps_rollup` and
`/proc/PID/smaps` on Linux. `written` is `Private_Dirty` there and `code` is the summed `Rss` of the
binary's own executable mappings, which is the nearest thing each kernel has to the other's question;
the script's header says exactly what each column is on each side. Three runs, `linux-arm64`,
Ubuntu 24.04 (kernel 6.8, 4 KiB pages), GraalVM CE 25.3.4.1, binaries from `./native.sh`. RSS
repeats to 0.2 MB and `code` to the kilobyte; `written` is the loose one, moving about 100 KB
between whole runs, so read that column at the hundred and not at the ten.

| state | | RSS | written | code | anonymous |
|---|---|---|---|---|---|
| `A` | fresh home, never joined | 17.3 MB | 856 KB | 7,420 KB | 0.8 MB |
| `Bpin` | joined with `--ca-file`, hub down | 20.2 | 1,012 | 9,404 | 1.0 |
| `C` | restarted daemon, connected | 23.0 | 1,640 | 11,260 | 1.6 |
| `E` | `C` with one link open | 23.2 | 1,792 | 11,260 | 1.8 |
| `J` | joined **and** opened within one daemon's life | 24.0 | 2,333 | 11,260 | 2.3 |

| | RSS | written | code |
|---|---|---|---|
| `A → Bpin` stand JSSE up, no bytes moved | +2.9 MB | +156 KB | +1,984 KB |
| `Bpin → C` handshake, Noise, mux, registration | +2.8 | +628 | +1,856 |
| `C → E` open one link | +0.2 | +152 | +0 |
| `E → J` having performed the join in this process | +0.8 | +541 | +0 |
| **`A → J`** | **+6.7** | **+1,477** | **+3,840** |

**The conclusion carries, and `written` — the column it rests on — carries with it.** darwin's
`A → J` is +8.0 MB of RSS for +1,546 KB written and +3,712 KB of code; Linux's is +6.7 MB for
**+1,477 KB written and +3,840 KB of code**, and three separate runs of it gave 1,477, 1,500 and
1,581 KB. Two kernels, two architectures, two samplers that do not share a line of code, and the
memory the process owns after standing JSSE up, connecting, opening a link and joining lands within
5% of the same figure. There is no megabyte of dirty memory to recover on Linux either.

**The 9 MB was never a Linux figure.** §14 publishes 34.4 MB for the node against darwin's 25.0, and
that is `linux-amd64`, the one platform the gate runs on. `linux-arm64` — a shipped release target
too — idles at **24.0 MB**, which is *below* macOS, not 9 MB above it.

| | node idle RSS | anonymous | file-backed |
|---|---|---|---|
| `darwin-arm64` | 25.0 MB | — | — |
| `linux-arm64` | 24.0 | 2.3 MB | 21.7 MB |
| `linux-amd64` ([§14](../ARCHITECTURE.md)) | 34.4 | 2.1 | 32.3 |

**The two Linux targets own the same memory to within 0.2 MB.** Every one of the 10.4 MB between
them is file-backed — 32.3 MB against 21.7 — clean pages the kernel can drop and re-read, which is
what §14 says the difference is made of and is now measured on both sides of it rather than argued
from one. §14 calls those pages the binary's, and that part is still an attribution: 32.3 MB is more
of them than the whole 26.4 MiB binary, and nothing here says which mappings they are. What it is
not is macOS counting differently from Linux, which is how that sentence reads — `linux-arm64` sits
with macOS and `linux-amd64` is the outlier.

Two smaller differences, neither of which moves anything:

- `code` stops growing at `C` on Linux — 11,260 KB at `C`, `E` and `J` alike — where on darwin it
  kept creeping, 8,096 to 8,144 to 8,272. The link and the join touch no new text pages there.
- The absolute `code` figures are higher on Linux (7,420 KB at `A` against darwin's 4,560) for a
  similar amount of growth, +3.8 MB against darwin's +3.6. The two absolutes are not the same
  measurement — Linux's column is the binary's executable mappings and darwin's is `__TEXT`, which
  carries rodata as well — so what carries across is the growth and not the 7,420 against 4,560.

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

What this leaves is thinner than it looked when the trust store was thought to be worth 2.5 MB. The
shipped configuration costs 0.55 MB more than the gate measures, and abandoning certificate
validation on a control channel that a pinned Noise key ([§5.2](../ARCHITECTURE.md)) already
authenticates would buy 1.06 MB — 4% of idle RSS, none of it written, against giving up a layer of
defence. If this number is ever worth moving, the lever is code layout.

## What this does not cover

`darwin-arm64` and `linux-arm64`. **`linux-amd64` is the one that is missing, and it is the one the
gate measures** — the 34.4 MB in §14 and the README is its figure, and nothing has taken it apart at
these five states. What the run above establishes is that its extra 10 MB is file-backed and not
memory the process owns; what it cannot establish is which mappings, because an arm64 machine is not
where that number comes from. #216 is that run.

Only `decompose.sh`'s five states have been run on Linux. The trust-store half of this file is
`truststore.sh`, which rests on `vmmap` and on a second image built beside the first, so the 0.55 MB
the shipped configuration costs and the 1.06 MB ceiling on dropping validation are `darwin-arm64`
figures and nothing has checked them anywhere else.

The two samplers are not the same measurement, only the same question: darwin has no column that
means what Linux's anonymous resident means, so the `anonymous` column exists on one side only, and
the cross-platform claims above are about `written`, `code` and RSS. Those three are comparable
between the platforms as differences between states and not as absolutes — `written` at `A` is
2,316 KB on darwin against 856 on Linux — which is why every cross-platform figure above is a
delta.

It also measures one TLS client and no visitors. Everything about what a *visitor* costs is
[§15](../ARCHITECTURE.md)'s 99 KB figure and a different measurement.
