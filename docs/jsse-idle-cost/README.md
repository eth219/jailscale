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
`linux-arm64` and on `linux-amd64` are further down, and all three say the same thing.

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
from one. §14 calls those pages the binary's, and on `linux-amd64` that is now sorted rather
than asserted — see "Which mappings, measured" below, which also says why more of them is not more
than the binary. On `linux-arm64` it is still an attribution: `breakdown` has not run there, and
that is #233. What it is
not is macOS counting differently from Linux, which is how that sentence reads — `linux-arm64` sits
with macOS and `linux-amd64` is the outlier.

Two smaller differences, neither of which moves anything:

- `code` stops growing at `C` on Linux — 11,260 KB at `C`, `E` and `J` alike — where on darwin it
  kept creeping, 8,096 to 8,144 to 8,272. The link and the join touch no new text pages there.
- The absolute `code` figures are higher on Linux (7,420 KB at `A` against darwin's 4,560) for a
  similar amount of growth, +3.8 MB against darwin's +3.6. The two absolutes are not the same
  measurement — Linux's column is the binary's executable mappings and darwin's is `__TEXT`, which
  carries rodata as well — so what carries across is the growth and not the 7,420 against 4,560.

## The same five states on `linux-amd64`, which is the platform the gate measures

The two runs above are arm64, and §14's node figure is not: 34.4 MB is `linux-amd64`, measured by
`measure.sh` on every push to `main`. No machine this is developed on can produce that platform, so
this run is a `workflow_dispatch` of `ci-full.yml` with `only: idle-split` — `ubuntu-24.04`,
GraalVM CE 25.3.4.1, `./mvnw -Pnative package`, the same toolchain and runner image the budget gate
itself uses. Three runs at the default settle. RSS repeated to 0.1 MB across all three and `code` to
the kilobyte. `written` is the mean of the three, and the arm64 section above measures that column's
own run-to-run movement at about 100 KB, which is the floor to read it against.

| state | | RSS | written | code | anonymous |
|---|---|---|---|---|---|
| `A` | fresh home, never joined | 29.9 MB | 713 KB | 10,388 KB | 0.7 MB |
| `Bpin` | joined with `--ca-file`, hub down | 32.3 | 923 | 11,988 | 0.9 |
| `C` | restarted daemon, connected | 34.3 | 1,499 | 13,268 | 1.5 |
| `E` | `C` with one link open | 34.5 | 1,685 | 13,268 | 1.6 |
| `J` | joined **and** opened within one daemon's life | 35.1 | 2,160 | 13,268 | 2.1 |

| | RSS | written | code |
|---|---|---|---|
| `A → Bpin` stand JSSE up, no bytes moved | +2.3 MB | +209 KB | +1,600 KB |
| `Bpin → C` handshake, Noise, mux, registration | +2.0 | +576 | +1,280 |
| `C → E` open one link | +0.2 | +187 | +0 |
| `E → J` having performed the join in this process | +0.7 | +475 | +0 |
| **`A → J`** | **+5.2** | **+1,447** | **+2,880** |

**`written` carries to the third platform, and it is the column everything above rests on.** `A → J`
owns 1,546 KB on `darwin-arm64`, 1,477 on `linux-arm64` and **1,447 on `linux-amd64`** — two
architectures, two kernels, two samplers that share no code, and a spread of 99 KB. That spread is
the size of the column's own noise and not smaller than it: the arm64 run's three passes gave 1,477,
1,500 and 1,581 KB. So this says the three platforms agree to within what one of them varies by, and
not that amd64 owns 30 KB less than arm64. The claim that standing JSSE up, connecting, opening a
link and joining costs about a megabyte and a half of memory the process owns is now measured on
every shipped native target but `windows-amd64`.

**The 10 MB is there before the daemon has done anything.** State `A` is a process that has never
built an `SSLContext`, never opened a socket to the hub and has no keys: 17.1 MB on `darwin-arm64`,
17.3 on `linux-arm64` and **29.9 on `linux-amd64`**. The whole of the gap §14 reports is already
present there. Everything after it is *cheaper* on amd64 than anywhere else — `A → J` is +5.2 MB
against arm64 Linux's +6.7 and darwin's +8.0 — so whatever the 10 MB is, it is not JSSE, not the
handshake, not the link and not the join. This is the question #216 asked, and it is answered in the
first row of the table.

**It is not the binary being bigger.** v0.1.10 ships `jailscale-linux-amd64` at 27.1 MiB against
`jailscale-linux-arm64` at 26.2 — 0.9 MiB apart, against 12.6 MB of RSS at `A`.

**Which mappings, measured.** `code` above is the binary's own executable mappings, and it is
10,388 KB at `A` against arm64's 7,420: **2.9 MB of the 12.6, and no more.** The rest of `A`'s
file-backed memory was named by nobody until `breakdown` sorted it (#227,
[run 35309183734](https://github.com/eth219/jailscale/actions/runs/35309183734), on ubuntu-24.04,
one run's last sample against the five-state table's mean of three):

| state `A`, `linux-amd64` | rss | of it anonymous | mapped |
|---|---|---|---|
| binary, executable | 10,388 KB | 0 | 14,036 KB |
| binary, not executable | 17,468 | 332 | 27,400 |
| other file-backed | 2,528 | 48 | 5,828 |
| no path | 356 | 348 | reserved, see below |
| **total** | **30,740** | **728** | |

`smaps_rollup` read 30,740 KB at the same moment. The script exits non-zero if those two disagree by
more than 64 KB, or if it meets a mapping header it cannot read, so a table that is missing a bucket
stops the run rather than being published.

**The 19.5 MB is the binary, and §14's sentence is right about it.** Of the 19,996 KB of file-backed
memory outside the executable mappings, **17,468 KB is the binary's non-executable mappings** — the
rodata and the image heap, which is what "text and rodata mapped in" meant and what nothing had
taken apart — and **2,528 KB is not the binary at all**. `libc.so.6` is 1,944 KB of that and the
rest of the loader's is 584. So of the state's 30.0 MB, 27.2 is the binary, 2.5 is the loader's and
0.3 has no path.

**The `anonymous` column is why the binary's share is 27.2 MB and not more.** A private file mapping
whose pages have been written stays resident under the file's path while being memory the process
owns, so a bucket by path alone counts the image heap's copy-on-write pages as binary. There are
332 KB of them inside the binary's mappings at `A`, and the column's total of 728 KB is the same
0.7 MB the five-state table reports as anonymous — two reads of `/proc` agreeing.

**And the binary is mapped more than once.** At `J` the two binary buckets hold 31,888 KB resident.
Take off the 492 KB of that which is anonymous — pages the image heap has written, which are no
longer the file — and **30.7 MiB of the file is resident out of a 27.3 MiB file**. A private mapping
cannot hold more of a file than the file has, so some of it is resident twice. The `mapped` column
is consistent with that rather than proof of it, since a file mapping may be longer than its file:
those buckets span 41,436 KB, 40.5 MiB of address space, which is room for the same bytes at two
addresses.

The `no path` bucket's span is reserved address space — tens of gigabytes of it, which the runtime
reserves and does not map — so that one cell is not a quantity of anything and the total omits it.

**And `J` lines up with the gate, which is the check that says this measured the right thing.** §14
publishes 34.4 MB for a node of exactly `J`'s shape and this reads **35.1**, which looks like 2% of
disagreement and is not. The `budget` job on `main` at the same commit
([35247984078](https://github.com/eth219/jailscale/actions/runs/35247984078)) reads **35.2 MB with
2.1 MB anonymous**, against `J`'s 35.1 with 2.1. The two harnesses are not the same sequence —
`measure.sh` settles for `IDLE=10` against this script's 8, and the daemon it samples has also
issued an invite, served a second node's join and answered a `netcheck` — and they land 0.1 MB
apart anyway.

What is 0.8 MB out of date is §14's **34.4**, which is v0.1.2's figure. The same run puts the
binary at 27.3 MiB against the table's 26.4, and since idle RSS here is mostly the binary mapped in,
a binary 0.9 MiB larger is the whole of it. The gate held on every release in between; the table
was not re-measured. #228 is that table.

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

**Which file-backed mappings the `linux-arm64` baseline is.** `breakdown` has run on
`linux-amd64` only, so the four buckets above are one architecture's. #233 is the arm64 run, and it
is the comparison that would say whether the 12.6 MB gap is more of the binary resident, the same
binary mapped differently, or something that is not the binary at all — the three the measurement
above cannot separate, for the reason its last paragraph gives. `windows-amd64` has no sampler here
at all and is the fourth target.

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
