# What a stalled reader costs the receiver, and what that measurement got wrong

Per-stream flow control bounds one stream and says nothing about their sum. `MuxStream.WINDOW` plus
a frame is 272 KiB, the hub admits `SniRouter.MAX_PER_NAME` = 1,024 visitors per name with no global
cap, and the product is 272 MB against a 96 MB heap ceiling. `SaturationMeasure.java` is the
measurement that found that, on the JVM, before anything was run on the native binaries.

It found the right place and predicted the wrong thing about it. Both halves are worth keeping: the
file is the cheapest way to look at this axis, and the gap between what it predicted and what the
native binaries actually did is the reason [ARCHITECTURE.md §5.3](../ARCHITECTURE.md)'s receive
budget is argued the way it is.

## The tool

Two `MuxSession`s over a loopback socket pair. The receiver accepts streams and never reads them —
a stalled local app, or a visitor who asks for a download and stops reading it. The sender writes
until its credits run out and blocks there, so the bytes come to rest in the receiver's inbound
queues, and `usedHeap()` after a forced GC says what that costs.

```sh
./mvnw -q -pl crypto,proto -am test-compile -DskipTests
m=~/.m2/repository/org
CP=proto/target/classes:crypto/target/classes:$(ls $m/junit/jupiter/junit-jupiter-api/*/junit-jupiter-api-*.jar | head -1):$(ls $m/apiguardian/apiguardian-api/*/apiguardian-api-*.jar | head -1)
javac -cp "$CP" -d out docs/mux-saturation/SaturationMeasure.java
java -Xmx64m -Dsaturation.n=32,64,128,256 -cp out:"$CP" io.jailscale.proto.mux.SaturationMeasure
```

`-Dsaturation.n=` is the stream counts to run, `-Dsaturation.budget=` the receiver's `FlowBudget` in
bytes (default unlimited, which is what reproduces the unbounded behaviour below).

## What it predicted

Unbounded, on a JVM, the cost is linear in stalled streams and there is no session-level limit:

| Streams | Accepted per stream | Heap per stream | Heap total |
|---|---|---|---|
| 32 | 256 KiB | 264 KiB | 8 MiB |
| 64 | 256 KiB | 264 KiB | 16 MiB |
| 128 | 256 KiB | 263 KiB | 32 MiB |
| 256 | 256 KiB | 268 KiB | 67 MiB |

Dividing that into the shipped ceilings gives about 245 stalled streams to fill the node's 64m and
about 370 to fill the hub's 96m. Run against a real ceiling, it does what the arithmetic says: at
`-Xmx64m`, 200 streams sit at 52 MiB and 240 die with an `OutOfMemoryError` on
`VirtualThread-unblocker` and `main` — the process, not the stream.

## What was true of the native binaries

**The place was right.** The sum of the per-stream windows was unbounded, an unauthenticated visitor
could grow it, and that is what `FlowBudget` now bounds.

**The mechanism was wrong.** What fills the queues is arrival rate, not stream count. 120 visitors
arriving in half a second fill the budget where 300 spread over 25 seconds do not, so the count this
file reports is not the number to design against.

**The threshold was wrong, and so was the failure.** On the shipped configuration nothing died at
300, 600 or 900 stalled visitors; the hub's peak flattens — 61, 78, 83 MB — rather than growing with
the count, and an ordinary visitor arriving among 900 stalled ones is still served, 16x slower. The
axis only reaches the hub's heap with `-XX:MaxHeapSize=768m` on the **node**: at the shipped 64m the
node's own per-visitor `TlsEndpoint` state saturates first and the hub never gets there. That is why
this read as harmless every time it was measured without it.

**And when it did fire, it was not a dead process.** The `OutOfMemoryError` landed on the thread
carrying a node's control connection, whose death runs `NodeGroup.detach`, so the whole node session
went with every link and visitor on it and the node reconnected a second later — an unauthenticated
outage of every name on that node. Which thread the error lands on is chance; a visitor thread would
have cost one visitor. It fired once in three identical attempts, in the one with the fastest ramp,
and ramp time tracked the peak inversely across all three: 144s/134.8 MB, 176s/121.4 MB,
218s/114.1 MB.

**One caution this file's own approach inherits.** Peak RSS on the hub varies by about 2x run to run
— the same 300 visitors gave 61.4 MB and 124.6 MB on the same binaries minutes apart, Serial GC not
returning the heap — which is why `FlowBudget`'s queue gauge, not RSS, is the number to trust on this
axis, and why any peak quoted from it needs its ramp time beside it.

## Why this is here and not under `src/test`

It asserts nothing. It prints a table, so there is no invariant it can fail to hold, and the
invariant it was reaching for belongs to `FlowBudgetTest` — `stalledStreamsStopAtTheBudget` and
`withoutABudgetTheSameLoadGrowsPastIt` assert it on every build rather than behind `@Tag("load")`.

And its three headline outputs — 264 KiB per stream, 245 streams at 64m, 370 at 96m — are wrong
predictions for the binaries that ship. A caveat comment depends on being read; a location does not.
This is the same place `docs/windows-virtual-thread-stall/` keeps its probes, outside the source root
where the build never compiles them and a superseded number cannot be mistaken for a current one.

## The question this tool could still answer

`FlowBudget` counts the payload bytes that enter a receive queue. Nothing verifies that its
accounting matches what the process actually retains: when it says 24 MB, whether the live set moved
by 24 MB or by 40. `measure.sh` reports RSS, which varies by 2x on this axis and includes everything
that is not heap; the unit tests check the counter against itself. `usedHeap()` here is the one
approach in the repository that could close that gap — run a bounded receiver at a known budget and
compare the retained heap against what the gauge claims.

Worth knowing before trying: the node's residency on this axis is mostly not receive queues at all.
A visitor sends one `GET` line, so the node's queues hold tens of bytes, and its 98 MB is
`TlsEndpoint`'s per-visitor `netInBuf`, `appInBuf` and `SSLEngine` ([§15](../ARCHITECTURE.md)). Any
sum that does not account for those will not balance.
