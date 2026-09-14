# What one busy name does to the other names on the same node

A node serves at most `Visitors.MAX_IN_FLIGHT` visitors ([§9.3](../ARCHITECTURE.md)) and may serve up
to `Links.MAX_LINKS_PER_NODE` = 20 names. Nothing shares the bound between them: the hub admits first
come, first served, so a name that fills the node leaves the others refused. [§15](../ARCHITECTURE.md)
has recorded that as a limit since the bound existed, with no number beside it and no answer to the
question that decides whether it matters.

That question is not "is there starvation". A slot comes back the moment a visitor finishes, so it is
**entirely about how long the busy name's visitors hold theirs**, and the two answers are different
products. `StarvationMeasure.java` beside this file measures both.

## What it found

One node bounded at 20 visitors, two names on it — `hot` busy, `cold` quiet — and `cold` tried 40
times in each phase. Three runs:

| the busy name | the quiet name gets | latency |
|---|---|---|
| **holds its connections** (a download, a websocket, a stalled reader) | **0 of 40, three runs out of three** | — |
| **answers and releases** (ordinary request/response, ~1,500 requests in 5 s) | 34, 39, 35 of 40 | 4–27 ms |

**The long case is a complete blackout, not a delay.** Forty attempts over five seconds and not one
got through, every run. That is what the arithmetic says should happen — the holders never release,
so there is never a free slot — but it is worth having measured, because the other case turns out
not to look like it at all.

**The short case is degraded and usable.** 85% to 97% served at ordinary latency. The refusals are
real and not noise: the node genuinely is at its bound at that instant. A visitor that retries gets
in, which is what a browser does.

So a name's exposure is decided by its neighbour's *connection lifetime*, not by its neighbour's
request rate. A node publishing a busy API next to a quiet one is fine. A node publishing anything
that holds connections open — SSE, websockets, large downloads — takes every other name on that node
dark for as long as it is saturated.

## What it does not cover

The bound here is 20, on the JVM, with two names. The shipped bound is 450 with up to 20 names, on
the native binaries. Nothing about the admission rule changes with scale — it is the same first-come
check in `SniRouter` — but any *sizing* decision (how many slots a reservation would need to hold
back, and what that costs the busy name) needs measuring at the real bound, because the fraction
reserved is what matters and 2 of 20 is not 2 of 450.

It also measures the hub's admission only. What a visitor experiences on the far side of a refusal —
a closed connection, no page — is [§9.3](../ARCHITECTURE.md)'s, and unchanged by any of this.

## What it cost to find out, and one bug it found by accident

The measurement is about 250 lines and took three runs. It is here rather than in the test suite
because it asserts nothing: it is a question, and the answer above is the point. `docs/mux-saturation`
is the same shape and for the same reason.

While reading its output, the node's refusal line said **"at the visitor ceiling (64800)"** for a
node whose bound was 20. `Visitors` had two numbers in scope — a static holding the derived default
and the instance's own — and the log had picked up the static while the check used the instance. A
node running to any bound other than the derived one told its operator a number it was not using.
Nothing caught it because nothing reads the log. The static is gone now; there is one number in
scope and the mistake no longer compiles.

## Where this leaves the limit

The blackout is real, deterministic, and reached by ordinary product behaviour rather than by abuse.
The design space is in [§15](../ARCHITECTURE.md); the short version is that static partitioning is
wrong (it idles capacity in the common case, where one name is busy and the rest are not) and
eviction is wrong (the hub has no way to tell which live connection deserves to die, where
`FlowBudget` could point at a stream that had consumed nothing for two seconds). What is left is
holding back a few slots per name, whose cost is paid only while a node is saturated — which is
already a degraded state. Nothing here sizes that, and nothing has been built.
