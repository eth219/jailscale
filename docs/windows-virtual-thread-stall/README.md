# Windows cannot poll one socket for read and for write at the same time

`MuxSessionTest.largeTransferRespectsFlowControl` hit a 30 second timeout intermittently, on
Windows CI only, and so did `RawPortTest.tcpAndUdpThroughAssignedPorts` and other end-to-end tests.
A node on Windows lost a hub connection for up to 60 seconds now and then for the same reason.

The cause is a Windows defect the JDK has an open bug for, and the condition it needs is narrow
enough to design around. jailscale now does, and the stall is gone: measured below.

## What goes wrong

A virtual thread that blocks on a socket does not block in the OS. It registers the socket with a
poller and parks; the poller thread unparks it when the socket is ready. On Windows that poller is
`sun.nio.ch.WEPollPoller`, built on [wepoll](https://github.com/piscisaureus/wepoll), and **the JDK
runs two of them**: one epoll handle for read readiness, one for write readiness
(`sun.nio.ch.Poller.readPoller`/`writePoller`). Each park is an `EPOLL_CTL_ADD` with
`EPOLLONESHOT`, each wake-up an `EPOLL_CTL_DEL`.

wepoll implements those handles with `AFD_POLL` requests against the undocumented `\Device\Afd`
driver. When one socket has two of them outstanding — because one virtual thread is parked reading
it and another is parked writing it — AFD sometimes completes the wrong one: the read handle is
woken for a write event, and the write event is never reported to the handle that asked for it.
`WEPollPoller.poll` does not look at the event mask, so the wrong thread is unparked, retries, finds
nothing, and re-registers; the right thread is never unparked at all.

This is [JDK-8334574](https://bugs.openjdk.org/browse/JDK-8334574), "Socket operations never
complete when run on a virtual thread", open since June 2024 and still open. Upstream it is
[wepoll#35](https://github.com/piscisaureus/wepoll/issues/35), where the investigation ends at:

> If we never poll the same socket handle from 2 distinct epoll handles at the same time, the
> problem doesn't reproduce.

So the trigger is not "bidirectional traffic", which is what this page used to say. It is **one
socket parked for read and for write at the same time, by virtual threads**. Platform threads block
in the OS and enter no poller, so a socket with a platform thread on one side is never in two
handles at once.

## Measurements

`Probe.java` is the reproducer: about 220 lines, no dependencies, `java.base` only. Every variant
moves the same 800 KB per iteration over loopback with the same window updates, and changes only
which socket the updates travel over, or which single thread is a platform thread.

```sh
javac -d out Probe.java
java -cp out Probe <variant> <runs> <per-run timeout s> <total budget s>
```

GitHub Actions `windows-2025`, Liberica 25.0.4 and 26.0.2, 4 cores, 10 s per-run timeout, 480 s
budget:

| Variant | What it changes | JDK 25 | JDK 26 |
|---|---|---|---|
| `bidi` | nothing: one socket parked both ways | **48 of 137 (35%)** | **48 of 169 (28%)** |
| `preader` | a platform thread on the *other* socket | **48 of 126 (38%)** | |
| `uni` | no window updates, so no second direction | 0 of 5,000 | |
| `split` | updates over a second socket pair, everything still virtual | 0 of 5,000 | 0 of 5,000 |
| `pwriter` | the writer is a platform thread | 0 of 5,000 | 0 of 5,000 |
| `packs` | the update reader is a platform thread | 0 of 5,000 | |
| `platform` | every thread is a platform thread | 0 of 5,000 | |

`split` is the one that settles it: traffic in both directions, every thread virtual, nothing but
the socket the updates ride on is different, and it does not stall in 5,000 runs. `preader` settles
the other half: a platform thread that is not on the doubly-parked socket changes nothing. The fix
is not "fewer virtual threads", it is "never two pollers on one socket".

A stalled run dumps all three threads. They are parked in `sun.nio.ch.Poller.poll`, with credits to
spare and nothing in either receive buffer — the writer is waiting for a write-readiness event that
was delivered to the read handle instead:

```
  credits=245760
  reader-socket available=0 ack-socket available=0
  writer state=WAITING virtual
      at java.base/sun.nio.ch.Poller.poll(Poller.java:144)
      at java.base/sun.nio.ch.NioSocketImpl.park(NioSocketImpl.java:174)
```

The wake-up is lost, not delayed: raising the per-run limit from 10 s to 150 s leaves the rate
unchanged (previous runs: 42.7% of 281 against 40.0% of 20).

JDK 26 is not a way out. `WEPollPoller` there still keeps a separate handle per direction and still
adds and deletes per park (JDK-8374170 reworked the poller without touching this), and the numbers
above are the same.

## What jailscale does

`io.jailscale.proto.net.DuplexThread` starts the thread that will sit on one direction of a socket
another thread is using at the same time: a platform thread on Windows, a virtual one everywhere
else. Every such socket in jailscale now has exactly one side started that way, so no socket is ever
in two poll handles:

| Socket | The side that moved |
|---|---|
| The mux socket to the hub or the node | `mux-reader` (`MuxSession.start`, and `run` waits on one) |
| A visitor socket at the hub | `relay-in` (`Relay.pump`) |
| A local target socket at the node | `visitor-in`, `raw-in` (`Visitors`) |
| A local UDP target at the node | `raw-udp-back` (`Visitors`) |
| A raw UDP port at the hub | the `raw-udp-<port>` receive loop (`RawPorts`) |
| Two test harnesses that do the same thing | `RawPortTest`, `ProxyProtocolEndToEndTest` |

The cost is one platform thread per concurrently-used socket, on Windows only. Linux and macOS get
`Thread.ofVirtual()` exactly as before, and nothing about the protocol or the wire changes.

`MuxLoop.java` measures it through jailscale's own code rather than a socket reproducer: the body of
`MuxSessionTest.largeTransferRespectsFlowControl` in a loop, two `MuxSession`s over a loopback pair.

| `windows-2025`, 3,000 runs, 10 s timeout | Stalls | Wall clock |
|---|---|---|
| before | **19 (0.63%)** | 215 s |
| after | **0** | 30 s |

Nineteen stalls is a rate the fix would survive by luck about one time in 10<sup>8</sup>, and the
run is seven times quicker because none of it is spent waiting out a lost wake-up.

## If you add a duplex socket

Use `DuplexThread.start` for one of its two sides. The rule is only about sockets that two threads
use at the same time in opposite directions: a request/response exchange on one thread is fine, and
so is an accept loop. A Windows-only hang, with no assertion failure, is this page — check whether
the socket involved has a virtual thread parked on each direction.
