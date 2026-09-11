# A lost read wake-up on Windows with virtual threads and bidirectional loopback traffic

`MuxSessionTest.largeTransferRespectsFlowControl` hit a 30 second timeout
intermittently, on Windows CI only. Narrowing it down produced a JDK problem
with nothing to do with jailscale. `SockLoop.java` is the reproducer: about 180
lines, no dependencies, `java.base` only.

```sh
javac -d out SockLoop.java
java -cp out SockLoop <runs> <per-run timeout s> <total budget s> <virtual|platform> <uni|bidi>
```

## Measurements

GitHub Actions, Liberica NIK 25.0.4, 4 cores.

| Condition | Stalls |
|---|---|
| windows-2025, bidi, **virtual** | **60** of 152 (39.5%) |
| windows-2025, bidi, platform | 0 of 5,000 |
| windows-2025, uni, virtual | 0 of 5,000 |
| ubuntu-24.04, bidi, virtual | 0 of 5,000 |
| ubuntu-24.04, bidi, platform | 0 of 5,000 |

All three have to be present: Windows, virtual threads, and traffic in both
directions. Remove any one and it does not happen.

For comparison, the same conditions through jailscale's own `MuxSession` stall
in 55 of 3,000 runs (1.8%), which is lower than the bare reproducer. The Noise
encryption and frame handling shift the timing. It is not a defect on our side.

## Lost, not delayed

The wake-up is lost. The same code was run with only the per-run limit changed.

| Per-run limit | Stalls |
|---|---|
| 10s | 120 of 281 (42.7%) |
| 150s | 8 of 20 (40.0%) |

The rate is unchanged. A wake-up that has not arrived within 10 seconds does not
arrive within 150 either.

## What stalls

The writing side parks with a full send buffer. The reading side parks waiting
for a frame length and is never woken. Those two states cannot both hold on one
loopback connection, which points at the `wepoll`-based poller on Windows losing
a read-readiness signal. Platform threads block in the OS directly and do not
take that path.

## What it means for jailscale

There is nothing to fix in our code. The safety net already exists: both the hub
(`NodeSession`) and the node (`HubClient`) set a 60 second read timeout on the
mux socket, and `MuxSession` sends a KEEPALIVE every 25 seconds. If this happens
in production the session closes with `peer idle too long` and the node
reconnects. Visitors on that connection lose up to 60 seconds and then recover.

In CI it is not only `MuxSessionTest`. `RawPortTest.tcpAndUdpThroughAssignedPorts`
has hit the same thing: a 90 second timeout on Windows alone, parked in
`readNBytes` on a loopback socket while another thread wrote the other
direction, on a commit whose Windows job had passed one run earlier. Any test
that moves bytes both ways over loopback is exposed, which is most of the
end-to-end ones.

Neither test is disabled or wrapped in a retry. When one fails this way, read
this page: a Windows-only hang, with no assertion failure, is this.
