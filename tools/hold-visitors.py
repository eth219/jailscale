#!/usr/bin/env python3
"""Hold N visitor TLS sessions open against a jailscale link at the same time.

Used by measure.sh. The point is that they are all alive together: a load
generator that fires short requests and moves on never has N sessions open, and
so it measures a fraction of the memory the design's own limit allows (the hub
caps a name at SniRouter.MAX_PER_NAME concurrent visitors).

Usage: hold-visitors.py <port> <ca-pem> <count> <workdir>
Writes "<held> <seconds>" to <workdir>/held.txt, then keeps the sessions up for
HOLD_SECONDS so the caller can sample RSS, and closes them.
"""
import asyncio
import ssl
import sys
import time

HOLD_SECONDS = 12
STEP_TIMEOUT = 10
BATCH = 100
BATCH_PAUSE = 0.05


async def main(port, ca, count, workdir):
    ctx = ssl.create_default_context(cafile=ca)
    held = []

    async def one():
        # Connection: close, so this measures a visitor session held open rather than a whole live
        # chain to the app: the budget was set against the former, and the latter is a different
        # (heavier) measurement. And a timeout on every step, because without one a saturated node
        # leaves this waiting for a reply that never comes -- which hung a CI run rather than
        # reporting a number.
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            "127.0.0.1", port, ssl=ctx, server_hostname="demo.hub.test"), STEP_TIMEOUT)
        writer.write(b"GET / HTTP/1.1\r\nHost: demo.hub.test\r\nConnection: close\r\n\r\n")
        await asyncio.wait_for(writer.drain(), STEP_TIMEOUT)
        line = await asyncio.wait_for(reader.readline(), STEP_TIMEOUT)
        if b"200" in line:
            held.append(writer)
        else:
            writer.close()

    started = time.time()
    # Ramp in batches: a burst larger than the kernel accept queue is reset by the
    # kernel before jailscale ever sees it, which would measure the wrong thing.
    for i in range(0, count, BATCH):
        n = min(BATCH, count - i)
        await asyncio.gather(*(one() for _ in range(n)), return_exceptions=True)
        await asyncio.sleep(BATCH_PAUSE)

    with open(workdir + "/held.txt", "w") as f:
        f.write("%d %.1f" % (len(held), time.time() - started))
    await asyncio.sleep(HOLD_SECONDS)
    for w in held:
        w.close()


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]))
