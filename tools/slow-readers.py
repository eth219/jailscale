#!/usr/bin/env python3
"""Hold N visitor sessions open that ask for a large body and then stop reading it.

The axis tools/hold-visitors.py does not cover. That one holds sessions with no
bytes in flight, so the hub's per-stream receive queues are near empty and the
peak it reports says nothing about what a stalled reader costs. Here every
visitor asks for a body far larger than one stream's 256 KB window and reads
only the status line, so the node fills its credits, the hub cannot hand the
bytes on, and they come to rest in the hub's queues -- which is the shape of
ARCHITECTURE.md 5.3's receive budget, and the only shape that reaches it.

A hub with the budget sheds the slowest streams and stays under its heap
ceiling; a hub without one holds 256 KB per visitor until the process dies.

Usage: slow-readers.py <port> <ca-pem> <count> <workdir> [path]
Writes "<held> <seconds>" to <workdir>/slow.txt, holds for HOLD_SECONDS so the
caller can sample RSS, then closes.
"""
import asyncio
import ssl
import sys
import time

HOLD_SECONDS = 15
STEP_TIMEOUT = 15
BATCH = 50
BATCH_PAUSE = 0.05


async def main(port, ca, count, workdir, path):
    ctx = ssl.create_default_context(cafile=ca)
    held = []

    async def one():
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            "127.0.0.1", port, ssl=ctx, server_hostname="demo.hub.test"), STEP_TIMEOUT)
        # Keep-alive, so the chain to the app stays live and the body keeps coming: with
        # Connection: close the node finishes and Relay's linger, not a stalled reader, is what
        # holds the session.
        writer.write(("GET %s HTTP/1.1\r\nHost: demo.hub.test\r\n\r\n" % path).encode())
        await asyncio.wait_for(writer.drain(), STEP_TIMEOUT)
        # One line, and then nothing, ever. The rest of the body has to go somewhere.
        line = await asyncio.wait_for(reader.readline(), STEP_TIMEOUT)
        if b"200" in line:
            held.append((reader, writer))
        else:
            writer.close()

    started = time.time()
    for i in range(0, count, BATCH):
        n = min(BATCH, count - i)
        await asyncio.gather(*(one() for _ in range(n)), return_exceptions=True)
        await asyncio.sleep(BATCH_PAUSE)

    with open(workdir + "/slow.txt", "w") as f:
        f.write("%d %.1f" % (len(held), time.time() - started))
    await asyncio.sleep(HOLD_SECONDS)
    # Tell the caller the hold is over before tearing it down. Closing N sessions at once is a
    # thundering herd of its own, and a latency probe that lands in it measures the teardown rather
    # than the state being held -- which is exactly what it looked like when the probe's last sample
    # was the only bad one, run after run, and was read as a stall that was still there.
    open(workdir + "/closing.txt", "w").close()
    for _, w in held:
        w.close()


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4],
                     sys.argv[5] if len(sys.argv) > 5 else "/big"))
