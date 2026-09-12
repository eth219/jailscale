#!/usr/bin/env python3
"""Put a fixed amount of work through a jailscale link, one phase per run.

Used by measure.sh. Everything else §14 measures is memory, size or one cold
start, so a change that trades CPU for footprint -- or a toolchain feature that
claims to buy speed, like profile-guided optimization -- had no number to move.

The number that moves is **server CPU per operation**, which measure.sh computes
from the count here and the hub's and node's CPU around the run. A maximum rate
would not do: the first version of this measured the hub's signing limit rather
than its capacity. Offered 32 workers' worth of fresh handshakes, it completed
exactly 7,000 in 5 seconds, which is NodeGroup's SIGN_BURST of 2,000 plus
SIGN_PER_SECOND of 1,000 for five seconds, and refused 7,908 more. That is the
limiter working as §11.5 says it should, and it tells you nothing about a build.

  handshake  a fresh TLS session per request, offered at a fixed rate below that
             limit: SNI routing, a stream opened to the node, a signature asked
             of the hub and bound to that stream (§9.2), the node finishing the
             handshake, then one GET. The expensive path, and the one that
             scales with visitors arriving.
  warm       N sessions kept open, requests one after another on each. No
             handshakes and no signatures: the relay copying bytes, which is
             what scales with traffic rather than with arrivals. Nothing limits
             it, so here the rate is capacity.

The client's own CPU is reported too, because a load generator in Python can
become the thing being measured. If it is using more than the hub and node
together, the rate is the client's limit and the comparison is worthless.

Usage: throughput.py <port> <ca-pem> <seconds> <workdir> handshake <per-second>
       throughput.py <port> <ca-pem> <seconds> <workdir> warm <connections>
Writes "<phase> <completed> <seconds> <errors> <client-cpu-seconds>" to
<workdir>/throughput.txt.
"""
import asyncio
import ssl
import sys
import time

HOST = "demo.hub.test"
REQUEST = b"GET / HTTP/1.1\r\nHost: demo.hub.test\r\n\r\n"


async def read_response(reader):
    """Headers, then exactly Content-Length bytes, so the socket stays usable."""
    head = await reader.readuntil(b"\r\n\r\n")
    if b" 200 " not in head.split(b"\r\n", 1)[0]:
        raise IOError("not a 200")
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    if length:
        await reader.readexactly(length)


def note(counters, e):
    counters["errors"] += 1
    kind = "%s: %s" % (type(e).__name__, e or "(no message)")
    counters["kinds"][kind] = counters["kinds"].get(kind, 0) + 1


async def handshake_phase(ctx, port, seconds, per_second, counters):
    """One session per request, started on a schedule rather than as fast as possible."""
    async def one():
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=ctx, server_hostname=HOST)
        except Exception as e:
            note(counters, e)
            return
        try:
            writer.write(REQUEST)
            await writer.drain()
            await read_response(reader)
            counters["done"] += 1
        except Exception as e:
            note(counters, e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    start = time.monotonic()
    tasks = []
    for i in range(int(seconds * per_second)):
        due = start + i / per_second
        now = time.monotonic()
        if due > now:
            await asyncio.sleep(due - now)
        tasks.append(asyncio.create_task(one()))
        # Keep the backlog bounded: if the server cannot keep up with the offered rate, say so by
        # falling behind rather than by opening an unbounded number of sockets.
        if len(tasks) >= 4 * per_second:
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            tasks = list(pending)
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def warm_phase(ctx, port, seconds, connections, counters):
    deadline = time.monotonic() + seconds

    async def worker():
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=ctx, server_hostname=HOST)
        except Exception as e:
            note(counters, e)
            return
        try:
            while time.monotonic() < deadline:
                writer.write(REQUEST)
                await writer.drain()
                await read_response(reader)
                counters["done"] += 1
        except Exception as e:
            note(counters, e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    await asyncio.gather(*(worker() for _ in range(connections)), return_exceptions=True)


async def main(port, ca, seconds, workdir, phase, n):
    ctx = ssl.create_default_context(cafile=ca)
    counters = {"done": 0, "errors": 0, "kinds": {}}
    cpu0, wall0 = time.process_time(), time.monotonic()
    if phase == "handshake":
        await handshake_phase(ctx, port, seconds, n, counters)
        offered = "%d/s offered" % n
    else:
        await warm_phase(ctx, port, seconds, n, counters)
        offered = "%d connections" % n
    wall = time.monotonic() - wall0
    cpu = time.process_time() - cpu0
    rate = counters["done"] / wall if wall else 0
    print("  %-10s %7.0f /s   (%s, %d done, %d errors, client CPU %.1fs)"
          % (phase, rate, offered, counters["done"], counters["errors"], cpu))
    for kind, k in sorted(counters["kinds"].items(), key=lambda kv: -kv[1])[:2]:
        print("             %6d x %s" % (k, kind[:80]))
    with open(workdir + "/throughput.txt", "w") as f:
        f.write("%s %d %.2f %d %.2f\n"
                % (phase, counters["done"], wall, counters["errors"], cpu))


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]), sys.argv[2], float(sys.argv[3]),
                     sys.argv[4], sys.argv[5], int(sys.argv[6])))
