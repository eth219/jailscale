#!/usr/bin/env python3
"""A small app to put behind a jailscale link, and a page that measures the link.

    python3 docs/demo/demo.py 3000
    jailscale open 3000 --name demo

Then open the printed https link. The page times its own traffic and shows where
the milliseconds went: the network to the hub, the keyless handshake, and the
relay round trip on a connection that is already open.

WHAT THIS IS NOT. It is not measure.sh. That script runs both binaries on
loopback with no network in the way, and its numbers are a gate. This one is
measured from a browser somewhere on the internet, so the viewer's own link and
their distance to the hub are inside every number on the page. That is the point
-- it answers "what does a visitor get" rather than "what does the code cost" --
but the two questions have different answers and the page says so out loud.
Nothing here belongs in a budget.

Everything is the standard library, like the rest of tools/: the demo has to run
wherever the node runs, and the node has no runtime dependency to borrow.

One deliberate difference from measure.sh's throwaway app. That one pins
SO_SNDBUF to 64 KB, because 400 stalled readers on loopback otherwise autotune
the machine's whole network memory pool into socket buffers (see measure.sh's
header). This app does not: a small send buffer caps throughput to
buffer/round-trip, which over a real network -- 64 KB at 50 ms is 1.3 MB/s --
would make the throughput figure a measurement of the buffer. Different
workload, different hazard: a handful of visitors reading as fast as they can.
"""
import asyncio
import os
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "index.html")

# Enough to fill a real path for a second or two, and bounded so that a stray
# ?n= cannot ask this process to write forever. Lower it with --max-bytes where
# the app is public: the page only ever asks for 8 MB, and the default would let
# an anonymous caller pull 128 MB at a time out of whatever uplink the node sits
# behind.
MAX_BYTES = 128 * 1024 * 1024
CHUNK = b"x" * 65536

STATE = {"requests": 0, "bytes": 0, "live": 0, "started": time.time(),
         "max_bytes": MAX_BYTES}


def response(status, ctype, body, extra=()):
    lines = [
        "HTTP/1.1 " + status,
        "Content-Type: " + ctype,
        "Content-Length: %d" % len(body),
        # No store anywhere: a cached /ping would measure the browser's disk.
        "Cache-Control: no-store",
        "Connection: keep-alive",
    ]
    lines.extend(extra)
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


async def send_bytes(writer, n):
    """A body of n bytes, written until the reader stops taking them.

    Content-Length rather than chunked, so the page can divide bytes by the time
    between the first and the last one without counting framing it cannot see.
    """
    writer.write((
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %d\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: keep-alive\r\n\r\n" % n
    ).encode())
    sent = 0
    while sent < n:
        piece = CHUNK if n - sent >= len(CHUNK) else CHUNK[: n - sent]
        writer.write(piece)
        # Parks as soon as the path downstream is full, which is where the
        # measurement lives: the producer here is faster than any real link.
        await writer.drain()
        sent += len(piece)
    STATE["bytes"] += sent


def query_int(query, key, default, lo, hi):
    for part in query.split("&"):
        name, _, value = part.partition("=")
        if name == key:
            try:
                return max(lo, min(hi, int(value)))
            except ValueError:
                return default
    return default


async def serve(reader, writer):
    STATE["live"] += 1
    try:
        while True:
            # 8 KB of request line and headers is plenty for a GET and bounds
            # what one connection can make this process hold.
            head = await reader.readuntil(b"\r\n\r\n")
            if len(head) > 8192:
                return
            started = time.perf_counter()
            STATE["requests"] += 1
            lines = head.decode("latin-1").split("\r\n")
            try:
                method, target, _ = lines[0].split(" ", 2)
            except ValueError:
                return
            path, _, query = target.partition("?")
            keep = "connection: close" not in head.decode("latin-1").lower()

            if method not in ("GET", "HEAD"):
                writer.write(response("405 Method Not Allowed", "text/plain", b"GET only\n"))
            elif path == "/":
                with open(INDEX, "rb") as f:
                    body = f.read()
                writer.write(response("200 OK", "text/html; charset=utf-8", body))
            elif path == "/ping":
                # The smallest honest unit: a request and a response, nothing in
                # the app worth measuring. Server-Timing carries what little the
                # app did spend, so the page can subtract it instead of
                # assuming it away -- the browser exposes it on same-origin
                # responses through PerformanceResourceTiming.serverTiming.
                body = b'{"t":%d}' % int(time.time() * 1000)
                dur = (time.perf_counter() - started) * 1000
                writer.write(response("200 OK", "application/json", body,
                                      ["Server-Timing: app;dur=%.3f" % dur]))
            elif path == "/bytes":
                n = query_int(query, "n", 8 * 1024 * 1024, 0, STATE["max_bytes"])
                if method == "HEAD":
                    writer.write(response("200 OK", "application/octet-stream", b""))
                else:
                    await send_bytes(writer, n)
            elif path == "/stats":
                # maxBytes is here so the page can hide what it cannot measure. A
                # public deployment runs with --max-bytes 0, and a download card
                # reporting 0 MB/s would be a broken instrument rather than an
                # absent one.
                body = ('{"requests":%d,"bytes":%d,"live":%d,"uptime":%.1f,"maxBytes":%d}'
                        % (STATE["requests"], STATE["bytes"], STATE["live"],
                           time.time() - STATE["started"], STATE["max_bytes"])).encode()
                dur = (time.perf_counter() - started) * 1000
                writer.write(response("200 OK", "application/json", body,
                                      ["Server-Timing: app;dur=%.3f" % dur]))
            else:
                writer.write(response("404 Not Found", "text/plain", b"not found\n"))

            await writer.drain()
            if not keep:
                return
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
        pass
    except Exception:
        pass
    finally:
        STATE["live"] -= 1
        try:
            writer.close()
        except Exception:
            pass


async def main():
    port = 3000
    bind = "127.0.0.1"
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--max-bytes":
            STATE["max_bytes"] = max(0, min(MAX_BYTES, int(args[i + 1])))
            i += 2
        elif args[i] == "--bind":
            # For the container path in the README: the node reaches the app by
            # container name, and a socket on 127.0.0.1 inside a container is
            # reachable from nothing but that container.
            bind = args[i + 1]
            i += 2
        else:
            port = int(args[i])
            i += 1
    # A burst larger than the accept queue is reset by the kernel before this
    # process sees it, and the burst test on the page is exactly such a burst.
    server = await asyncio.start_server(serve, bind, port, backlog=512,
                                        family=socket.AF_INET)
    print("demo app on http://%s:%d -- now: jailscale open %d --name demo"
          % (bind, port, port), flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
