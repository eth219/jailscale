# A demo you can point at a link

`measure.sh` measures the code: both native binaries on loopback, with no
network in the way, gated on binary size, idle RSS, peak RSS under 1,000 held
visitors and CLI cold start. It cannot tell you what a visitor feels, because a
visitor is somewhere else and the distance is most of their answer.

This is the other side of that. A small app to publish, and a page that times
its own traffic through the link it arrived on and shows where the milliseconds
went.

```sh
python3 docs/demo/demo.py 3000
jailscale open 3000 --name demo
```

Open the printed `https://demo.<your-hub>` link. Nothing to install: the app is
the standard library, and the page is one file with no dependency to fetch —
which it has to be, since a page that pulls a script from a CDN would measure
the CDN.

In a container, the node reaches the app by name rather than on `127.0.0.1`
(see [deploy/README.md](../../deploy/README.md)), so the app has to listen on more than its own loopback:

```sh
python3 docs/demo/demo.py 3000 --bind 0.0.0.0
jailscale open 3000 --host demo-app --name demo
```

## What the page shows

| | What it is | What it is not |
|---|---|---|
| **Network floor** | your TCP round trip to the hub | anything jailscale can change — every other number contains it |
| **Keyless handshake** | SNI routing, a stream to the node, one hub signature bound to that stream, the node finishing the session | free of the network: it costs round trips, so distance is in it too |
| **Round trip** | `GET /ping` on an open connection: the relay, twice across your network | the relay's own cost — on loopback the pair does ~38,000 requests a second |
| **Download** | bytes a second over one HTTP/1.1 connection | a capacity: it is the smallest of your downlink, the hub's uplink and the node's uplink |
| **Burst** | requests a second at six in flight | a rate limit of the hub's — six is the browser's per-origin cap. `tools/throughput.py` is the one that measures capacity |

The app stamps its own handling time into a `Server-Timing` header and the page
subtracts it, so what is plotted is the path and not the app. Timings come from
the browser's Resource Timing rather than a clock around `fetch()`, which would
also count the tab's own scheduling.

Setup phases read zero in two different situations — the browser reused a
connection, or there is no network to measure because hub and node are on one
machine — and the page says both rather than sending you to open a private
window for the same zeros.

## What it said once

Through `jailscale.sinabro.io` on 2026-09-14, with the visitor and the node
each about 7 ms from it: a TCP round trip of 6.6 to 6.7 ms, a TLS handshake of
29 to 33 ms on top of that, and a warm round trip of 14 ms at p50, about twice
the floor for the extra hop. **The keyless handshake costs round trips, not
CPU**: the same handshake measures 2.4 ms on loopback, where the round trips
are free, and the hub's own work in it is one signature. That is the shape to
plan for: a visitor pays it once on arrival, and nothing after that. It is a
demonstration, not a gate; a browser on the internet measures its own distance
to the hub at least as much as it measures either binary.

## Endpoints

| | |
|---|---|
| `GET /` | the page |
| `GET /ping` | a few bytes, `Server-Timing: app;dur=…` |
| `GET /bytes?n=` | `n` bytes with a `Content-Length`, up to 128 MiB |
| `GET /stats` | requests, bytes and live connections this process has seen |

One deliberate difference from the throwaway app inside `measure.sh`: that one
pins `SO_SNDBUF` to 64 KB, because 400 stalled readers on loopback otherwise
autotune the machine's whole network memory pool into socket buffers. This one
does not. A small send buffer caps throughput at buffer over round trip — 64 KB
at 50 ms is 1.3 MB/s — so over a real network the pin would turn the download
figure into a measurement of the buffer. Different workload, different hazard.

Nothing measured here belongs in a budget, which is also why it sits under `docs/` rather than in
`tools/`: everything in `tools/` is something `measure.sh` calls, and nothing calls this.
