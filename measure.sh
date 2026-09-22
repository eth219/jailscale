#!/bin/sh
# Lightweight-budget measurement and gate (ARCHITECTURE.md §14): runs the native hub and two node
# daemons on loopback, joins them through the real CLI, opens a link, optionally throws LOAD
# concurrent visitors at it, and reports binary size, RSS and CLI cold start.
#
# Usage: ./native.sh -DskipTests && ./measure.sh [--check]
#   IDLE=10      seconds to idle before the idle measurement
#   PORT=18443   the hub's port; the local app follows it (APP_PORT, default PORT+138) so that two
#                runs on one machine cannot land on each other
#   LOAD=1000    also run LOAD concurrent https visitors through the link (needs curl >= 7.66)
#   --check      exit 1 when a number exceeds the budget below (the CI gate)
#   SLOW=300     also run SLOW visitors that ask for a large body and then stop reading it, which
#                is the axis LOAD does not touch: LOAD holds sessions with no bytes in flight, so
#                the hub's receive queues are empty and its peak says nothing about what a stalled
#                reader costs. This is what reaches the receive budget (ARCHITECTURE.md 5.3).
#   RATE=8       also measure throughput, 8s per phase (tools/throughput.py); reported, not gated.
#                RATE_HANDSHAKES= offered handshakes a second (400), RATE_CONNS= warm ones (32)
#                RATE_PHASES="warm" runs one phase instead of both
#   HUB_OPTS=    runtime options for the hub, and JAILSCALE_DAEMON_OPTS for the node's daemon:
#                -XX:MaxHeapSize= to lift the build's ceiling
# HOW THIS HARNESS HAS MISLED PEOPLE. Every item below produced a confident, wrong conclusion that
# somebody acted on, and in every one the numbers looked plausible -- which is the only reason the
# list is worth keeping. Read it before trusting a surprising result from here.
#
#   Shared state. The local app was hardcoded on 18080 while PORT moved only the hub, so two runs at
#   once shared one app and quietly corrupted each other. Fixed (APP_PORT follows PORT), but the
#   shape recurs: another session's load also moves these numbers, and hub peak RSS varies 2x on an
#   idle machine. Ramp times drifted monotonically slower across one afternoon as the machine filled,
#   which read as a code change and was the machine.
#
#   The harness shaping what it measures. The latency prober was serial, so while one probe was slow
#   no connection arrived and the hub's accept loop showed a gap exactly as long as the probe -- an
#   effect read as a cause. Serial sampling also turned a contiguous burst of slow admissions into
#   one rare-looking outlier. And it probed into the herd of N sessions closing at once. All three
#   fixed; all three were believed first.
#
#   Instruments that answer a narrower question than they look like they do. Adding one timer per
#   rebuild, each to a stage guessed at in advance, had every stage come back fast -- which produced
#   "the time is between stages, so it is scheduling". It was not: measuring every stage at once
#   showed unaccounted at zero and all of it in one stage. Eight rebuilds, and the answer needed
#   every stage measured at once instead of one at a time. Twice over, a value already being
#   collected was not read. (Those stage timers were the hub's metrics endpoint, and went with it;
#   what is left here is the gate, not the breakdown.)
#
#   Reading a mechanism one layer too shallow. "Control frames queue behind data, so put them in
#   front" -- correct as far as it goes, and the measured problem was that there is no room in front,
#   because the connection itself is full. Ordering and capacity are different faults.
#
#   Experiments invalidated by a later fix. With two causes, an experiment run before one is fixed
#   says nothing about the other. One finding here was retracted and then un-retracted for exactly
#   that reason.
#
#   RSS cannot see the live set. A heap ceiling means the collector fills the space it has, so RSS
#   plateaus whatever the live set does. That is why the receive budget is gated on
#   jailhub_receive_queued_peak_bytes, which is exact, and RSS is only reported here.
#
#   The configuration this harness chooses is part of what it measures, and two of its choices make
#   the idle row describe a node nobody runs. It joins with --ca-file, so the node's trust manager
#   holds two certificates; a node joined to a public-CA hub leaves caFile null and pays about
#   0.55 MB more for the trust store the binary carries. And it samples idle in the daemon that just
#   performed the join, which is 2.0 MB that a node pays once -- the same node restarted idles about
#   2 MB lower. Neither is a bug in the budget, which is a gate on this tree against itself, and the
#   two are small and point opposite ways, so nothing here is mis-gated. But neither number is what
#   an operator's node does, and the README said it was. docs/jsse-idle-cost has both, and
#   truststore.sh there has the two ways of measuring the first one that give wrong answers.
#
#   The kernel is shared state too, and it was the one nobody sampled. SLOW= visitors asked for
#   8 MB on loopback and the kernel autotuned every socket in the chain to megabytes, so 400 of
#   them put 660 to 680 MB in socket buffers with the machine's cluster pools at their caps, and
#   every socket on the machine froze: the node's write to the hub blocked for 3.2 s, an ordinary
#   visitor took 5 to 17 s, this script's own ramp took 18 s instead of 5, and both processes' own
#   timers said they were idle, because they were. It read as the multiplexer's control frames
#   starving behind data, three designs were priced against it, and none of them touched the
#   cause. Two runs told them apart: the same 400 visitors with a 768 KB body kept the kernel at
#   229 MB and served the ordinary visitor in 5 to 26 ms through the same multiplexer. And it was
#   intermittent at the old occupancy -- two of four runs froze, on the same binaries -- which is
#   how it looked like a code change between builds. The SLOW phase now prints the kernel's peak
#   and how many allocations it refused, and every socket in the chain has a bounded buffer: the
#   node's app socket (Visitors.connectLocal), the app's own send side here, and the visitor's.
set -eu
R=$(cd "$(dirname "$0")" && pwd)
HUB=$R/hub/target/jailhub
NODE=$R/node/target/jailscale
CERT=$R/hub/src/test/resources/tls/hub-test.crt
KEY=$R/hub/src/test/resources/tls/hub-test.key
W=/tmp/jsm$$
PORT=${PORT:-18443}
# The local app's port moves with PORT, or two runs at once quietly ruin each other's numbers: PORT
# used to move the hub and leave the app on 18080, so the second run's node published the first
# run's app and both sampled RSS off a topology neither of them set up. Found by two sessions
# measuring at the same time.
APP_PORT=${APP_PORT:-$((PORT + 138))}
CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1

# Budget (ARCHITECTURE.md §14). Change only with a reason, in the same commit as the design table.
# Per platform, because the same code measures differently on each and one shared number would have
# to be the loosest: Linux counts the binary's own mapped pages in RSS where macOS largely does not
# -- on linux-amd64 about 32 MB of a 35 MB idle RSS is the binary itself, clean and reclaimable,
# against about 3 MB of anonymous memory
# at the moment this script measures. (A hub left running grows that anonymous share -- the live one
# is at 15 MB after a day -- which is why the budget is on RSS and the anonymous figure is only
# printed. ARCHITECTURE.md §14 has both numbers and which is which.)
# These describe what the release ships: GraalVM CE 25.3, -O2, no profile-guided optimization, on
# both the gate's runner and the machine this is developed on. Measured: binaries 25.3 to 26.2 MiB,
# idle 24.8 to 35.1 MB, peak with 1,000 held 53.5 to 70.0 MB, CLI 2.4 to 6.3 ms.
# The load budget is the one with teeth: without the heap ceilings the peak was 91.7 (hub) and
# 94.0 (node), so a build that lost them fails here. The node runs closer to it on the 25.3 line,
# which expands the heap more eagerly under the same ceiling -- at -XX:MaxHeapSize=32m the same
# 1,000 visitors peak at 59.8 (linux) and 53.7 (macOS), which is the lever if this ever binds.
B_NODE_LOAD_MB=88
B_HUB_LOAD_MB=88
# The SLOW phase needs its own node budget, looser than B_NODE_LOAD_MB and for a reason that is not
# the receive budget: a visitor sending one GET line puts tens of bytes in the node's receive queue.
# What grows is TlsEndpoint's per-visitor state (netInBuf + appInBuf + the SSLEngine's own, 50-60 KB
# each) times the visitors live at once -- its own unbounded per-connection term, and its own change
# to make.
#
# BECAUSE THAT TERM IS PER VISITOR, THE BUDGET IS ONLY A BUDGET AT ONE COUNT. B_NODE_SLOW_AT is the
# count it was measured at, and the gate below is skipped at any other: applied to a different SLOW=
# this number means nothing in either direction. That check earned itself once already -- the gate
# was very nearly wired to SLOW=1000 against a budget measured at 1,000 on a machine where 1,000 no
# longer behaved.
B_NODE_SLOW_AT=1000
#
# RSS is the right metric here and the wrong one for the hub, which is worth knowing rather than
# looking inconsistent. The hub's growth is receive queues that the collector expands and reclaims on
# its own schedule, so its peak swung 61 to 125 MB on one configuration; the node's is per-visitor TLS
# state that scales with the visitor count, and it repeated to 0.1 MB across runs. So the hub is gated
# on jailhub_receive_queued_peak_bytes, which is exact, and the node on RSS, which for the node is
# reproducible. Replace this with a direct count of concurrent visitor TLS endpoints when the node
# exposes one; RSS is standing in for that number.
#
# WHY 1,000, WHEN THIS RAN AT 400 FOR A DAY. It ran at 400 because at a thousand stalled readers the
# node reached the open per-visitor defect instead of a peak: 817 of 1,000 admitted, the ramp 60.7 s
# against 5.4 s at 400, six OutOfMemoryErrors taking mux-reader and mux-writer with them, the hub
# connection dropped and remade, an ordinary visitor timing out at 30 s fourteen probes running.
# Gating that would have been a red main on every build.
#
# The node bounds its concurrent visitors now (Visitors.MAX_IN_FLIGHT, ARCHITECTURE.md 9.3), so a
# thousand is survivable and worth asking for. Three runs on darwin-arm64 with the bound: 450 of
# 1,000 held with the rest refused, node peak 86.2, 86.8, 86.8 MB, no OutOfMemoryError, and the
# ordinary visitor served in 1 to 36 ms.
#
# WHAT RAISING THE COUNT DID NOT BUY, WHICH IS WHAT IT WAS RAISED FOR. The reasoning was that 400
# never got the hub's receive queue past 4.7 MB of its 24 MB budget on the CI runner, so the one
# exact assertion in this phase could not fail where the gate runs, and that a thousand would reach
# it. It does on a developer's machine -- 24.0 of 24.0 with 27 to 91 streams shed, at 400 as well as
# at 1,000 -- and it does NOT on the runner: two runs at a thousand read 0.1 and 10.2 MB with
# nothing reclaimed, against 2.0, 4.4, 4.7 and 11.9 at four hundred. Lower on average, not higher,
# because the node refuses 550 of the thousand and the ramp stretches to 18 s, so the hub drains
# what it is given as fast as it arrives. The queue's occupancy on that runner is somewhere between
# 0.1 and 11.9 MB whatever it is asked for, and the honest reading is that this machine cannot fill
# the queue at all: the assertion lives with whoever runs this by hand.
#
# So what 1,000 buys is the node's bound under load -- 450 held, 550 refused, and a node that is
# still there afterwards -- which is the thing that changed and the thing worth a gate. Left at 400
# nothing in CI would ever exercise it.
#
# The number itself is per platform, below, for the same RSS-accounting reason as the idle budgets:
# it was derived on darwin-arm64, and a Linux peak carries the binary's own mapped pages on top of
# the anonymous memory this phase actually grows.
B_CLI_MS=50
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    # These are the release toolchain's, which they once were not: the binary budget was 30 while
    # the release shipped 30.1 MiB darwin-arm64 binaries, and the idle budget was 28 while that
    # binary idled at 29.0. Both had been set against whichever GraalVM this machine happened to
    # have, and the gate only runs on linux, so neither could ever fail.
    # ~10% over the highest seen at SLOW=1000 with the visitor bound in place (86.2, 86.8, 86.8).
    # It was the same 95 at SLOW=400, where the figures were 82.1 to 83.2: the node holds at most
    # MAX_IN_FLIGHT visitors either way, so past the bound the count stops moving this number.
    B_BINARY_MIB=28; B_NODE_IDLE_MB=28; B_HUB_IDLE_MB=28; B_NODE_SLOW_MB=95 ;;
  Linux-x86_64)
    # Measured on the ubuntu-24.04 runner at SLOW=1000, the count the gate runs: 92.5 and 94.6 MB.
    # 105 is ~11% over the higher, the margin the macOS one carries.
    #
    # This constant has been 105 before, and the fact that it is 105 again is a coincidence worth
    # naming rather than a vindication. That 105 was derived -- the macOS figure plus the two
    # platforms' idle difference -- and it was applied to SLOW=400, where the runner actually reads
    # 88.5 to 89.7, so it was loose by more than the margin it was supposed to carry. A derived
    # number that lands near a later measurement of a different thing is still a number nobody
    # measured.
    B_BINARY_MIB=28; B_NODE_IDLE_MB=38; B_HUB_IDLE_MB=38; B_NODE_SLOW_MB=105 ;;
  *)
    # An unmeasured platform gets the loosest of the measured ones rather than a guess of its own.
    echo "note: no budget measured for $(uname -s)-$(uname -m); using the widest known"
    B_BINARY_MIB=28; B_NODE_IDLE_MB=38; B_HUB_IDLE_MB=38; B_NODE_SLOW_MB=105 ;;
esac

mkdir -p "$W/hub" "$W/app"
# The node daemons log to their own state directories, not to a file this script redirects: `node
# open` daemonises itself. Both OOM checks used to grep "$W/node.log", which nothing ever writes, so
# a node that died of memory exhaustion passed silently -- on the one axis built to provoke exactly
# that. Globbed, because there are two homes ($W/a, $W/b) and a third would be missed by name.
oom_check() {
  for f in "$W/hub.log" "$W"/*/daemon.log; do
    [ -f "$f" ] || continue
    if grep -qi OutOfMemory "$f"; then
      echo "  !! OutOfMemoryError in ${f#$W/}"; fail=1
    fi
  done
}

# The work directory goes at exit, so anything worth reading after a failure has to be copied while
# it still exists. Findings on this axis are intermittent: losing the one run that reproduced costs
# an hour of re-running, which is how the first OOM log was lost.
keep_logs() {
  d=$(mktemp -d "${TMPDIR:-/tmp}/jsm-failed-XXXX")
  cp "$W/hub.log" "$d/" 2>/dev/null || true
  for f in "$W"/*/daemon.log; do
    [ -f "$f" ] && cp "$f" "$d/$(basename "$(dirname "$f")")-daemon.log"
  done
  echo "  logs kept in $d"
}

cleanup() {
  # Matched on the subcommand and the work directory, not on the binary name next to them:
  # JAILSCALE_DAEMON_OPTS puts runtime options between the two, and a pattern that expected them
  # adjacent stopped matching, so the daemons were never signalled -- which is how an instrumented
  # binary came to write no profile at all.
  pkill -f "daemon --home $W" 2>/dev/null || true
  [ -n "${HUBPID:-}" ] && kill "$HUBPID" 2>/dev/null || true
  [ -n "${APPPID:-}" ] && kill "$APPPID" 2>/dev/null || true
  sleep 0.3
  rm -rf "$W"
}
trap cleanup EXIT
fail=0
gate() { # gate <label> <value> <budget>
  if [ "$CHECK" = 1 ] && [ "$(echo "$2 > $3" | bc -l)" = 1 ]; then
    echo "  !! $1 = $2 exceeds budget $3"; fail=1
  fi
}
rss_mb() { echo "$(ps -o rss= -p "$1" | tr -d ' ') / 1024" | bc -l; }
# On Linux most of RSS is the binary's own mapped pages, which are clean and reclaimable; the
# anonymous share is what the process actually costs. Reported, not gated -- the budget stays on the
# number `ps` reports, so the two platforms are compared on the same measurement.
# CPU seconds a process has used, to tell a server-bound rate from a client-bound one.
cpu_s() {
  if [ -r "/proc/$1/stat" ]; then
    awk '{print ($14 + $15) / 100}' "/proc/$1/stat"
  else
    # macOS ps prints cumulative CPU as [[dd-]hh:]mm:ss.ss
    ps -o time= -p "$1" 2>/dev/null | awk -F'[:-]' '{
      n = NF; s = $n; if (n > 1) s += $(n-1) * 60; if (n > 2) s += $(n-2) * 3600;
      if (n > 3) s += $(n-3) * 86400; printf "%.2f", s }'
  fi
}
anon_note() {
  [ -r "/proc/$1/status" ] || return 0
  printf '   (%.1f anonymous)' "$(echo "$(awk '/^RssAnon:/{print $2}' "/proc/$1/status") / 1024" | bc -l)"
}
# What the kernel is holding for sockets, machine-wide, in KB: the shared state the SLOW phase used
# to fill without anyone looking (the header says what that cost). macOS: mbuf clusters in use,
# summed by size -- not the pool's allocated size, which stays where the last peak left it. Linux
# counts TCP pages in /proc/net/sockstat. Anything else reads 0.
net_mem_kb() {
  if [ -r /proc/net/sockstat ]; then
    awk '/^TCP:/{for(i=1;i<=NF;i++) if($i=="mem"){print $(i+1)*4; exit}}' /proc/net/sockstat
  else
    netstat -m 2>/dev/null | awk '/mbuf [0-9]+KB clusters in use/{split($1,a,"/"); sub("KB","",$3); kb+=a[1]*$3} END{print kb+0}'
  fi
}
# Allocations the kernel refused, cumulative; a delta over a phase says the pool ran dry. macOS
# counts these; Linux has no equivalent counter, so it is not claimed there.
net_denied() {
  [ -r /proc/net/sockstat ] && { echo n/a; return; }
  netstat -m 2>/dev/null | awk '/requests for memory denied/{print $1; exit}'
}

# HUB_OPTS is the hub's half of JAILSCALE_DAEMON_OPTS (which the CLI gives the node's daemon):
# runtime options the native image reads before main, deliberately unquoted so several split.
# shellcheck disable=SC2086
"$HUB" ${HUB_OPTS:-} serve --base-url "https://hub.test:$PORT" --listen "127.0.0.1:$PORT" --tls-cert "$CERT" --tls-key "$KEY" \
  --state "$W/hub" > "$W/hub.log" 2>&1 &
HUBPID=$!
sleep 1.5
INV=$(grep -o "https://hub.test:$PORT/join/[A-Za-z0-9_-]*" "$W/hub.log" | head -1)
# --ca-file pins the test certificate, which is what a loopback hub needs and is also, deliberately,
# not what a real node does (see the header: it is worth about 0.55 MB of the idle figure below).
"$NODE" up --invite "$INV" --hub-addr 127.0.0.1 --user alice --ca-file "$CERT" --home "$W/a" > /dev/null
INV2=$("$NODE" invite --user bob --home "$W/a" | grep -o "https://hub.test:$PORT/join/[A-Za-z0-9_-]*" | head -1)
"$NODE" up --invite "$INV2" --hub-addr 127.0.0.1 --ca-file "$CERT" --home "$W/b" > /dev/null
"$NODE" netcheck --home "$W/b" > /dev/null
# A local app behind alice, published as demo.hub.test (the idle budget is "one link open").
# asyncio rather than http.server, and HTTP/1.1 with keep-alive, for two reasons that only showed
# up when both were needed at once. Keep-alive is what makes tools/throughput.py's warm phase
# possible at all, and it also makes the load phase honest: with a connection that closes after
# every response, a "held" visitor is only held because Relay lingers, not because anything is
# still connected end to end. But ThreadingHTTPServer costs a thread per connection, so 1,000 held
# visitors became 1,000 Python threads, and the measurement got worse rather than better -- 900 of
# 1,000 held, and peaks of 76 and 100 MB against 53 and 69. One event loop holds them all for
# nothing. The backlog is set high because a burst larger than the accept queue is reset by the
# kernel before the app sees it.
cat > "$W/app/app.py" <<'EOF'
import asyncio
import socket
import sys

KEEP = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\nhello\n"
CLOSE = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello\n"
# /big is for tools/slow-readers.py: far more than one stream's 256 KB window, so a visitor that
# stops reading leaves bytes with nowhere to go but the hub's receive queue.
BIG = 8 * 1024 * 1024
CHUNK = b"x" * 65536

async def serve(reader, writer):
    # A small send buffer, so a stalled visitor leaves 64 KB of this app's bytes in the kernel and
    # not the megabytes it would autotune to. The SLOW phase is measured against the machine's
    # network memory pool, and the app's share of it is the harness's to bound (the header).
    writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    # Honour Connection: close, because the two phases want opposite things. The warm throughput
    # phase needs the connection to survive a response; the load phase wants what an ordinary page
    # view does, one request and gone, and holding 1,000 live chains instead measures something
    # heavier (and slower) than the budget was set against.
    try:
        while True:
            head = await reader.readuntil(b"\r\n\r\n")
            if b" /big " in head:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n" % BIG)
                for _ in range(BIG // len(CHUNK)):
                    writer.write(CHUNK)
                    # Parks once the node stops taking them, which is the whole point: the producer
                    # is faster than the visitor and something in between holds the difference.
                    await writer.drain()
                continue
            if b"connection: close" in head.lower():
                writer.write(CLOSE)
                await writer.drain()
                return
            writer.write(KEEP)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

async def main():
    server = await asyncio.start_server(serve, '127.0.0.1', int(sys.argv[1]), backlog=1024)
    async with server:
        await server.serve_forever()

asyncio.run(main())
EOF
python3 "$W/app/app.py" "$APP_PORT" > /dev/null 2>&1 &
APPPID=$!
"$NODE" open "$APP_PORT" --name demo --home "$W/a" > /dev/null
sleep "${IDLE:-10}"
NODEPID=$(pgrep -f "daemon --home $W/a")

echo "binary size (MiB)"
for b in "$HUB" "$NODE"; do
  mib=$(echo "$(stat -f%z "$b" 2>/dev/null || stat -c%s "$b") / 1048576" | bc -l)
  printf '  %-10s %6.1f\n' "$(basename "$b")" "$mib"; gate "$(basename "$b") size" "$mib" "$B_BINARY_MIB"
done
echo "idle RSS after ${IDLE:-10}s, one link open (MB)"
printf '  %-10s %6.1f%s\n' jailhub "$(rss_mb "$HUBPID")" "$(anon_note "$HUBPID")"
gate "hub idle RSS" "$(rss_mb "$HUBPID")" "$B_HUB_IDLE_MB"
printf '  %-10s %6.1f%s\n' jailscale "$(rss_mb "$NODEPID")" "$(anon_note "$NODEPID")"
gate "node idle RSS" "$(rss_mb "$NODEPID")" "$B_NODE_IDLE_MB"

if [ -n "${LOAD:-}" ]; then
  # Visitors are held open at the same time, not fired and forgotten. curl --parallel churns
  # short requests, so it never has LOAD sessions alive at once and reported about a third of the
  # real memory. The peak below is sampled while every connection is still up.
  echo "load: $LOAD visitors held open at once, peak RSS while they are up"
  python3 "$R/tools/hold-visitors.py" "$PORT" "$CERT" "$LOAD" "$W" > "$W/held.log" 2>&1 &
  LGPID=$!
  peak_h=0; peak_n=0
  while kill -0 $LGPID 2>/dev/null; do
    h=$(rss_mb "$HUBPID"); n=$(rss_mb "$NODEPID")
    [ "$(echo "$h > $peak_h" | bc -l)" = 1 ] && peak_h=$h
    [ "$(echo "$n > $peak_n" | bc -l)" = 1 ] && peak_n=$n
    sleep 1
  done
  wait $LGPID 2>/dev/null || true
  ok=$(cut -d' ' -f1 "$W/held.txt" 2>/dev/null || echo 0)
  printf '  %s/%s held in %ss\n' "$ok" "$LOAD" "$(cut -d' ' -f2 "$W/held.txt" 2>/dev/null || echo '?')"
  printf '  %-10s %6.1f  (peak)\n' jailhub "$peak_h";  gate "hub RSS under load" "$peak_h" "$B_HUB_LOAD_MB"
  printf '  %-10s %6.1f  (peak)\n' jailscale "$peak_n"; gate "node RSS under load" "$peak_n" "$B_NODE_LOAD_MB"
  oom_check
  [ "$CHECK" = 1 ] && [ "$ok" -lt $((LOAD * 99 / 100)) ] && { echo "  !! only $ok of $LOAD visitors were held"; fail=1; }
  [ "${fail:-0}" = 1 ] && keep_logs
fi

if [ -n "${SLOW:-}" ]; then
  # The saturation axis. Each visitor asks for 8 MB and reads one line, so the node fills its
  # per-stream credits and the hub is left holding them. Gated on the same ceiling as LOAD, because
  # the claim being checked is exactly that: a stalled reader must not move the hub's peak past it.
  # Without the receive budget of ARCHITECTURE.md 5.3 this is what killed the process outright.
  # The visitor's socket is given a small receive buffer (tools/slow-readers.py) so that the bytes
  # come to rest in the hub's queue and not in the kernel, which is what the budget bounds.
  echo "saturation: $SLOW visitors asking for 8 MB and not reading it, peak RSS while they are up"
  python3 "$R/tools/slow-readers.py" "$PORT" "$CERT" "$SLOW" "$W" > "$W/slow.log" 2>&1 &
  SGPID=$!
  # An ordinary visitor is probed repeatedly while the stalled ones are held, not once: a single
  # sample cannot tell a reclaim stall from a GC pause from the ramp still running, and the spread
  # is the thing worth knowing -- a hub that serves at 300 ms with one 5 s outlier is a different
  # product from one that serves at 300 ms flat.
  peak_h=0; peak_n=0; probes=""
  # The kernel's share, sampled alongside: this is where 400 stalled chains once put 680 MB while
  # both processes reported themselves idle (the header, and ARCHITECTURE.md 14).
  net0=$(net_mem_kb); peak_k=${net0:-0}; denied0=$(net_denied)
  while kill -0 $SGPID 2>/dev/null; do
    h=$(rss_mb "$HUBPID"); n=$(rss_mb "$NODEPID"); k=$(net_mem_kb)
    [ "$(echo "$h > $peak_h" | bc -l)" = 1 ] && peak_h=$h
    [ "$(echo "$n > $peak_n" | bc -l)" = 1 ] && peak_n=$n
    [ -n "$k" ] && [ "$k" -gt "$peak_k" ] && peak_k=$k
    # Only while the visitors are actually held: tools/slow-readers.py drops closing.txt before it
    # tears them down, and a probe inside that herd measures the teardown. RSS sampling continues,
    # because the peak there is real.
    if [ ! -f "$W/quiet.txt" ]; then
      # Fired and forgotten, one a second. A serial prober makes its own gaps: while one probe is
      # slow no new connection arrives, so the hub's accept loop looks stalled for exactly as long as
      # the probe took, which reads as a cause and is an effect.
      # curl's exit status, not just its timing. Once the node is at its bound (ARCHITECTURE.md
      # 9.3) the hub refuses this probe too, and a refused connection comes back in about no time
      # at all -- so without this the line filled with "0" and read as the fastest service anyone
      # had ever measured. A visitor that was turned away is an "x" and is counted separately.
      ( t=$(curl -sk -o /dev/null -w '%{time_total}' --max-time 30 \
              --resolve "demo.hub.test:$PORT:127.0.0.1" "https://demo.hub.test:$PORT/" 2>/dev/null); rc=$?
        if [ "$rc" = 0 ]; then
          echo "$t" | awk '{printf "%.0f\n", $1 * 1000}' >> "$W/probes.txt"
        else
          echo x >> "$W/probes.txt"
        fi ) &
    fi
    sleep 1
  done
  wait $SGPID 2>/dev/null || true
  ok=$(cut -d' ' -f1 "$W/slow.txt" 2>/dev/null || echo 0)
  printf '  %s/%s held in %ss\n' "$ok" "$SLOW" "$(cut -d' ' -f2 "$W/slow.txt" 2>/dev/null || echo '?')"
  # The hub is reported and not gated on RSS here, the mirror of the node and for the opposite
  # reason: its growth is receive queues that the collector expands and reclaims on its own
  # schedule, and its peak swung 61 to 125 MB on one configuration. Gating that produces red runs
  # with no code change behind them. The hub's assertion on this axis is the receive queue's
  # high-water mark below, which is exact and reproduces at the budget every time.
  printf '  %-10s %6.1f  (peak, reported; the queue below is the hub'"'"'s gate)\n' jailhub "$peak_h"
  # Gated on B_NODE_SLOW_MB, not B_NODE_LOAD_MB: the node legitimately carries more here, for a
  # reason that is not the receive budget. The constant's comment has the numbers and the why -- and
  # why the gate is only applied at the count it was measured at. The hub's assertion below is not
  # conditional: the receive queue's high-water is the budget whatever the visitor count is.
  printf '  %-10s %6.1f  (peak)\n' jailscale "$peak_n"
  if [ "$SLOW" = "$B_NODE_SLOW_AT" ]; then
    gate "node RSS with stalled readers" "$peak_n" "$B_NODE_SLOW_MB"
  else
    printf '             not gated: the node budget is measured at SLOW=%s, this run is %s\n' "$B_NODE_SLOW_AT" "$SLOW"
  fi
  # grep -c prints its 0 and then exits 1, so a `|| echo 0` here appends a second zero and the
  # line reads "0\n0". The count is whatever it printed; only a missing file needs a default.
  served=$(grep -cv x "$W/probes.txt" 2>/dev/null) || true
  turned=$(grep -c x "$W/probes.txt" 2>/dev/null) || true
  printf '  ordinary visitor while held (ms, x = turned away): %s\n' "$(tr '\n' ' ' < "$W/probes.txt" 2>/dev/null)"
  printf '             %s served, %s turned away\n' "${served:-0}" "${turned:-0}"
  # The node's side of the multiplexer, which the hub's line below cannot see: the bulk travels
  # node to hub, so the writer that blocks under saturation is this one ("count mean/max" ms).
  "$NODE" status --home "$W/a" 2>/dev/null | sed -n 's/.*"muxQueueWaitMs":"\([^"]*\)".*"muxSocketWriteMs":"\([^"]*\)".*/  node mux, count mean\/worst ms: queue_wait=\1 socket_write=\2/p'
  # The node's own bound (ARCHITECTURE.md 9.3) next to the count it refused. Without this a phase
  # that asks for more visitors than the node will hold reads as a node that quietly lost them.
  "$NODE" status --home "$W/a" 2>/dev/null \
    | sed -n 's/.*"visitorCeiling":\([0-9]*\).*"visitorsRefused":\([0-9]*\).*/  node visitor ceiling \1, refused \2/p'
  denied1=$(net_denied)
  if [ "$denied0" = n/a ]; then refused=n/a; else refused=$((${denied1:-0} - ${denied0:-0})); fi
  printf '  kernel socket memory %.0f MB before, %.0f MB peak; allocations refused during the phase: %s\n' \
    "$(echo "${net0:-0} / 1024" | bc -l)" "$(echo "$peak_k / 1024" | bc -l)" "$refused"
  # Surviving is the point, so a process that died is caught here and not inferred from RSS.
  oom_check
  kill -0 $HUBPID 2>/dev/null || { echo "  !! jailhub died under stalled readers"; fail=1; }
  kill -0 $NODEPID 2>/dev/null || { echo "  !! jailscale died under stalled readers"; fail=1; }
  # The gate with teeth on this axis, and the only deterministic number here: peak RSS on a Serial
  # GC that never returns the heap is a GC-timing artefact that varies 2x run to run, but the receive
  # queue's high-water mark is exact and reproduced at exactly the budget across every run of this
  # phase. Over the budget means the bound leaked; zero reclaims with the peak AT the budget means
  # something other than the bound flattened it, which is the falsification FlowBudget asks for.
  # Over the admin socket, which is where these numbers live now that the hub has no metrics
  # listener: `jailhub status` prints the JSON object the socket answered with, one line.
  set -- $("$HUB" status --state "$W/hub" 2>/dev/null \
      | tr ',{}' '\n\n\n' \
      | awk -F: '/"reclaimed"/{r=$2} /"peak"/{p=$2} /"limit"/{b=$2} /"online"/{n=$2} \
             END{gsub(/[^0-9]/,"",r); gsub(/[^0-9]/,"",p); gsub(/[^0-9]/,"",b); gsub(/[^0-9]/,"",n); \
                 print r+0, p+0, b+0, n+0}')
  rec=${1:-0}; qpeak=${2:-0}; qbud=${3:-0}; nodes=${4:-1}
  # The budget is charged before the queue takes the payload, so each session reader can be holding
  # one 16 KB frame that is counted and not yet queued: the invariant is the budget plus a frame per
  # reader, not the budget exactly. Asserting it exactly failed by 16,367 bytes -- one frame less
  # seventeen -- which is the slack doing exactly what it is documented to do.
  #
  # Derived from the node count rather than hardcoded, because a fixed number would silently be a
  # fact about this harness: it starts two node daemons today, and the first person to add a third
  # gets the same false failure and re-debugs it. A node may hold up to four connections (5.3) and
  # each one has a reader, so the bound is nodes x 4 frames. That is 128 KB here against a 24 MB
  # budget -- noise even at a hundred nodes, which is why this is a gate concern and not a
  # correctness one.
  qslack=$((nodes * 4 * 16 * 1024))
  # The stage and mux breakdowns that used to print here came off the hub's metrics endpoint and
  # went with it. The node still keeps its own mux timings, in `jailscale status`.
  printf '  receive queue peak %.1f MB of %.1f MB (+%d KB slack, %s nodes), %s streams reclaimed\n' \
    "$(echo "$qpeak / 1048576" | bc -l)" "$(echo "$qbud / 1048576" | bc -l)" "$((qslack / 1024))" "$nodes" "$rec"
  if [ "$qbud" -gt 0 ] && [ "$qpeak" -gt $((qbud + qslack)) ]; then
    echo "  !! the receive queue passed its budget: $qpeak > $qbud + $qslack bytes"; fail=1
  fi
  if [ "$CHECK" = 1 ] && [ "$qbud" -gt 0 ] && [ "$qpeak" -ge "$qbud" ] && [ "$rec" -eq 0 ]; then
    echo "  !! queue reached the budget with nothing reclaimed; the bound is not what held it"; fail=1
  fi
  [ "${fail:-0}" = 1 ] && keep_logs
fi

if [ -n "${RATE:-}" ]; then
  # Reported, never gated. There is no budget for a rate yet, and the useful number is not the rate
  # anyway: it is the server CPU each operation costs, which is what a compiler or GC change moves
  # and what survives both the hub's signing limit and a slow client. Handshakes are offered at a
  # fixed rate under NodeGroup.SIGN_PER_SECOND on purpose (tools/throughput.py says why).
  echo "throughput, ${RATE}s per phase (reported, not gated)"
  # RATE_PHASES picks which of them to run, so one kind of work can be measured on its own.
  for phase in ${RATE_PHASES:-handshake warm}; do
    case "$phase" in
      handshake) n=${RATE_HANDSHAKES:-400} ;;
      warm) n=${RATE_CONNS:-32} ;;
      *) echo "  unknown phase $phase"; continue ;;
    esac
    h0=$(cpu_s "$HUBPID"); n0=$(cpu_s "$NODEPID")
    rm -f "$W/throughput.txt"
    # Reported, not gated, so a driver that trips over a runner's limits says so and the gate
    # carries on rather than failing on a number nothing depends on.
    python3 "$R/tools/throughput.py" "$PORT" "$CERT" "$RATE" "$W" "$phase" "$n" \
      || echo "  $phase: driver failed, no number"
    h1=$(cpu_s "$HUBPID"); n1=$(cpu_s "$NODEPID")
    done_n=$(cut -d' ' -f2 "$W/throughput.txt" 2>/dev/null || echo 0)
    if [ "$done_n" -gt 0 ]; then
      printf '             server CPU per op: jailhub %.0f us, jailscale %.0f us\n' \
        "$(echo "($h1 - $h0) * 1000000 / $done_n" | bc -l)" \
        "$(echo "($n1 - $n0) * 1000000 / $done_n" | bc -l)"
    fi
  done
fi

echo "CLI cold start, jailscale status, 10 runs (ms)"
python3 - "$NODE" "$W/a" "$W/cli.txt" <<'PY'
import subprocess, sys, time
node, home, out = sys.argv[1], sys.argv[2], sys.argv[3]
ts = []
for _ in range(10):
    t = time.perf_counter()
    subprocess.run([node, 'status', '--home', home], stdout=subprocess.DEVNULL)
    ts.append((time.perf_counter() - t) * 1000)
ts.sort()
print(f"  median {ts[5]:.1f}   min {ts[0]:.1f}")
open(out, 'w').write(f"{ts[5]:.1f}")
PY
gate "CLI cold start (median ms)" "$(cat "$W/cli.txt")" "$B_CLI_MS"

[ "$fail" = 0 ] || { echo "budget gate FAILED"; exit 1; }
[ "$CHECK" = 1 ] && echo "budget gate OK"
exit 0
