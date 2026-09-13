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
#                -XX:MaxHeapSize= to lift the build's ceiling, -XX:ProfilesDumpFile= to profile
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
# idle 24.8 to 35.1 MB, peak with 1,000 held 53.5 to 70.0 MB, CLI 2.4 to 6.3 ms. A profile-guided
# build (-Ppgo) is smaller again and passes all of these with room to spare; the budgets describe
# what ships, not the best build available.
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
# to make. Measured 96.7 to 98.9 at about 1,000 visitors, by two people on one machine; 108 is ~10%
# over the highest number anyone has seen. Tight enough to mean something: the failure this phase
# exists to catch drove the node past 200, so a real regression blows through 108 rather than
# creeping to 101.
#
# RSS is the right metric here and the wrong one for the hub, which is worth knowing rather than
# looking inconsistent. The hub's growth is receive queues that the collector expands and reclaims on
# its own schedule, so its peak swung 61 to 125 MB on one configuration; the node's is per-visitor TLS
# state that scales with the visitor count, and it repeated to 0.1 MB across runs. So the hub is gated
# on jailhub_receive_queued_peak_bytes, which is exact, and the node on RSS, which for the node is
# reproducible. Replace this with a direct count of concurrent visitor TLS endpoints when the node
# exposes one; RSS is standing in for that number.
#
# Derived on darwin-arm64. NOT confirmed on linux-amd64, where RSS accounting differs enough to
# matter (see the note below the platform block: most of a Linux idle RSS is binary pages). Someone
# should measure it there before the gate runs on it.
B_NODE_SLOW_MB=108
B_CLI_MS=50
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    # These are the release toolchain's, which they once were not: the binary budget was 30 while
    # the release shipped 30.1 MiB darwin-arm64 binaries, and the idle budget was 28 while that
    # binary idled at 29.0. Both had been set against whichever GraalVM this machine happened to
    # have, and the gate only runs on linux, so neither could ever fail.
    B_BINARY_MIB=28; B_NODE_IDLE_MB=28; B_HUB_IDLE_MB=28 ;;
  Linux-x86_64)
    B_BINARY_MIB=28; B_NODE_IDLE_MB=38; B_HUB_IDLE_MB=38 ;;
  *)
    # An unmeasured platform gets the loosest of the measured ones rather than a guess of its own.
    echo "note: no budget measured for $(uname -s)-$(uname -m); using the widest known"
    B_BINARY_MIB=28; B_NODE_IDLE_MB=38; B_HUB_IDLE_MB=38 ;;
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

# HUB_OPTS is the hub's half of JAILSCALE_DAEMON_OPTS (which the CLI gives the node's daemon):
# runtime options the native image reads before main, deliberately unquoted so several split.
# shellcheck disable=SC2086
"$HUB" ${HUB_OPTS:-} serve --base-url "https://hub.test:$PORT" --listen "127.0.0.1:$PORT" --tls-cert "$CERT" --tls-key "$KEY" \
  --state "$W/hub" --port-range none --http-listen none > "$W/hub.log" 2>&1 &
HUBPID=$!
sleep 1.5
INV=$(grep -o "https://hub.test:$PORT/join/[A-Za-z0-9_-]*" "$W/hub.log" | head -1)
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
import sys

KEEP = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\nhello\n"
CLOSE = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello\n"
# /big is for tools/slow-readers.py: far more than one stream's 256 KB window, so a visitor that
# stops reading leaves bytes with nowhere to go but the hub's receive queue.
BIG = 8 * 1024 * 1024
CHUNK = b"x" * 65536

async def serve(reader, writer):
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
  echo "saturation: $SLOW visitors asking for 8 MB and not reading it, peak RSS while they are up"
  python3 "$R/tools/slow-readers.py" "$PORT" "$CERT" "$SLOW" "$W" > "$W/slow.log" 2>&1 &
  SGPID=$!
  # An ordinary visitor is probed repeatedly while the stalled ones are held, not once: a single
  # sample cannot tell a reclaim stall from a GC pause from the ramp still running, and the spread
  # is the thing worth knowing -- a hub that serves at 300 ms with one 5 s outlier is a different
  # product from one that serves at 300 ms flat.
  peak_h=0; peak_n=0; probes=""
  while kill -0 $SGPID 2>/dev/null; do
    h=$(rss_mb "$HUBPID"); n=$(rss_mb "$NODEPID")
    [ "$(echo "$h > $peak_h" | bc -l)" = 1 ] && peak_h=$h
    [ "$(echo "$n > $peak_n" | bc -l)" = 1 ] && peak_n=$n
    # Only while the visitors are actually held: tools/slow-readers.py drops closing.txt before it
    # tears them down, and a probe inside that herd measures the teardown. RSS sampling continues,
    # because the peak there is real.
    if [ ! -f "$W/quiet.txt" ]; then
      # Fired and forgotten, one a second. A serial prober makes its own gaps: while one probe is
      # slow no new connection arrives, so the hub's accept loop looks stalled for exactly as long as
      # the probe took, which reads as a cause and is an effect.
      ( curl -sk -o /dev/null -w '%{time_total}\n' --max-time 30 \
          --resolve "demo.hub.test:$PORT:127.0.0.1" "https://demo.hub.test:$PORT/" 2>/dev/null \
          | awk '{printf "%.0f\n", $1 * 1000}' >> "$W/probes.txt" ) &
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
  # reason that is not the receive budget. The constant's comment has the numbers and the why.
  printf '  %-10s %6.1f  (peak)\n' jailscale "$peak_n"; gate "node RSS with stalled readers" "$peak_n" "$B_NODE_SLOW_MB"
  printf '  ordinary visitor while held (ms): %s\n' "$(tr '\n' ' ' < "$W/probes.txt" 2>/dev/null)"
  # Surviving is the point, so a process that died is caught here and not inferred from RSS.
  oom_check
  kill -0 $HUBPID 2>/dev/null || { echo "  !! jailhub died under stalled readers"; fail=1; }
  kill -0 $NODEPID 2>/dev/null || { echo "  !! jailscale died under stalled readers"; fail=1; }
  # The gate with teeth on this axis, and the only deterministic number here: peak RSS on a Serial
  # GC that never returns the heap is a GC-timing artefact that varies 2x run to run, but the receive
  # queue's high-water mark is exact and reproduced at exactly the budget across every run of this
  # phase. Over the budget means the bound leaked; zero reclaims with the peak AT the budget means
  # something other than the bound flattened it, which is the falsification FlowBudget asks for.
  set -- $(curl -sk --resolve "hub.test:$PORT:127.0.0.1" "https://hub.test:$PORT/metrics" 2>/dev/null \
      | awk '/^jailhub_streams_reclaimed_total /{r=$2} /^jailhub_receive_queued_peak_bytes /{p=$2} \
             /^jailhub_receive_budget_bytes /{b=$2} /^jailhub_nodes_online /{n=$2} \
             END{print r+0, p+0, b+0, n+0}')
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
  # The stage breakdown (ARCHITECTURE.md 6.3). first_byte running ahead of the sum of the others is
  # time in no stage at all, which is the finding that took eight rebuilds to reach by hand.
  curl -sk --resolve "hub.test:$PORT:127.0.0.1" "https://hub.test:$PORT/metrics" 2>/dev/null \
    | awk '/^jailhub_visitor_admissions_total /{n=$2}
           /^jailhub_visitor_[a-z_]+_seconds_total /{split($1,a,"_"); k=$1; sub("jailhub_visitor_","",k); sub("_seconds_total","",k); sum[k]=$2}
           /^jailhub_visitor_[a-z_]+_seconds_max /{k=$1; sub("jailhub_visitor_","",k); sub("_seconds_max","",k); mx[k]=$2}
           END{if (n>0) {
                 parts=sum["peek"]+sum["resolve"]+sum["open"]+sum["reply"];
                 printf "  admissions %d, mean/worst ms:", n;
                 split("peek resolve open reply first_byte", o, " ");
                 for (i=1;i<=5;i++) printf " %s=%.0f/%.0f", o[i], sum[o[i]]/n*1000, mx[o[i]]*1000;
                 printf " unaccounted=%.0f\n", (sum["first_byte"]-parts)/n*1000 }}'
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
  # RATE_PHASES picks which of them to run, which is how a PGO profile can be collected from one
  # kind of work and the result measured on the other.
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
