#!/bin/sh
# Lightweight-budget measurement and gate (ARCHITECTURE.md §14): runs the native hub and two node
# daemons on loopback, joins them through the real CLI, opens a link, optionally throws LOAD
# concurrent visitors at it, and reports binary size, RSS and CLI cold start.
#
# Usage: ./native.sh -DskipTests && ./measure.sh [--check]
#   IDLE=10      seconds to idle before the idle measurement
#   LOAD=1000    also run LOAD concurrent https visitors through the link (needs curl >= 7.66)
#   --check      exit 1 when a number exceeds the budget below (the CI gate)
set -eu
R=$(cd "$(dirname "$0")" && pwd)
HUB=$R/hub/target/jailhub
NODE=$R/node/target/jailscale
CERT=$R/hub/src/test/resources/tls/hub-test.crt
KEY=$R/hub/src/test/resources/tls/hub-test.key
W=/tmp/jsm$$
PORT=${PORT:-18443}
CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1

# Budget (ARCHITECTURE.md §14). Change only with a reason, in the same commit as the design table.
# Per platform, because the same code measures differently on each and one shared number would have
# to be the loosest: an amd64 binary is about 6.5 MiB bigger than the arm64 one, and Linux counts the
# binary's own mapped pages in RSS where macOS largely does not -- on linux-amd64 about 34 MB of a
# 40 MB idle RSS is the binary itself, clean and reclaimable, against about 6 MB of anonymous memory
# at the moment this script measures. (A hub left running grows that anonymous share -- the live one
# is at 15 MB after a day -- which is why the budget is on RSS and the anonymous figure is only
# printed. ARCHITECTURE.md §14 has both numbers and which is which.)
B_NODE_LOAD_MB=192
B_HUB_LOAD_MB=160
B_CLI_MS=50
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    # 32, not 30: the release does not use this machine's toolchain. `brew`'s GraalVM CE (25.3 line)
    # builds jailhub at 25.2 MiB and jailscale at 25.3 here, while the release workflow's Liberica
    # NIK 25.0.4 builds the same commit at 29.9 and 30.2 -- so v0.1.0 shipped darwin-arm64 binaries
    # of 29.8 and 30.1 MiB, over the 30 the budget used to say, and nothing noticed because the
    # `budget` job only runs on linux-amd64. The number now describes what ships, with about 2 MiB
    # of headroom, and §14 records that the two toolchains differ by 4.7 MiB for reasons not
    # isolated (it is not compressed references, which changed no size on linux).
    B_BINARY_MIB=32; B_NODE_IDLE_MB=28; B_HUB_IDLE_MB=30 ;;
  Linux-x86_64)
    B_BINARY_MIB=36; B_NODE_IDLE_MB=46; B_HUB_IDLE_MB=46 ;;
  *)
    # An unmeasured platform gets the loosest of the measured ones rather than a guess of its own.
    echo "note: no budget measured for $(uname -s)-$(uname -m); using the widest known"
    B_BINARY_MIB=36; B_NODE_IDLE_MB=46; B_HUB_IDLE_MB=46 ;;
esac

mkdir -p "$W/hub" "$W/app"
cleanup() {
  pkill -f "jailscale daemon --home $W" 2>/dev/null || true
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
anon_note() {
  [ -r "/proc/$1/status" ] || return 0
  printf '   (%.1f anonymous)' "$(echo "$(awk '/^RssAnon:/{print $2}' "/proc/$1/status") / 1024" | bc -l)"
}

"$HUB" serve --base-url "https://hub.test:$PORT" --listen "127.0.0.1:$PORT" --tls-cert "$CERT" --tls-key "$KEY" \
  --state "$W/hub" --port-range none --http-listen none > "$W/hub.log" 2>&1 &
HUBPID=$!
sleep 1.5
INV=$(grep -o "https://hub.test:$PORT/join/[A-Za-z0-9_-]*" "$W/hub.log" | head -1)
"$NODE" up --invite "$INV" --hub-addr 127.0.0.1 --user alice --ca-file "$CERT" --home "$W/a" > /dev/null
INV2=$("$NODE" invite --user bob --home "$W/a" | grep -o "https://hub.test:$PORT/join/[A-Za-z0-9_-]*" | head -1)
"$NODE" up --invite "$INV2" --hub-addr 127.0.0.1 --ca-file "$CERT" --home "$W/b" > /dev/null
"$NODE" netcheck --home "$W/b" > /dev/null
# A local app behind alice, published as demo.hub.test (the idle budget is "one link open").
# (python's stock http.server has a listen backlog of 5; give it one that survives a burst)
cat > "$W/app/app.py" <<'EOF'
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Length', '6'); self.end_headers(); self.wfile.write(b'hello\n')
    def log_message(self, *a): pass
ThreadingHTTPServer.request_queue_size = 1024
ThreadingHTTPServer(('127.0.0.1', 18080), H).serve_forever()
EOF
python3 "$W/app/app.py" > /dev/null 2>&1 &
APPPID=$!
"$NODE" open 18080 --name demo --home "$W/a" > /dev/null
sleep "${IDLE:-10}"
NODEPID=$(pgrep -f "jailscale daemon --home $W/a")

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
  for f in "$W/hub.log" "$W/node.log"; do
    [ -f "$f" ] && grep -qi OutOfMemory "$f" && { echo "  !! OutOfMemoryError in $(basename "$f")"; fail=1; }
  done
  [ "$CHECK" = 1 ] && [ "$ok" -lt $((LOAD * 99 / 100)) ] && { echo "  !! only $ok of $LOAD visitors were held"; fail=1; }
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
