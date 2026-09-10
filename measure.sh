#!/bin/sh
# Lightweight-budget measurement and gate (DESIGN.md §4): runs the native hub and two node
# daemons on loopback, joins them through the real CLI, opens a link, optionally throws LOAD
# concurrent visitors at it, and reports binary size, RSS and CLI cold start.
#
# Usage: ./native.sh -DskipTests && ./measure.sh [--check]
#   IDLE=10      seconds to idle before the idle measurement
#   LOAD=1000    also run LOAD concurrent https visitors through the link (needs curl >= 7.66)
#   --check      exit 1 when a number exceeds the budget below (the CI gate)
set -eu
R=$(cd "$(dirname "$0")" && pwd)
HUB=$R/jailscale-hub/target/jailhub
NODE=$R/jailscale-node/target/jailscale
CERT=$R/jailscale-hub/src/test/resources/tls/hub-test.crt
KEY=$R/jailscale-hub/src/test/resources/tls/hub-test.key
W=/tmp/jsm$$
PORT=${PORT:-18443}
CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1

# Budget (DESIGN.md §4). Change only with a reason, in the same commit as the design table.
B_BINARY_MIB=30
B_NODE_IDLE_MB=28
B_HUB_IDLE_MB=30
B_NODE_LOAD_MB=128
B_HUB_LOAD_MB=128
B_CLI_MS=50

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
printf '  %-10s %6.1f\n' jailhub "$(rss_mb "$HUBPID")";  gate "hub idle RSS" "$(rss_mb "$HUBPID")" "$B_HUB_IDLE_MB"
printf '  %-10s %6.1f\n' jailscale "$(rss_mb "$NODEPID")"; gate "node idle RSS" "$(rss_mb "$NODEPID")" "$B_NODE_IDLE_MB"

if [ -n "${LOAD:-}" ]; then
  echo "load: $LOAD concurrent visitors (curl --parallel), then RSS"
  t0=$(date +%s.%N 2>/dev/null || python3 -c 'import time;print(time.time())')
  curl -s -o /dev/null --cacert "$CERT" --resolve "demo.hub.test:$PORT:127.0.0.1" \
    --parallel --parallel-immediate --parallel-max "$LOAD" -w '%{http_code}\n' \
    "https://demo.hub.test:$PORT/?v=[1-$LOAD]" > "$W/codes.txt" || true
  t1=$(date +%s.%N 2>/dev/null || python3 -c 'import time;print(time.time())')
  ok=$(grep -c '^200$' "$W/codes.txt" || true)
  printf '  %s/%s ok in %.1fs' "$ok" "$LOAD" "$(echo "$t1 - $t0" | bc -l)"
  [ "$ok" -lt "$LOAD" ] && printf '  (other codes: %s)' "$(grep -v '^200$' "$W/codes.txt" | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
  echo
  printf '  %-10s %6.1f  (after load)\n' jailhub "$(rss_mb "$HUBPID")";  gate "hub RSS under load" "$(rss_mb "$HUBPID")" "$B_HUB_LOAD_MB"
  printf '  %-10s %6.1f  (after load)\n' jailscale "$(rss_mb "$NODEPID")"; gate "node RSS under load" "$(rss_mb "$NODEPID")" "$B_NODE_LOAD_MB"
  [ "$CHECK" = 1 ] && [ "$ok" -lt $((LOAD * 99 / 100)) ] && { echo "  !! only $ok of $LOAD visitors succeeded"; fail=1; }
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
