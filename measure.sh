#!/bin/sh
# Lightweight-budget measurement (DESIGN.md §4): runs the native hub and two node daemons on
# loopback, joins them through the real CLI, and reports binary size, idle RSS and CLI cold start.
# Usage: ./native.sh -DskipTests && ./measure.sh
set -eu
R=$(cd "$(dirname "$0")" && pwd)
HUB=$R/jailscale-hub/target/jailhub
NODE=$R/jailscale-node/target/jailscale
CERT=$R/jailscale-hub/src/test/resources/tls/hub-test.crt
KEY=$R/jailscale-hub/src/test/resources/tls/hub-test.key
W=/tmp/jsm$$
PORT=${PORT:-18443}
mkdir -p "$W/hub"
cleanup() {
  pkill -f "jailscale daemon --home $W" 2>/dev/null || true
  [ -n "${HUBPID:-}" ] && kill "$HUBPID" 2>/dev/null || true
  sleep 0.3
  rm -rf "$W"
}
trap cleanup EXIT

"$HUB" serve --base-url "https://localhost:$PORT" --listen "127.0.0.1:$PORT" --tls-cert "$CERT" --tls-key "$KEY" \
  --state "$W/hub" > "$W/hub.log" 2>&1 &
HUBPID=$!
sleep 1.5
INV=$(grep -o "https://localhost:$PORT/join/[A-Za-z0-9_-]*" "$W/hub.log" | head -1)
"$NODE" up --invite "$INV" --user alice --ca-file "$CERT" --home "$W/a" > /dev/null
INV2=$("$NODE" invite --user bob --home "$W/a" | grep -o "https://localhost:$PORT/join/[A-Za-z0-9_-]*" | head -1)
"$NODE" up --invite "$INV2" --ca-file "$CERT" --home "$W/b" > /dev/null
"$NODE" netcheck --home "$W/b" > /dev/null
sleep "${IDLE:-10}"

echo "binary size (MiB)"
for b in "$HUB" "$NODE"; do printf '  %-10s %6.1f\n' "$(basename "$b")" "$(echo "$(stat -f%z "$b" 2>/dev/null || stat -c%s "$b") / 1048576" | bc -l)"; done
echo "idle RSS after ${IDLE:-10}s (MB)"
ps -o rss= -o command= -p "$HUBPID" $(pgrep -f "jailscale daemon --home $W" | tr '\n' ' ') | while read -r rss cmd; do
  name=$(basename "$(echo "$cmd" | cut -d' ' -f1)")
  printf '  %-10s %6.1f\n' "$name" "$(echo "$rss / 1024" | bc -l)"
done
echo "CLI cold start, jailscale status, 10 runs (ms)"
python3 - "$NODE" "$W/a" <<'PY'
import subprocess, sys, time
node, home = sys.argv[1], sys.argv[2]
ts = []
for _ in range(10):
    t = time.perf_counter()
    subprocess.run([node, 'status', '--home', home], stdout=subprocess.DEVNULL)
    ts.append((time.perf_counter() - t) * 1000)
ts.sort()
print(f"  median {ts[5]:.1f}   min {ts[0]:.1f}")
PY
