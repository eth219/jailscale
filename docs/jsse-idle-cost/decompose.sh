#!/bin/sh
# Where the node's idle memory goes, and how much of it is memory at all.
#
# ARCHITECTURE.md §12 reports one delta -- "the node daemon alone is about 16.7 MB and reaches about
# 24.3 MB the moment it connects, so roughly 7.6 MB is JSSE initialisation for one TLS client" -- and
# §15 carries it as the reason idle RSS is 25 MB against the 20 MB aimed at. That delta is measured
# between two processes in two configurations and attributed entirely to JSSE. This takes it apart:
# one daemon, held in each of eight states, measured three ways.
#
#   RSS          what `ps` reports, which is what measure.sh gates on and README publishes
#   written      vmmap's writable-regions figure: the pages this process owns and has dirtied
#   code         resident pages of the binary's own __TEXT: clean, file-backed, evictable
#
# The states, and what separates each from the one before it:
#
#   A     fresh home, never joined         no SSLContext is ever built
#   Bpin  joined (--ca-file), hub down     SSLContext with a pinned CA; connect refused, no handshake
#   Bsys  same with caFile removed         SSLContext with no trust managers, so JSSE's default one
#                                          (the platform root store) is built lazily and, with no
#                                          handshake, never demanded
#   Dpin  pinned WRONG CA, hub up          handshake attempted and rejected
#   Dsys  caFile removed, hub up           rejected too -- but the platform store is loaded to reject
#   C     restarted daemon, connected      handshake, Noise, mux, registration
#   E     C plus one link open             what a long-running node idles at
#   J     joined and opened in one life     what measure.sh measures: the daemon that did the join
#
# Three differences are the point.
#
#   C - Bpin separates standing JSSE up from using it.
#
#   (Dsys - Bsys) - (Dpin - Bpin) is the platform root store and nothing else: both sides attempt a
#   handshake and both are rejected, so what is left between them is the trust anchors. It cannot be
#   measured by a successful handshake here, because nothing local has a publicly trusted
#   certificate -- but a failing PKIX path build loads the anchors before it rejects the chain,
#   which is all this needs. It matters because measure.sh always joins with --ca-file and a node
#   pointed at a public-CA hub does not, so the gate measures a configuration nobody ships.
#
#   J - E is the join itself: /v1/key, the join request, the first certificate. measure.sh samples
#   idle in the same daemon that just performed it, so the published figure carries one-time work
#   that a node which restarts never pays again.
#
# EVERY STATE ASSERTS THAT IT IS THE STATE IT CLAIMS TO BE, and that is not defensive dressing: the
# first version of this script swallowed a failed `open` behind `|| true` and reported E as 0.1 MB
# above C, a plausible number for a measurement that never happened. A second version sampled Dsys
# while the daemon was still in its reconnect backoff and had not yet reached PKIX, which read as a
# 3 MB spread in the trust-store figure. Both looked like results.
#
# Usage: ./native.sh -DskipTests && docs/jsse-idle-cost/decompose.sh
#   PORT=19643   the hub's port; the local app and the metrics listener follow it
#   RUNS=3       repeats per state. The spread is under 0.2 MB, so three is enough to show that.
#   SETTLE=8     seconds to let each state settle after it has been confirmed, before sampling
#
# macOS only, because the split rests on vmmap. On Linux /proc/PID/smaps_rollup carries the same two
# numbers (Rss and RssAnon) and README already prints the anonymous share beside RSS.
set -eu
R=$(cd "$(dirname "$0")/../.." && pwd)
HUB=$R/hub/target/jailhub
NODE=$R/node/target/jailscale
CERT=$R/hub/src/test/resources/tls/hub-test.crt
KEY=$R/hub/src/test/resources/tls/hub-test.key
PORT=${PORT:-19643}; APP_PORT=$((PORT + 138)); METRICS_PORT=$((PORT + 139))
RUNS=${RUNS:-3}; SETTLE=${SETTLE:-8}
W=/tmp/jsse-decompose.$$
[ -x "$HUB" ] && [ -x "$NODE" ] || { echo "build first: ./native.sh -DskipTests" >&2; exit 1; }
command -v vmmap > /dev/null || { echo "needs vmmap (macOS)" >&2; exit 1; }
mkdir -p "$W/hub"

cleanup() {
  # Matched on the work directory rather than on the binary name beside it, for the reason
  # measure.sh's cleanup() gives: runtime options go between the two.
  pkill -f "daemon --home $W" 2>/dev/null || true
  for p in ${HUBPID:-} ${APPPID:-}; do kill "$p" 2>/dev/null || true; done
  sleep 0.3
  rm -rf "$W"
}
trap cleanup EXIT
naps() { perl -e "select(undef,undef,undef,$1)"; }
die() { echo "  !! $*" >&2; exit 1; }

start_hub() {
  "$HUB" serve --base-url "https://hub.test:$PORT" --listen "127.0.0.1:$PORT" --tls-cert "$CERT" --tls-key "$KEY" \
    --state "$W/hub" --port-range none --http-listen none --metrics-listen "127.0.0.1:$METRICS_PORT" >> "$W/hub.log" 2>&1 &
  HUBPID=$!
}
stop_hub() { [ -n "${HUBPID:-}" ] && kill "$HUBPID" 2>/dev/null; HUBPID=; naps 1; }

# await <file> <pattern> <seconds> -- the state is not the state until its evidence is in the log
await() {
  i=0
  while [ "$i" -lt "$(echo "$3 * 10" | bc)" ]; do
    grep -q "$2" "$1" 2>/dev/null && return 0
    i=$((i + 1)); naps 0.1
  done
  echo "  --- $1 ---" >&2; tail -5 "$1" >&2
  die "waited ${3}s for '$2' in $(basename "$1") and it never came"
}

sample() { # sample <label> <pid>
  rss=$(ps -o rss= -p "$2" | tr -d ' ') || die "$1: the daemon is gone"
  [ -n "$rss" ] || die "$1: the daemon is gone"
  vmmap "$2" > "$W/$1.vmmap" 2>&1 || true
  wr=$(awk -F'written=' '/^Writable regions:/{split($2,a,"K"); print a[1]; exit}' "$W/$1.vmmap")
  tx=$(awk '/^__TEXT .*target\/jailscale$/{print $5; exit}' "$W/$1.vmmap" | tr -d 'K')
  [ -n "${wr:-}" ] && [ -n "${tx:-}" ] || die "$1: vmmap gave no figures"
  printf '%s\t%s\t%s\t%s\n' "$1" "$rss" "$wr" "$tx" >> "$W/t.tsv"
}

# measure <label> <home> <pattern|-> -- daemon in the foreground, so this owns the pid
measure() {
  rm -f "$W/$1.out"
  "$NODE" daemon --home "$2" > "$W/$1.out" 2>&1 & p=$!
  [ "$3" = "-" ] || await "$W/$1.out" "$3" 20
  naps "$SETTLE"
  sample "$1" "$p"
  kill -TERM "$p" 2>/dev/null || true
  naps 1
}

# A certificate the hub does not present, so the pinned side of the trust-store comparison fails its
# handshake exactly where the platform-store side fails its own.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout "$W/wrong.key" -out "$W/wrong.crt" \
  -days 2 -nodes -subj "/CN=not-the-hub" > /dev/null 2>&1 || die "openssl could not make the wrong certificate"

python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s): s.send_response(200); s.send_header('Content-Length','6'); s.end_headers(); s.wfile.write(b'hello\n')
    def log_message(s,*a): pass
socketserver.TCPServer(('127.0.0.1',$APP_PORT), H).serve_forever()" & APPPID=$!

start_hub; naps 1.5
INV=$(grep -o "https://hub.test:$PORT/join/[A-Za-z0-9_-]*" "$W/hub.log" | head -1)
[ -n "$INV" ] || { tail -5 "$W/hub.log" >&2; die "no invite in hub.log"; }
"$NODE" up --invite "$INV" --hub-addr 127.0.0.1 --user alice --ca-file "$CERT" --home "$W/a" > /dev/null
"$NODE" down --home "$W/a" > /dev/null 2>&1 || true
naps 0.5; pkill -f "daemon --home $W" 2>/dev/null || true; naps 0.5

# The two variants are copies of the joined state with one field changed, so nothing but the trust
# configuration differs: same machine key, same pinned hub key, same hub.
for d in pin sys; do cp -R "$W/a" "$W/$d"; rm -f "$W/$d/daemon.lock" "$W/$d/daemon.log"; done
sed -e "s#\"caFile\":\"[^\"]*\"#\"caFile\":\"$W/wrong.crt\"#" "$W/a/node.json" > "$W/pin/node.json"
sed -e 's/"caFile":"[^"]*",//' "$W/a/node.json" > "$W/sys/node.json"
grep -q caFile "$W/sys/node.json" && die "caFile survived the edit; the sys states would be pinned"
grep -q "$W/wrong.crt" "$W/pin/node.json" || die "the wrong certificate did not go into the pinned state"

n=0
while [ $n -lt "$RUNS" ]; do
  n=$((n + 1)); echo "run $n/$RUNS"

  measure C    "$W/a"   "connected to hub"
  measure Dpin "$W/pin" "certificate_unknown"
  measure Dsys "$W/sys" "certificate_unknown"

  # E: the restarted daemon, with a link. Asserted through `ls`, not through open's exit code.
  rm -f "$W/E.out"
  "$NODE" daemon --home "$W/a" > "$W/E.out" 2>&1 & e=$!
  await "$W/E.out" "connected to hub" 20
  "$NODE" open "$APP_PORT" --name demo --home "$W/a" > /dev/null 2>&1 || true
  "$NODE" ls --home "$W/a" 2>/dev/null | grep -q "demo.*open" || die "E: the link did not open"
  naps "$SETTLE"; sample E "$e"
  # The invite for J comes out of this daemon while it is still up -- `invite` talks to a running
  # one -- and after E is sampled, so that issuing it cannot move E's own figures.
  INVJ=$("$NODE" invite --user "j$n" --home "$W/a" 2>/dev/null | grep -o "https://hub.test:$PORT/join/[A-Za-z0-9_-]*" | head -1)
  "$NODE" close demo --home "$W/a" > /dev/null 2>&1 || true
  kill -TERM "$e" 2>/dev/null || true; naps 1

  # J: a node that joins and opens within one daemon's life -- measure.sh's shape. A new home and a
  # new invite each run, because a join is not repeatable.
  [ -n "$INVJ" ] || die "J: no invite"
  "$NODE" up --invite "$INVJ" --hub-addr 127.0.0.1 --user "j$n" --ca-file "$CERT" --home "$W/j$n" > /dev/null
  "$NODE" open "$APP_PORT" --name "demo$n" --home "$W/j$n" > /dev/null 2>&1 || true
  "$NODE" ls --home "$W/j$n" 2>/dev/null | grep -q "demo$n.*open" || die "J: the link did not open"
  j=$(pgrep -f "daemon --home $W/j$n" | head -1)
  [ -n "$j" ] || die "J: no daemon"
  naps "$SETTLE"; sample J "$j"; kill -TERM "$j" 2>/dev/null || true; naps 1

  stop_hub
  measure Bpin "$W/pin"   "Connection refused"
  measure Bsys "$W/sys"   "Connection refused"
  measure A    "$W/fresh" -
  grep -q "\[link\]" "$W/A.out" && die "A: the fresh daemon tried to connect, so it is not state A"
  start_hub; naps 2
done

echo
grep -m1 "certificate_unknown" "$W/Dpin.out" 2>/dev/null | sed 's/^/  Dpin: /' || true
grep -m1 "certificate_unknown" "$W/Dsys.out" 2>/dev/null | sed 's/^/  Dsys: /' || true
echo
printf 'state  RSS MB (min-max)      written KB   code KB\n'
for s in A Bpin Bsys Dpin Dsys C E J; do
  awk -F'\t' -v s="$s" '$1==s { n++; r=$2/1024; sr+=r; sw+=$3; st+=$4; if(r>mx||n==1)mx=r; if(r<mn||n==1)mn=r }
    END { if (n) printf "%-6s %5.1f (%.1f-%.1f)%9s%.0f%9s%.0f\n", s, sr/n, mn, mx, "", sw/n, "", st/n }' "$W/t.tsv"
done
echo
awk -F'\t' '{ n[$1]++; r[$1]+=$2/1024; w[$1]+=$3; t[$1]+=$4 }
  END { for (s in n) { r[s]/=n[s]; w[s]/=n[s]; t[s]/=n[s] }
    printf "  A    -> Bpin  stand JSSE up, no bytes moved   RSS %+.1f MB  written %+.0f KB  code %+.0f KB\n", r["Bpin"]-r["A"], w["Bpin"]-w["A"], t["Bpin"]-t["A"]
    printf "  Bpin -> C     handshake, Noise, mux, register RSS %+.1f MB  written %+.0f KB  code %+.0f KB\n", r["C"]-r["Bpin"], w["C"]-w["Bpin"], t["C"]-t["Bpin"]
    printf "  C    -> E     open one link                   RSS %+.1f MB  written %+.0f KB  code %+.0f KB\n", r["E"]-r["C"], w["E"]-w["C"], t["E"]-t["C"]
    printf "  E    -> J     having joined in this process   RSS %+.1f MB  written %+.0f KB  code %+.0f KB\n", r["J"]-r["E"], w["J"]-w["E"], t["J"]-t["E"]
    printf "  A    -> J     the whole of what §12 splits    RSS %+.1f MB  written %+.0f KB  code %+.0f KB\n", r["J"]-r["A"], w["J"]-w["A"], t["J"]-t["A"]
    printf "\n  the platform root store, alone              RSS %+.1f MB  written %+.0f KB  code %+.0f KB\n", \
      (r["Dsys"]-r["Bsys"])-(r["Dpin"]-r["Bpin"]), (w["Dsys"]-w["Bsys"])-(w["Dpin"]-w["Bpin"]), (t["Dsys"]-t["Bsys"])-(t["Dpin"]-t["Bpin"]) }' "$W/t.tsv"
