#!/bin/sh
# Where the node's idle memory goes, and how much of it is memory at all.
#
# ARCHITECTURE.md §12 reports one delta -- "the node daemon alone is about 16.7 MB and reaches about
# 24.3 MB the moment it connects, so roughly 7.6 MB is JSSE initialisation for one TLS client" -- and
# §15 carries it as the reason idle RSS is 25 MB against the 20 MB aimed at. That delta is measured
# between two processes in two configurations and attributed entirely to JSSE. This takes it apart:
# one daemon, held in each of five states, measured three ways.
#
#   RSS          what `ps` reports, which is what measure.sh gates on and README publishes
#   written      the pages this process owns and has dirtied
#   code         resident pages of the binary's own code: clean, file-backed, evictable. darwin's
#                __TEXT and Linux's executable mappings, which are not the same sections -- see
#                "Two samplers" below, and do not read one platform's absolute figure against the
#                other's
#   anon         Linux only: resident anonymous memory, which is the figure measure.sh prints beside
#                RSS and §14 publishes. Here so that a state of this run can be lined up against it.
#
# The middle two are read from vmmap on darwin and from /proc/PID/smaps* on Linux. They are the same
# two quantities asked of two kernels, not the same number: see "Two samplers" below.
#
# The states, and what separates each from the one before it:
#
#   A     fresh home, never joined         no SSLContext is ever built
#   Bpin  joined (--ca-file), hub down     SSLContext with a pinned CA; connect refused, no handshake
#   C     restarted daemon, connected      handshake, Noise, mux, registration
#   E     C plus one link open             what a long-running node idles at
#   J     joined and opened in one life    what measure.sh measures: the daemon that did the join
#
# Two differences are the point.
#
#   C - Bpin separates standing JSSE up from using it.
#
#   J - E is the join itself: /v1/key, the join request, the first certificate. measure.sh samples
#   idle in the same daemon that just performed it, so the published figure carries one-time work
#   that a node which restarts never pays again.
#
# What this script deliberately does NOT try to answer is what the trust configuration costs. Every
# state here pins the test CA, because a loopback hub has nothing else it can present, and the two
# ways of faking the shipped configuration without a second binary both give wrong answers by a
# factor of three or more. truststore.sh beside this file builds that second binary and says why.
#
# EVERY STATE ASSERTS THAT IT IS THE STATE IT CLAIMS TO BE, and that is not defensive dressing: the
# first version of this script swallowed a failed `open` behind `|| true` and reported E as 0.1 MB
# above C, a plausible number for a measurement that never happened. Another version let its wait
# for "connected" give up quietly, and a daemon that never connected read 4 MB light. Both looked
# like results.
#
# Usage: ./native.sh -DskipTests && docs/jsse-idle-cost/decompose.sh
#   PORT=19643   the hub's port; the local app and the metrics listener follow it
#   RUNS=3       repeats per state. The spread is under 0.2 MB, so three is enough to show that.
#   SETTLE=8     seconds to let each state settle after it has been confirmed, before sampling
#
# Two samplers, darwin and Linux, because neither kernel will answer the other's question.
#
#   written   darwin: vmmap's "Writable regions: ... written=", the dirty pages of writable regions.
#             Linux:  Private_Dirty from smaps_rollup -- pages private to this process that have
#             been written. Both mean "memory this process owns", and neither counts a clean
#             file-backed page the kernel may drop and re-read.
#
#   code      darwin: the resident bytes of the __TEXT segment of the node binary.
#             Linux:  the summed Rss of the binary's own executable (r-xp) mappings, found through
#             /proc/PID/exe rather than by a path this script composed, so a symlinked or relocated
#             binary cannot silently sum nothing.
#
# The absolute figures are not comparable across the two, and the whole point of running it on both
# is the differences between states within one platform -- which is where they agree: README has the
# two runs, and A -> J costs the same written memory on either to within 50 KB.
#
# Not comparable across architectures either, and that is the sharper warning. §14 publishes 34.4 MB
# of node idle RSS for linux-amd64 against 25.0 for darwin, and it is tempting to read a Linux run
# here as taking that apart. It is not: linux-arm64 idles at 24.0 MB, below macOS. The gap is between
# the two Linux targets and not between the kernels, so say which architecture any figure came from.
set -eu
R=$(cd "$(dirname "$0")/../.." && pwd)
HUB=$R/hub/target/jailhub
NODE=$R/node/target/jailscale
CERT=$R/hub/src/test/resources/tls/hub-test.crt
KEY=$R/hub/src/test/resources/tls/hub-test.key
PORT=${PORT:-19643}; APP_PORT=$((PORT + 138)); METRICS_PORT=$((PORT + 139))
RUNS=${RUNS:-3}; SETTLE=${SETTLE:-8}
# State A's whole definition is that no SSLContext is ever built, and the daemon's first update check
# fires 60 to 300 s after start (Daemon.updateLoop), reaching api.github.com over the default trust
# manager. A settle long enough to contain it would make A a measurement of something else.
# Checked against elapsed time at each sample rather than against SETTLE alone: sampling happens at
# await + SETTLE, so a SETTLE inside the limit can still be sampled outside it. Also SETTLE may be
# fractional, which an integer test would reject with a confusing message.
UPDATE_CHECK_FLOOR=55
W=/tmp/jsse-decompose.$$
[ -x "$HUB" ] && [ -x "$NODE" ] || { echo "build first: ./native.sh -DskipTests" >&2; exit 1; }
OS=$(uname -s)
case $OS in
  Darwin) command -v vmmap > /dev/null || { echo "needs vmmap" >&2; exit 1; } ;;
  # smaps_rollup is 4.14 and later. Checked against this shell's own, so a kernel that lacks it
  # says so here rather than after the first state has been stood up and held for SETTLE seconds.
  Linux)  [ -r /proc/self/smaps_rollup ] \
            || { echo "needs /proc/PID/smaps_rollup (Linux 4.14+)" >&2; exit 1; } ;;
  *)      echo "no sampler for $OS: this needs vmmap or /proc/PID/smaps*" >&2; exit 1 ;;
esac
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

# split_darwin <label> <pid> -- sets wr and tx, in KB, from vmmap. There is no `an`: vmmap has no
# column that means the same thing as Linux's anonymous resident, and inventing one from the region
# list would be a number this file could not defend.
split_darwin() {
  vmmap "$2" > "$W/$1.map" 2>&1 || true
  # Unit-aware for the same reason the code column below is: vmmap switches these to M past
  # 10240K, and splitting on "K" would take "written=10.5M(8%) resident=6064" as the figure, pass
  # the -n guard and print 10 KB for 10,752.
  wr=$(awk '/^Writable regions:/ {
        if (match($0, /written=[0-9.]+[KMG]?/)) {
          v = substr($0, RSTART + 8, RLENGTH - 8); u = substr(v, length(v), 1); n = v + 0
          if (u == "M") n *= 1024; else if (u == "G") n *= 1048576
          printf "%d", n; exit } }' "$W/$1.map")
  tx=$(awk '/^__TEXT .*target\/jailscale$/{ v = $5; u = substr(v, length(v), 1); n = v + 0
        if (u == "M") n *= 1024; else if (u == "G") n *= 1048576
        printf "%d", n; exit }' "$W/$1.map")
}

# split_linux <label> <pid> -- sets wr, tx and an, in KB, from /proc/PID/smaps_rollup and smaps.
#
# smaps is copied before it is read rather than piped through awk twice: it is generated on read and
# a daemon that exits between the two passes would give one column of one state and not the other.
split_linux() {
  cat "/proc/$2/smaps_rollup" > "$W/$1.rollup" 2>/dev/null || return 0
  cat "/proc/$2/smaps"        > "$W/$1.map"    2>/dev/null || return 0
  wr=$(awk '/^Private_Dirty:/ { printf "%d", $2; exit }' "$W/$1.rollup")
  # smaps_rollup's Anonymous is /proc/PID/status's RssAnon, which is what measure.sh reports and
  # §14 publishes; read from the rollup so both Linux columns come from one sample of one file.
  an=$(awk '/^Anonymous:/ { printf "%d", $2; exit }' "$W/$1.rollup")
  # The binary is found through /proc/PID/exe and not through $NODE: the two are the same file here,
  # but a path this script composed and a path the kernel reports are not the same claim, and the
  # failure of the second is a zero that looks like a measurement.
  exe=$(readlink "/proc/$2/exe" 2>/dev/null) || return 0
  # Empty would match every anonymous mapping below, which have no path at all.
  [ -n "$exe" ] || return 0
  tx=$(awk -v exe="$exe" '
        # A mapping header is "start-end perms offset dev inode [path]". The path is the whole of
        # the rest of the line and not $NF: it may contain a space, and a binary replaced under the
        # running daemon has " (deleted)" appended here and by readlink both, so $NF would be
        # "(deleted)" against an exe that ends in it. Anonymous mappings stop at the inode, which
        # leaves the path empty and unequal to a non-empty exe.
        /^[0-9a-f]+-[0-9a-f]+ / {
          p = ""
          if (match($0, /^[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[0-9]+ +/)) p = substr($0, RSTART + RLENGTH)
          code = (p == exe && $2 ~ /x/); next }
        code && /^Rss:/ { s += $2 }
        END { printf "%d", s }' "$W/$1.map")
}

sample() { # sample <label> <pid> <epoch the daemon started>
  up=$(( $(date +%s) - $3 ))
  [ "$up" -lt "$UPDATE_CHECK_FLOOR" ] \
    || die "$1 sampled ${up}s after start; the update check can fire from ${UPDATE_CHECK_FLOOR}s (lower SETTLE)"
  rss=$(ps -o rss= -p "$2" | tr -d ' ') || die "$1: the daemon is gone"
  [ -n "$rss" ] || die "$1: the daemon is gone"
  wr=; tx=; an=
  case $OS in Darwin) split_darwin "$1" "$2" ;; Linux) split_linux "$1" "$2" ;; esac
  # Zero is rejected as well as empty, and ${x:-0} makes the two the same test. Every one of these
  # is a sum over mappings that certainly exist in a running daemon, so a 0 is a sampler that
  # matched nothing -- which is the shape this script's header says looked like a result twice.
  [ "${wr:-0}" -gt 0 ] || die "$1: the sampler gave no written figure"
  [ "${tx:-0}" -gt 0 ] || die "$1: the sampler gave no code figure"
  [ "$OS" != Linux ] || [ "${an:-0}" -gt 0 ] || die "$1: the sampler gave no anonymous figure"
  # Five fields on both platforms, the fifth empty on darwin: the two tables below read the first
  # four and are the same code on either, and only the Linux-only table reads the fifth.
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$rss" "$wr" "$tx" "${an:-}" >> "$W/t.tsv"
}

# measure <label> <home> <pattern|-> -- daemon in the foreground, so this owns the pid
measure() {
  rm -f "$W/$1.out"
  t0=$(date +%s)
  "$NODE" daemon --home "$2" > "$W/$1.out" 2>&1 & p=$!
  [ "$3" = "-" ] || await "$W/$1.out" "$3" 20
  naps "$SETTLE"
  sample "$1" "$p" "$t0"
  kill -TERM "$p" 2>/dev/null || true
  naps 1
}

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

n=0
while [ $n -lt "$RUNS" ]; do
  n=$((n + 1)); echo "run $n/$RUNS"

  measure C "$W/a" "connected to hub"

  # E: the restarted daemon, with a link. Asserted through `ls`, not through open's exit code.
  rm -f "$W/E.out"
  eT0=$(date +%s)
  "$NODE" daemon --home "$W/a" > "$W/E.out" 2>&1 & e=$!
  await "$W/E.out" "connected to hub" 20
  "$NODE" open "$APP_PORT" --name demo --home "$W/a" > /dev/null 2>&1 || true
  "$NODE" ls --home "$W/a" 2>/dev/null | grep -q "demo.*open" || die "E: the link did not open"
  naps "$SETTLE"; sample E "$e" "$eT0"
  # The invite for J comes out of this daemon while it is still up -- `invite` talks to a running
  # one -- and after E is sampled, so that issuing it cannot move E's own figures.
  INVJ=$("$NODE" invite --user "j$n" --home "$W/a" 2>/dev/null | grep -o "https://hub.test:$PORT/join/[A-Za-z0-9_-]*" | head -1)
  # Asserted, not hoped for: a link survives in node.json and Daemon.onConnected reopens it, so a
  # close that quietly failed would make the next run's C state an E and the C -> E delta vanish.
  "$NODE" close demo --home "$W/a" > /dev/null 2>&1 || true
  # Fail-closed: `ls` must succeed AND not name the link. A dead daemon prints nothing to stdout, so
  # testing only for the absence of "demo" would pass in the one case this is here to catch.
  left=$("$NODE" ls --home "$W/a" 2>/dev/null) || die "ls failed after close; cannot tell whether the link went"
  case $left in *demo*) die "the link did not close; C would be an E next run" ;; esac
  kill -TERM "$e" 2>/dev/null || true; naps 1

  # J: a node that joins and opens within one daemon's life -- measure.sh's shape. A new home and a
  # new invite each run, because a join is not repeatable.
  [ -n "$INVJ" ] || die "J: no invite"
  jT0=$(date +%s)
  "$NODE" up --invite "$INVJ" --hub-addr 127.0.0.1 --user "j$n" --ca-file "$CERT" --home "$W/j$n" > /dev/null
  "$NODE" open "$APP_PORT" --name "demo$n" --home "$W/j$n" > /dev/null 2>&1 || true
  "$NODE" ls --home "$W/j$n" 2>/dev/null | grep -q "demo$n.*open" || die "J: the link did not open"
  j=$(pgrep -f "daemon --home $W/j$n" | head -1)
  [ -n "$j" ] || die "J: no daemon"
  naps "$SETTLE"; sample J "$j" "$jT0"; kill -TERM "$j" 2>/dev/null || true; naps 1

  stop_hub
  measure Bpin "$W/a"     "Connection refused"
  measure A    "$W/fresh" -
  grep -q "\[link\]" "$W/A.out" && die "A: the fresh daemon tried to connect, so it is not state A"
  start_hub; naps 2
done


echo
printf 'state  RSS MB (min-max)      written KB   code KB\n'
for s in A Bpin C E J; do
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
    printf "  A    -> J     the whole of what §12 splits    RSS %+.1f MB  written %+.0f KB  code %+.0f KB\n", r["J"]-r["A"], w["J"]-w["A"], t["J"]-t["A"] }' "$W/t.tsv"

# Linux only, and last, because it is the column darwin has no answer for. It is here to be lined up
# against §14, which publishes RSS with the anonymous share beside it: `file-backed` is the rest of
# RSS, and it is the claim this whole file rests on -- that most of what the connect costs is not
# memory the process owns.
if [ "$OS" = Linux ]; then
  echo
  printf 'state  RSS MB   anonymous MB   file-backed MB   anon %%\n'
  for s in A Bpin C E J; do
    awk -F'\t' -v s="$s" '$1==s { n++; sr+=$2/1024; sa+=$5/1024 }
      END { if (n) printf "%-6s %6.1f %14.1f %16.1f %8.0f\n", s, sr/n, sa/n, (sr-sa)/n, 100*sa/sr }' "$W/t.tsv"
  done
fi
