#!/bin/sh
# What the trust configuration a node actually ships with costs, measured with a handshake that
# succeeds -- which needs a second binary, and that is the whole point of this script.
#
# measure.sh joins with --ca-file, so every published idle figure describes a node whose trust
# manager holds two certificates. A node joined to a hub with an ordinary web-PKI certificate leaves
# caFile null and JSSE builds its default trust manager over the platform root store, which
# native-image baked into the image at build time. Nothing local has a publicly trusted certificate,
# so that path cannot be exercised against a loopback hub -- unless the store the image was built
# with also trusts the test certificate. So this builds one that does.
#
# TWO CHEAPER-LOOKING METHODS GIVE THE WRONG ANSWER, both by a lot, and both looked fine:
#
#   A failing handshake. Point a caFile-null node at the test hub and PKIX loads the anchors to
#   reject the chain, so the difference against a pinned-CA node that also fails should be the
#   store. It reads +2.5 MB. It is wrong because failing a path build is not the shipped path: it
#   builds and abandons candidate paths and touches code a successful validation never runs.
#
#   A run-time store. The binary does honour -Djavax.net.ssl.trustStore, so a full-size store
#   containing the test certificate can be handed to the shipped binary and the handshake succeeds.
#   It reads +5.7 MB, 4.9 MB of it written. That is wrong in the other direction: it parses a
#   PKCS12 file into the heap at run time, where the shipped node has the anchors in its image heap
#   already, mapped from the binary and mostly clean.
#
# Both were believed before this script existed. The answer is +0.8 MB.
#
# Usage: ./native.sh -DskipTests && docs/jsse-idle-cost/truststore.sh
#   RUNS=5       repeats per state; the spread is under 0.1 MB
#   GRAALVM_HOME to pick the toolchain, as native.sh does
set -eu
R=$(cd "$(dirname "$0")/../.." && pwd)
HUB=$R/hub/target/jailhub
CERT=$R/hub/src/test/resources/tls/hub-test.crt
KEY=$R/hub/src/test/resources/tls/hub-test.key
PORT=${PORT:-19943}; METRICS_PORT=$((PORT + 139)); RUNS=${RUNS:-5}; SETTLE=${SETTLE:-8}
W=/tmp/jsse-truststore.$$
[ -x "$HUB" ] || { echo "build first: ./native.sh -DskipTests" >&2; exit 1; }
mkdir -p "$W/hub"
cleanup() { pkill -f "daemon --home $W" 2>/dev/null || true; [ -n "${HUBPID:-}" ] && kill "$HUBPID" 2>/dev/null || true; sleep 0.3; rm -rf "$W"; }
trap cleanup EXIT
naps() { perl -e "select(undef,undef,undef,$1)"; }
die() { echo "  !! $*" >&2; exit 1; }

home=${GRAALVM_HOME:-}
if [ -z "$home" ]; then
  for c in /Library/Java/JavaVirtualMachines/graalvm-community-25.3*/Contents/Home \
           "$HOME"/Library/Java/JavaVirtualMachines/graalvm-community-25.3*/Contents/Home; do
    [ -x "$c/bin/native-image" ] && { home=$c; break; }
  done
fi
[ -x "$home/bin/native-image" ] || die "native-image not found; see native.sh"

# The store the scratch image is built with: the toolchain's own anchors plus the test certificate,
# so the count is realistic and a loopback hub still validates.
cp "$home/lib/security/cacerts" "$W/cacerts" || die "no cacerts in $home"
keytool -importcert -file "$CERT" -keystore "$W/cacerts" -storepass changeit -noprompt -alias hubtest > /dev/null 2>&1 \
  || die "keytool could not add the test certificate"
anchors=$(keytool -list -keystore "$W/cacerts" -storepass changeit 2>/dev/null | grep -c trustedCertEntry)
echo "scratch trust store: $anchors anchors"

# One glob per jar: a colon-joined pattern is one word to the shell and matches nothing, which
# native-image reports as an empty classpath rather than as the missing jar it is.
CP=""
for m in node proto crypto; do
  j=$(ls "$R/$m/target/$m"-*.jar 2>/dev/null | grep -v -- '-sources\|-javadoc' | head -1)
  [ -n "$j" ] || die "no jar for $m; run ./native.sh -DskipTests first"
  CP="${CP:+$CP:}$j"
done
"$home/bin/native-image" -cp "$CP" --color=never -o "$W/jailscale" \
  -O2 -H:+ReportExceptionStackTraces -R:MaxHeapSize=64m \
  "-Djavax.net.ssl.trustStore=$W/cacerts" -Djavax.net.ssl.trustStorePassword=changeit \
  -Djavax.net.ssl.trustStoreType=PKCS12 io.jailscale.node.Main > "$W/build.log" 2>&1 \
  || { tail -20 "$W/build.log" >&2; die "the scratch build failed"; }
NODE=$W/jailscale
echo "scratch binary built"

start_hub() { "$HUB" serve --base-url "https://hub.test:$PORT" --listen "127.0.0.1:$PORT" --tls-cert "$CERT" --tls-key "$KEY" \
  --state "$W/hub" --port-range none --http-listen none --metrics-listen "127.0.0.1:$METRICS_PORT" >> "$W/hub.log" 2>&1 & HUBPID=$!; }

# Every state asserts it connected before it is sampled. An earlier version of this let the wait
# give up quietly, and a daemon that never connected read 4 MB light -- a plausible number for a
# measurement of nothing.
measure() {
  rm -f "$W/$1.out"
  "$NODE" daemon --home "$2" > "$W/$1.out" 2>&1 & p=$!
  i=0; ok=no
  while [ $i -lt 250 ]; do grep -q "connected to hub" "$W/$1.out" 2>/dev/null && { ok=yes; break; }; i=$((i + 1)); naps 0.1; done
  [ "$ok" = yes ] || { tail -3 "$W/$1.out" >&2; die "$1: never connected"; }
  naps "$SETTLE"
  rss=$(ps -o rss= -p "$p" | tr -d ' ') || die "$1: the daemon is gone"
  vmmap "$p" > "$W/$1.vmmap" 2>&1 || true
  wr=$(awk -F'written=' '/^Writable regions:/{split($2,a,"K"); print a[1]; exit}' "$W/$1.vmmap")
  kill -TERM "$p" 2>/dev/null || true; naps 1
  printf '%s\t%s\t%s\n' "$1" "$rss" "${wr:-0}" >> "$W/t.tsv"
}

start_hub; naps 1.5
INV=$(grep -o "https://hub.test:$PORT/join/[A-Za-z0-9_-]*" "$W/hub.log" | head -1)
[ -n "$INV" ] || die "no invite in hub.log"
"$NODE" up --invite "$INV" --hub-addr 127.0.0.1 --user alice --ca-file "$CERT" --home "$W/a" > /dev/null
"$NODE" down --home "$W/a" > /dev/null 2>&1 || true; naps 0.5
pkill -f "daemon --home $W" 2>/dev/null || true; naps 0.5
# Three copies of one joined state, differing only in how the hub's certificate is trusted.
for d in emb ins; do cp -R "$W/a" "$W/$d"; rm -f "$W/$d/daemon.lock" "$W/$d/daemon.log"; done
sed -e 's/"caFile":"[^"]*",//' "$W/a/node.json" > "$W/emb/node.json"
sed -e 's/"caFile":"[^"]*",//' -e 's/"tlsInsecure":false/"tlsInsecure":true/' "$W/a/node.json" > "$W/ins/node.json"
grep -q caFile "$W/emb/node.json" && die "caFile survived the edit"
grep -q '"tlsInsecure":true' "$W/ins/node.json" || die "tlsInsecure did not take"

n=0
while [ $n -lt "$RUNS" ]; do
  n=$((n + 1)); echo "run $n/$RUNS"
  measure ins "$W/ins"; measure pin "$W/a"; measure emb "$W/emb"
done

echo
printf '%-42s %s\n' "trust configuration" "RSS MB (min-max)   written KB"
for s in ins pin emb; do
  case $s in
    ins) label="tlsInsecure: TrustAll, no PKIX at all" ;;
    pin) label="--ca-file: two anchors (what the gate uses)" ;;
    emb) label="caFile null: the image's own store ($anchors)" ;;
  esac
  awk -F'\t' -v s="$s" -v l="$label" '$1==s { n++; r=$2/1024; sr+=r; sw+=$3; if(r>mx||n==1)mx=r; if(r<mn||n==1)mn=r }
    END { if (n) printf "%-42s %5.2f (%.1f-%.1f)%7s%.0f\n", l, sr/n, mn, mx, "", sw/n }' "$W/t.tsv"
done
echo
awk -F'\t' '{ n[$1]++; r[$1]+=$2/1024; w[$1]+=$3 }
  END { for (s in n) { r[s]/=n[s]; w[s]/=n[s] }
    printf "  what the shipped trust config costs over the gate'"'"'s   %+.2f MB  (written %+.0f KB)\n", r["emb"]-r["pin"], w["emb"]-w["pin"]
    printf "  what dropping certificate validation entirely buys   %+.2f MB  (written %+.0f KB)\n", r["ins"]-r["emb"], w["ins"]-w["emb"] }' "$W/t.tsv"
