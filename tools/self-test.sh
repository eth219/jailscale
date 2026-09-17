#!/usr/bin/env sh
# Runs the self-test of every script in tools/ that has one, and refuses to run if any script here
# is in neither list below. CI calls this (#192): until it existed, tools/ held eleven scripts --
# two of which sign a release -- and nothing in CI ran a test for any of them.
#
#   tools/self-test.sh
#
# The point of the second list is that it is a list. A script with no test is a decision somebody
# made, and the reason is written next to it, the way spotbugs-exclude.xml carries the reason for
# every exclusion. Adding a script to tools/ and forgetting to test it is the case this refuses
# to let pass quietly: it fails, naming the file, until the file is in one list or the other.
set -eu

dir=$(cd "$(dirname "$0")" && pwd)

# Has a --self-test, and it runs here.
TESTED='flake-rate.sh'

# Has none, and why. "Reaches the network or a key" is not an excuse forever -- it is a statement
# that nobody has yet worked out what the test would assert, which is issue-shaped rather than
# something to invent in this file.
UNTESTED='
hold-visitors.py    a load generator; measure.sh is what says whether its numbers are believed
kms-key.sh          creates the signing key in Cloud KMS, once, by hand
openssl-ed25519.sh  prints an openssl invocation; its output is checked by the eye that runs it
refresh-index.sh    signs a new release-index pointer with the KMS key
release-index.sh    builds the index document that refresh-index.sh signs
release-key.sh      prints the public half of the signing key
release-keys.sh     lists the keys a release may be signed under
sign-release.sh     signs RELEASE.txt with the KMS key
slow-readers.py     a load generator, as above
throughput.py       a load generator, as above
verify-release.sh   checks a published release; the nightly index job runs it against the real one
'

fail=0
# The names only. A `while read` in a pipeline runs in a subshell AND returns the status of its
# last command, so `... | while read; do [ x = y ] && exit; done || found=yes` reports "found" every
# time -- which it did, and said flake-rate.sh was in both lists.
UNTESTED_NAMES=$(printf '%s\n' "$UNTESTED" | awk 'NF { print $1 }')

# Every .sh and .py in tools/ is in exactly one of the two lists.
for path in "$dir"/*.sh "$dir"/*.py; do
    name=${path##*/}
    [ "$name" = "self-test.sh" ] && continue
    in_tested=no; in_untested=no
    for t in $TESTED; do [ "$t" = "$name" ] && in_tested=yes; done
    for u in $UNTESTED_NAMES; do [ "$u" = "$name" ] && in_untested=yes; done
    if [ "$in_tested" = no ] && [ "$in_untested" = no ]; then
        echo "$name is in neither list in tools/self-test.sh: give it a --self-test, or say why not." >&2
        fail=1
    fi
    if [ "$in_tested" = yes ] && [ "$in_untested" = yes ]; then
        echo "$name is in both lists in tools/self-test.sh." >&2
        fail=1
    fi
done

# And the reverse: a name in a list that no longer exists is a list nobody has read in a while.
for t in $TESTED; do
    [ -f "$dir/$t" ] || { echo "$t is listed as tested and is not in tools/." >&2; fail=1; }
done
for u in $UNTESTED_NAMES; do
    [ -f "$dir/$u" ] || { echo "$u is listed as untested and is not in tools/." >&2; fail=1; }
done

[ "$fail" = 0 ] || exit 1

# Each self-test has to say `self-test: ok` on its way out. Without that the runner's own claim is
# unfalsifiable: replace the invocation with `true` and it still reports that everything passed.
ran=0
for t in $TESTED; do
    echo "== $t --self-test"
    out=$("$dir/$t" --self-test 2>&1) || { printf '%s\n' "$out" >&2; exit 1; }
    printf '%s\n' "$out"
    case $out in
        *"self-test: ok"*) ;;
        *) echo "$t exited 0 without saying 'self-test: ok'; it did not run." >&2; exit 1 ;;
    esac
    ran=$((ran + 1))
done

# A runner that silently ran nothing would pass every time, which is the failure this whole file
# exists to prevent one directory over.
[ "$ran" -gt 0 ] || { echo "tools/self-test.sh ran no self-test at all." >&2; exit 1; }
total=$(ls "$dir"/*.sh "$dir"/*.py | wc -l | tr -d ' ')
echo "tools/self-test.sh: $ran of $((total - 1)) scripts have a self-test, and it passed."
