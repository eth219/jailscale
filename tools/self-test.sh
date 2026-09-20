#!/usr/bin/env sh
# Runs the self-test of every script in tools/ that has one, and refuses to run if any script here
# is in neither list below. CI calls this (#192): until it existed, tools/ held twelve scripts --
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
release-key.sh      prints the public half of the signing key
release-keys.sh     lists the keys a release may be signed under
sign-release.sh     signs RELEASE.txt with the KMS key
slow-readers.py     a load generator, as above
throughput.py       a load generator, as above
verify-release.sh   checks a published release; published.yml runs it against the real one
'

fail=0
# The names only. A `while read` in a pipeline runs in a subshell AND returns the status of its
# last command, so `... | while read; do [ x = y ] && exit; done || found=yes` reports "found" every
# time -- which it did, and said flake-rate.sh was in both lists.
UNTESTED_NAMES=$(printf '%s\n' "$UNTESTED" | awk 'NF { print $1 }')

# The names first, then `set -f`: an unquoted $TESTED in a `for` list is glob-expanded against the
# caller's working directory, so an entry with a metacharacter would make the answer depend on
# where the script was run from. The [ -e ] guard is for a glob that matches nothing -- delete the
# three .py files and "$dir"/*.py stays literal, and the run fails naming a file that is not there.
names=
for path in "$dir"/*.sh "$dir"/*.py; do
    [ -e "$path" ] || continue
    name=${path##*/}
    [ "$name" = "self-test.sh" ] && continue
    names="$names $name"
done
set -f

# This one cannot be tested: it has no --self-test, and listing it would recurse until the stack
# or the patience runs out.
for t in $TESTED; do
    [ "$t" = "self-test.sh" ] || continue
    echo "self-test.sh cannot be in its own TESTED list; it would run itself forever." >&2
    exit 1
done

# Every .sh and .py in tools/ is in exactly one of the two lists.
for name in $names; do
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
# A whole line and not a substring, because `usage: ... --self-test: ok to pass N` would otherwise
# do; stdout and not stderr, which is where a script says what went wrong rather than that nothing
# did.
ran=0
for t in $TESTED; do
    echo "== $t --self-test"
    # Four scripts in here are not executable in git's index, so this would otherwise be a bare
    # "Permission denied" from a line that does not say which file or why.
    [ -x "$dir/$t" ] || { echo "$t is listed as tested and is not executable." >&2; exit 1; }
    out=$("$dir/$t" --self-test) || exit 1
    printf '%s\n' "$out"
    printf '%s\n' "$out" | grep -qx 'self-test: ok' \
        || { echo "$t exited 0 without a line saying 'self-test: ok'; it did not run." >&2; exit 1; }
    ran=$((ran + 1))
done

# A runner that silently ran nothing would pass every time, which is the failure this whole file
# exists to prevent one directory over.
[ "$ran" -gt 0 ] || { echo "tools/self-test.sh ran no self-test at all." >&2; exit 1; }
# Counted from $names and not from a glob: `set -f` is on by now, and `ls "$dir"/*.sh` under it
# lists nothing and reports a negative.
total=0
for name in $names; do total=$((total + 1)); done
echo "tools/self-test.sh: $ran of $total scripts have a self-test, and it passed."
