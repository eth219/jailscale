#!/usr/bin/env sh
# Re-issues the signed pointer that says which release is current (docs/update-freshness).
#
#   tools/refresh-index.sh                  # same release, new sequence, new dates
#   tools/refresh-index.sh --tag vX.Y.Z     # point it somewhere else, on purpose
#   tools/refresh-index.sh --first vX.Y.Z   # the first pointer there has ever been
#
# tools/sign-release.sh moves the pointer forward whenever it publishes a release, so the plain
# form here is for the months with no release in them: the expiry is what stops a pointer nobody
# is re-issuing from going on being believed, and something has to re-issue it. One command, one
# KMS call, one upload.
#
# That recurring manual step is the price of not having a key the release pipeline can use, and it
# is the honest cost of this design: if it lapses, every node eventually reports that it cannot
# tell whether it is current -- which is true, and is the point -- while upgrades and signature
# checks go on working exactly as before.
#
# The sequence is only ever taken from the pointer that is published and incremented. A fetch that
# fails is not an empty index, and --first refuses to run while a pointer exists: a sequence that
# restarts is the rule a client enforces with it, deleted.
set -eu

usage() {
    echo "usage: tools/refresh-index.sh [--tag vX.Y.Z | --first vX.Y.Z]"
}

mode=refresh
want=""
case ${1:-} in
    "") ;;
    --tag) mode=move; want=${2:-} ;;
    --first) mode=first; want=${2:-} ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
if [ "$mode" != refresh ] && [ -z "$want" ]; then
    usage >&2
    exit 2
fi
command -v gh >/dev/null 2>&1 || { echo "this needs the gh CLI, logged in to the release account." >&2; exit 1; }

root=$(cd "$(dirname "$0")/.." && pwd)
. "$(dirname "$0")/release-keys.sh"
. "$(dirname "$0")/kms-key.sh"
. "$(dirname "$0")/openssl-ed25519.sh"
. "$(dirname "$0")/release-index.sh"
# Every gh call names the repository: this works in a temp directory, and gh otherwise resolves one
# from the working tree's remotes -- so without -R the upload finds a different checkout's, or none.
repo=$(cd "$root" && gh repo view --json nameWithOwner --jq .nameWithOwner) \
    || { echo "cannot tell which GitHub repository $root is; is the origin remote set?" >&2; exit 1; }

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

rc=0
index_fetch "$repo" "$dir/now" || rc=$?
[ "$rc" != 1 ] || { echo "could not read the current pointer, so this will not write one." >&2; exit 1; }

seq=""
tag=""
if [ "$mode" = first ]; then
    [ "$rc" = 3 ] || {
        echo "$repo already has a pointer. --first would restart the sequence at 1, which is the" >&2
        echo "one thing a client uses it to refuse; use --tag to move the pointer instead." >&2
        exit 1
    }
    seq=1
    tag=$want
    echo "no pointer exists yet; this will be the first, at seq 1."
else
    [ "$rc" = 0 ] || {
        echo "$repo has no $INDEX_TAG pointer yet." >&2
        echo "Make the first one with: tools/refresh-index.sh --first vX.Y.Z" >&2
        exit 1
    }
    # Verified before it is read from, and against a key list rather than one key: what the current
    # sequence is decides what this publishes, so unsigned bytes must not be what says it.
    rev=$(index_key_rev "$root" "$dir/now")
    keys=$(release_keys_at "$root" "$rev")
    [ -n "$keys" ] || { echo "no release key list in $RELEASE_KEYS_SRC at $rev." >&2; exit 1; }
    line=$(index_verify "$dir/now" "$keys") || {
        echo "the pointer that is published does not verify; do not overwrite it before finding out why." >&2
        exit 1
    }
    # shellcheck disable=SC2086 # five known fields, deliberately split
    set -- $line
    seq=$((${1} + 1))
    tag=${2}
    echo "published now: seq $1 names $2, issued $3, expires $4"
    [ "$mode" = refresh ] || tag=$want
fi

release_tag_ok "$tag" || {
    echo "$tag is not a release tag: vMAJOR.MINOR.PATCH, with an optional -suffix for a pre-release." >&2
    exit 1
}
# The same anchor sign-release.sh uses: the tag has to be in this clone already and on its main. A
# pointer is a claim that a release is the one to install, and it should not be made about a tag
# that only exists on the remote, where write access alone could have put it.
git -C "$root" rev-parse -q --verify "$tag^{commit}" >/dev/null || {
    echo "$root has no $tag. Do not fetch it to make this work: read what it names first." >&2
    exit 1
}
git -C "$root" merge-base --is-ancestor "$(git -C "$root" rev-parse "$tag^{commit}")" main || {
    echo "$tag names a commit that is not on this clone's main." >&2
    echo "If you tagged origin/main, fast-forward main here first: git -C $root fetch origin main:main" >&2
    exit 1
}
draft=$(gh release view -R "$repo" "$tag" --json isDraft --jq .isDraft 2>/dev/null) || {
    echo "$repo has no release $tag to point at." >&2
    exit 1
}
[ "$draft" = "false" ] || { echo "$tag is still a draft; publish it before pointing the index at it." >&2; exit 1; }
[ "$(gh release view -R "$repo" "$tag" --json isPrerelease --jq .isPrerelease)" = "false" ] || {
    echo "$tag is a pre-release. releases/latest skips those and so does this: nothing in the field" >&2
    echo "should be steered onto a build no release was made from." >&2
    exit 1
}
# A pointer at an unsigned release would announce a release no node can install, and the check is
# cheap: the three small files, the same way published.yml checks them.
echo "checking that $tag is signed ..."
"$(dirname "$0")/verify-release.sh" "$tag" >/dev/null || {
    echo "$tag does not verify, so it is not something to point every node at." >&2
    exit 1
}

# The key has to be one the field accepts, which is the list the release BEFORE this one compiled
# in -- not this one's, which may already carry the next key of a rotation that no deployed binary
# has yet. Same rule as signing a release, for the same reason.
kms_public_key "$dir/pub.pem"
spki=$(spki_base64 "$dir/pub.pem")
fingerprint=$(spki_fingerprint "$dir/pub.pem")
previous=$(release_previous_tag "$root" "$tag")
accepted_from=${previous:-$tag}
accepted=$(release_keys_at "$root" "$accepted_from")
[ -n "$accepted" ] || { echo "cannot read a key list from $RELEASE_KEYS_SRC at $accepted_from." >&2; exit 1; }
printf '%s\n' "$accepted" | grep -qxF "$spki" || {
    echo "the key you are signing with is not one that $accepted_from accepts." >&2
    echo "  this key:  $spki" >&2
    echo "Signing anyway would publish a pointer every binary in the field refuses to read." >&2
    exit 1
}

echo
echo "about to publish: seq $seq, tag $tag"
echo "  issued $(index_when 0), expires $(index_when "$INDEX_DAYS")"
echo "  signed with $KMS_KEY version $KMS_VERSION in $KMS_PROJECT, fingerprint $fingerprint"
if [ "$mode" = move ] && [ "$rc" = 0 ] && ! release_newer_than "$tag" "$(index_field "$dir/now/$INDEX_FILE" tag)"; then
    # Allowed, and worth a sentence first. A client takes the higher sequence and then compares the
    # tag with what it runs, so this never moves a node backwards -- it stops steering the ones that
    # have not upgraded yet, which is the reason to do it in a hurry.
    echo
    echo "this points the index BACK from $(index_field "$dir/now/$INDEX_FILE" tag) to $tag."
    echo "Nodes already on the newer release stay there and will report themselves up to date;"
    echo "nodes behind it will be offered $tag instead."
fi
printf 'sign and upload? [y/N] '
read -r answer
case "$answer" in
    y|Y) ;;
    *) echo "nothing signed."; exit 1 ;;
esac

index_issue "$repo" "$dir" "$tag" "$seq" "$dir/pub.pem"
echo
echo "$INDEX_TAG now names $tag at seq $seq."
