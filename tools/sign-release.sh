#!/usr/bin/env sh
# Signs a release's SHA256SUMS.txt and publishes it (ARCHITECTURE.md §9.4, §14).
#
#   tools/sign-release.sh v0.1.3
#
# The release workflow leaves a draft. This downloads everything in it, re-hashes it against the
# checksum file, shows what built it, and only then signs -- so the signature says "these are the
# bytes I looked at", not "the pipeline said so". `jailscale update --download` refuses anything
# this has not signed, which is also why publishing is the last step: a release visible before its
# signature is up is one nobody can install from.
#
# What gets signed is RELEASE.txt, written here: the tag and the sha256 of SHA256SUMS.txt. Not
# SHA256SUMS.txt itself, because that file says nothing about which release it belongs to -- a
# signature over it alone is a valid signature for every future tag, and whoever can publish a
# release could republish an old signed one under a higher version. SHA256SUMS.txt is left exactly
# as the workflow wrote it so that `sha256sum -c` still works on it.
#
# The key is in Cloud KMS and the call is made from here, by a person. Moving this step into the
# workflow would hand the capability to whoever can make that workflow run (§9.4), which is the
# adversary the signature exists for.
set -eu

tag=${1:-}
if [ -z "$tag" ]; then
    echo "usage: tools/sign-release.sh vX.Y.Z" >&2
    exit 2
fi
command -v gh >/dev/null 2>&1 || { echo "this needs the gh CLI, logged in to the release account." >&2; exit 1; }

root=$(cd "$(dirname "$0")/.." && pwd)
. "$(dirname "$0")/release-keys.sh"
release_tag_ok "$tag" || {
    echo "$tag is not a release tag: vMAJOR.MINOR.PATCH, with an optional -suffix for a pre-release." >&2
    echo "The node parses exactly that shape, and a release under any other name is one every node" >&2
    echo "reports \"cannot compare\" on." >&2
    exit 1
}
# Every gh call names the repository. The script works in a temp directory from here on, and gh
# resolves a repository from the working tree's remotes -- so without -R the upload at the end
# fails, or worse, finds a different checkout's.
repo=$(cd "$root" && gh repo view --json nameWithOwner --jq .nameWithOwner) \
    || { echo "cannot tell which GitHub repository $root is; is the origin remote set?" >&2; exit 1; }

. "$(dirname "$0")/kms-key.sh"
. "$(dirname "$0")/openssl-ed25519.sh"
. "$(dirname "$0")/release-index.sh"

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$@"; }
else
    sha256() { shasum -a 256 "$@"; }
fi

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
echo "downloading every asset of $tag ..."
gh release download -R "$repo" "$tag" --dir "$dir" --pattern '*' --clobber

cd "$dir"
[ -f SHA256SUMS.txt ] || { echo "$tag has no SHA256SUMS.txt to sign." >&2; exit 1; }

# The files the signature is about: everything in the release that is not the list itself, the
# build info, a signature from an earlier run, or the key this fetched. One definition, walked by
# both checks below, dotfiles included -- two copies of this list once disagreed about exactly that.
assets() {
    for f in * .[!.]*; do
        [ -e "$f" ] || continue # an unmatched glob is the pattern itself
        case "$f" in
            SHA256SUMS.txt|BUILDINFO.txt|RELEASE.txt|RELEASE.txt.sig|pub.pem) continue ;;
        esac
        printf '%s\n' "$f"
    done
}

# Both directions. Every name in the list has to hash to what the list says, and every asset that
# is not the list, the build info or an old signature has to be in the list -- an unlisted binary
# is one the signature would not cover while appearing to.
sha256 -c SHA256SUMS.txt
assets | while IFS= read -r f; do
    # -F and a cut list rather than a regex: an asset named jailscale-linux-amd.4 would otherwise
    # match the line for jailscale-linux-amd64 and ride along uncovered.
    sed 's/^[0-9a-fA-F]*[ *]*//' SHA256SUMS.txt | grep -qxF "$f" \
        || { echo "$f is published but not in SHA256SUMS.txt" >&2; exit 1; }
done || exit 1 # the loop is a subshell, so its exit has to be carried out of the pipeline

kms_public_key pub.pem
spki=$(spki_base64 pub.pem)
fingerprint=$(spki_fingerprint pub.pem)

# What accepts this signature is the binaries already in the field, so the key has to be on the
# list the PREVIOUS release compiled in -- not this one's, which only governs the release after it.
# That is exactly what makes a rotation work: ship {old, new} signed with old, then sign the next
# with new. The list is read by release_keys_at (tools/release-keys.sh), the same reader the
# published-release check uses.
src=$RELEASE_KEYS_SRC
keys_at() {
    release_keys_at "$root" "$1"
}
# The tag has to be in this clone already, and it has to be on this clone's main. Those two
# together are what make the local checkout an anchor at all: a tag that is only on the remote is
# one anybody with write access may have pushed, and the obvious fix -- fetch it and rerun -- would
# import their commit and then verify the release against it, with every check below green. So the
# message does not say "fetch"; it says "look". A tag made here and pushed from here is in both
# places by construction.
git -C "$root" rev-parse -q --verify "$tag^{commit}" >/dev/null || {
    echo "$root has no $tag." >&2
    echo "If you made this release, tag it here and push the tag from here. If the tag appeared on" >&2
    echo "the remote without you, do not fetch it and sign it: read what it names first --" >&2
    echo "  git -C $root fetch origin +refs/tags/$tag:refs/remotes/origin/tags/$tag --no-tags" >&2
    echo "  git -C $root log --oneline main..origin/tags/$tag" >&2
    exit 1
}
want_commit=$(git -C "$root" rev-parse "$tag^{commit}")
# The local branch, on purpose, not origin/main: whoever can push a tag can push to main too, and
# the reviewed history is the one in this clone. The cost is that a stale local main refuses a
# good tag, so the message says what to do about that rather than calling the tag unreviewed.
git -C "$root" rev-parse -q --verify 'main^{commit}' >/dev/null || {
    echo "$root has no local branch main, which is what a release tag is checked against." >&2
    exit 1
}
git -C "$root" merge-base --is-ancestor "$want_commit" main || {
    echo "$tag names $want_commit, which is not on this clone's main." >&2
    echo "If you tagged origin/main, fast-forward main here first and rerun:" >&2
    echo "  git -C $root fetch origin main:main" >&2
    echo "If main is current, this tag names a commit main never had, and it should not be signed." >&2
    exit 1
}
# Which release the field's key list comes from, by the one definition of it in
# tools/release-keys.sh -- a tag that is not a release is never "the previous release", and neither
# is a pre-release, because nothing in the field was built from an rc. A key list read from an rc is
# a list no deployed binary accepts, and a rotation checked against it would publish a release every
# node refuses, which is the exact outcome this check exists to stop. tools/refresh-index.sh asks
# the same question about the pointer and has to get the same answer.
previous=$(release_previous_tag "$root" "$tag")
accepted=""
accepted_from=$previous
[ -n "$previous" ] && accepted=$(keys_at "$previous")
if [ -z "$accepted" ]; then
    # Either the first release ever, or the first one after the key existed: the release before this
    # has no key list, so nothing in the field can accept any signature and there is nothing to be
    # compatible with. Fall back to this tag's own list, which at least catches signing with a key
    # no build has ever heard of.
    echo "nothing before $tag carries a key list; checking against $tag's own instead."
    accepted_from=$tag
    accepted=$(keys_at "$tag")
    [ -n "$accepted" ] || { echo "cannot read a key list from $src at $tag." >&2; exit 1; }
fi
if ! printf '%s\n' "$accepted" | grep -qxF "$spki"; then
    echo "the key you are signing with is not one that $accepted_from accepts." >&2
    echo "  this key:  $spki" >&2
    echo "  accepted:  $(printf '%s\n' "$accepted" | tr '\n' ' ')" >&2
    echo "Signing anyway would publish a release that every binary in the field refuses to update to." >&2
    echo "To rotate: ship a release whose PUBLIC_KEYS lists both keys, signed with the old one, first." >&2
    exit 1
fi
# Everything above compares the release against itself: SHA256SUMS.txt is an asset like the others,
# and so is BUILDINFO.txt, so anyone who can write to this release can make all of it agree. The one
# anchor outside it is the maintainer's own clone: the tag was required to be here already and on
# main, so the commit it names is one that was reviewed here rather than one release-write could
# supply. Build provenance is what ties the published bytes back to that commit.
echo "verifying build provenance against $want_commit ($tag in $root) ..."
assets | while IFS= read -r f; do
    # </dev/null: the loop's stdin is the asset list, and a gh that read from it would end the loop
    # early with the remaining assets unverified and the exit status clean.
    gh attestation verify "$f" -R "$repo" \
        --signer-workflow "$repo/.github/workflows/release.yml" \
        --source-digest "$want_commit" --source-ref "refs/tags/$tag" >/dev/null </dev/null \
        || { echo "$f is not attested as built by $repo's release workflow from $want_commit." >&2; exit 1; }
    echo "  $f"
done || exit 1

# BUILDINFO is the release's own account of itself, so it is compared rather than displayed. It
# proves nothing on its own -- the check above is what makes it hard to forge -- but a mismatch
# here means the release and the tag disagree about something, and that is worth stopping for.
if [ -f BUILDINFO.txt ]; then
    # Every line, not any line: the file is one block per target, so a single target built from
    # somewhere else is exactly the case worth catching.
    lines=$(grep -c '^commit:' BUILDINFO.txt || true)
    same=$(grep -c "^commit:  *$want_commit\$" BUILDINFO.txt || true)
    if [ "${lines:-0}" -eq 0 ] || [ "$lines" != "$same" ]; then
        echo "BUILDINFO.txt does not name $want_commit for every target:" >&2
        grep '^commit:' BUILDINFO.txt >&2
        exit 1
    fi
    echo
    cat BUILDINFO.txt
else
    echo "(no BUILDINFO.txt in this release)"
fi
echo
# What is about to be vouched for, as commits rather than as a hash: the signature says the
# maintainer looked, and this is the looking.
if [ -n "$previous" ]; then
    echo "$previous..$tag:"
    git -C "$root" log --oneline "$previous..$tag" | sed 's/^/  /'
    echo
fi
echo "$(grep -c . SHA256SUMS.txt) files, all hashing to what SHA256SUMS.txt says,"
echo "all attested as built from $want_commit."
echo "signing with $KMS_KEY version $KMS_VERSION in $KMS_PROJECT, fingerprint $fingerprint"
echo "which $accepted_from accepts, so the binaries in the field will too."
printf 'sign and upload? [y/N] '
read -r answer
case "$answer" in
    y|Y) ;;
    *) echo "nothing signed."; exit 1 ;;
esac

printf 'jailscale-release 1\ntag: %s\nsha256sums: %s\n' "$tag" "$(sha256 SHA256SUMS.txt | cut -d" " -f1)" > RELEASE.txt
kms_sign RELEASE.txt RELEASE.txt.sig
# Verified here before it is uploaded, against the public half fetched above: a signature nobody
# checked is how a release goes out that every node then refuses.
"$OPENSSL" pkeyutl -verify -pubin -inkey pub.pem -rawin -in RELEASE.txt -sigfile RELEASE.txt.sig
echo
cat RELEASE.txt
gh release upload -R "$repo" "$tag" RELEASE.txt RELEASE.txt.sig --clobber

if [ "$(gh release view -R "$repo" "$tag" --json isDraft --jq .isDraft)" = "true" ]; then
    printf 'publish %s now? [y/N] ' "$tag"
    read -r answer
    case "$answer" in
        y|Y) gh release edit -R "$repo" "$tag" --draft=false && echo "$tag is out." ;;
        *) echo "$tag stays a draft; gh release edit -R $repo $tag --draft=false when you are ready." ;;
    esac
fi

# --- the pointer that says which release is current (docs/update-freshness) --------------------
#
# What was signed above says which release it *is*. Nothing yet says which one is the newest, and
# that is the gap ARCHITECTURE.md §15 records: whoever can publish can hold a node on an older,
# genuinely signed release for as long as the index keeps naming it. The pointer closes it, and it
# is moved here rather than by hand, so that publishing a release and announcing it are one act
# with one decision in them. tools/refresh-index.sh does the same thing between releases.
echo
if [ "$(gh release view -R "$repo" "$tag" --json isDraft --jq .isDraft)" = "true" ]; then
    echo "$tag is a draft, so the index still names what it named."
    echo "Publish it and then: tools/refresh-index.sh --tag $tag"
    exit 0
fi
if [ "$(gh release view -R "$repo" "$tag" --json isPrerelease --jq .isPrerelease)" = "true" ]; then
    echo "$tag is a pre-release, so the index is left alone: releases/latest skips these and so do nodes."
    exit 0
fi
index_rc=0
index_fetch "$repo" "$dir/index" || index_rc=$?
if [ "$index_rc" = 3 ]; then
    echo "$tag is out. There is no $INDEX_TAG pointer yet, and this will not invent one:"
    echo "  tools/refresh-index.sh --first $tag"
    exit 0
fi
if [ "$index_rc" != 0 ]; then
    echo "$tag is out, but the current pointer could not be read, so it has not been moved." >&2
    echo "A sequence that restarts because a network was down is the rule it exists for, deleted." >&2
    echo "When you can reach GitHub again: tools/refresh-index.sh --tag $tag" >&2
    exit 1
fi
index_keys=$(release_keys_at "$root" "$(index_key_rev "$root" "$dir/index")")
index_line=$(index_verify "$dir/index" "$index_keys") || {
    echo "$tag is out, but the pointer that is published does not verify; find out why before" >&2
    echo "overwriting it. Nothing has been changed." >&2
    exit 1
}
index_seq=$(printf '%s' "$index_line" | cut -d' ' -f1)
index_names=$(printf '%s' "$index_line" | cut -d' ' -f2)
if ! release_newer_than "$tag" "$index_names"; then
    # Signing an older patch after a newer release is out is a thing that happens, and moving the
    # pointer back to it is not what the person doing it asked for. It stays a deliberate act:
    # refresh-index.sh --tag says the sentence about what it means and asks.
    echo "$tag is out. The index names $index_names, which is not below it, so it has not been moved."
    echo "If you do mean to point it back: tools/refresh-index.sh --tag $tag"
    exit 0
fi
echo "moving the index from $index_names (seq $index_seq) to $tag ..."
index_issue "$repo" "$dir/index" "$tag" "$((index_seq + 1))" "$dir/pub.pem"
echo
echo "$INDEX_TAG now names $tag at seq $((index_seq + 1))."
