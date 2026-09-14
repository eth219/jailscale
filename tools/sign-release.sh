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
# Every gh call names the repository. The script works in a temp directory from here on, and gh
# resolves a repository from the working tree's remotes -- so without -R the upload at the end
# fails, or worse, finds a different checkout's.
repo=$(cd "$root" && gh repo view --json nameWithOwner --jq .nameWithOwner) \
    || { echo "cannot tell which GitHub repository $root is; is the origin remote set?" >&2; exit 1; }

. "$(dirname "$0")/kms-key.sh"
. "$(dirname "$0")/openssl-ed25519.sh"

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

# Both directions. Every name in the list has to hash to what the list says, and every asset that
# is not the list, the build info or an old signature has to be in the list -- an unlisted binary
# is one the signature would not cover while appearing to.
sha256 -c SHA256SUMS.txt
for f in * .[!.]*; do
    [ -e "$f" ] || continue # an unmatched glob is the pattern itself
    case "$f" in
        SHA256SUMS.txt|BUILDINFO.txt|RELEASE.txt|RELEASE.txt.sig|pub.pem) continue ;;
    esac
    # -F and a cut list rather than a regex: an asset named jailscale-linux-amd.4 would otherwise
    # match the line for jailscale-linux-amd64 and ride along uncovered.
    sed 's/^[0-9a-fA-F]*[ *]*//' SHA256SUMS.txt | grep -qxF "$f" \
        || { echo "$f is published but not in SHA256SUMS.txt" >&2; exit 1; }
done

kms_public_key pub.pem
spki=$("$OPENSSL" pkey -pubin -in pub.pem -outform DER | base64 | tr -d '\n')
fingerprint=$("$OPENSSL" pkey -pubin -in pub.pem -outform DER | "$OPENSSL" dgst -sha256 -binary | od -An -tx1 | tr -d ' \n' | cut -c1-16)

# What accepts this signature is the binaries already in the field, so the key has to be on the
# list the PREVIOUS release compiled in -- not this one's, which only governs the release after it.
# That is exactly what makes a rotation work: ship {old, new} signed with old, then sign the next
# with new. Reading the key list means every string literal long enough to be one, because the
# field is a List.of(...) spread over lines.
src=node/src/main/java/io/jailscale/node/ReleaseKey.java
keys_at() {
    git -C "$root" show "$1:$src" 2>/dev/null | sed -n 's/.*"\([A-Za-z0-9+/=]\{40,\}\)".*/\1/p'
}
git -C "$root" rev-parse -q --verify "$tag^{commit}" >/dev/null \
    || { echo "$root has no $tag; git fetch --tags and try again." >&2; exit 1; }
previous=$(git -C "$root" describe --tags --abbrev=0 "$tag^" 2>/dev/null || true)
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
# anchor outside it is the maintainer's own clone -- `git fetch --tags` will not move a tag that is
# already present without --force, so the commit this tag names here is not something release-write
# can rewrite. Build provenance is what ties the published bytes back to that commit.
want_commit=$(git -C "$root" rev-parse "$tag^{commit}")
echo "verifying build provenance against $want_commit ($tag in $root) ..."
for f in *; do
    case "$f" in
        SHA256SUMS.txt|BUILDINFO.txt|RELEASE.txt|RELEASE.txt.sig|pub.pem) continue ;;
    esac
    gh attestation verify "$f" -R "$repo" \
        --signer-workflow "$repo/.github/workflows/release.yml" \
        --source-digest "$want_commit" --source-ref "refs/tags/$tag" >/dev/null \
        || { echo "$f is not attested as built by $repo's release workflow from $want_commit." >&2; exit 1; }
    echo "  $f"
done

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
