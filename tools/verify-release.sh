#!/usr/bin/env sh
# Checks that a published release is signed the way `jailscale update --download` will check it
# (ARCHITECTURE.md §9.4): RELEASE.txt verifies under a key that the tag's own ReleaseKey.java
# lists, names that tag, and carries the digest of the SHA256SUMS.txt beside it.
#
#   tools/verify-release.sh vX.Y.Z [DIR]
#
# With no DIR the three files are downloaded from the release with gh. With one, they are read
# from it, which is how a person checks a download by hand. The key list is read from this clone
# at the tag, or at $RELEASE_KEYS_REV when that is set -- the release workflow runs this from a
# checkout that is already at the tag and says HEAD.
#
# This is what .github/workflows/published.yml runs the moment a release is published, and a
# release that fails it is put back into draft: "published" is only allowed to mean "signed".
set -eu

tag=${1:-}
dir=${2:-}
if [ -z "$tag" ]; then
    echo "usage: tools/verify-release.sh vX.Y.Z [DIR]" >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/.." && pwd)
. "$(dirname "$0")/release-keys.sh"
. "$(dirname "$0")/openssl-ed25519.sh"

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$@"; }
else
    sha256() { shasum -a 256 "$@"; }
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if [ -z "$dir" ]; then
    command -v gh >/dev/null 2>&1 || { echo "this needs the gh CLI." >&2; exit 1; }
    repo=$(cd "$root" && gh repo view --json nameWithOwner --jq .nameWithOwner)
    dir=$tmp/release
    mkdir -p "$dir"
    for f in RELEASE.txt RELEASE.txt.sig SHA256SUMS.txt; do
        gh release download -R "$repo" "$tag" --dir "$dir" --pattern "$f" </dev/null \
            || { echo "$tag has no $f." >&2; exit 1; }
    done
fi
for f in RELEASE.txt RELEASE.txt.sig SHA256SUMS.txt; do
    [ -f "$dir/$f" ] || { echo "$dir has no $f." >&2; exit 1; }
done

# The manifest has to say it is this release: a signature over another tag's RELEASE.txt is a
# genuine signature over the wrong thing, which is the replay the tag line exists to stop.
head -n 1 "$dir/RELEASE.txt" | grep -qx 'jailscale-release 1' \
    || { echo "RELEASE.txt is not in a format this reads: $(head -n 1 "$dir/RELEASE.txt")" >&2; exit 1; }
said=$(sed -n 's/^tag:[[:space:]]*//p' "$dir/RELEASE.txt" | head -n 1)
[ "$said" = "$tag" ] || { echo "RELEASE.txt says it belongs to '$said', not $tag." >&2; exit 1; }
want=$(sed -n 's/^sha256sums:[[:space:]]*//p' "$dir/RELEASE.txt" | head -n 1 | tr 'A-F' 'a-f')
have=$(sha256 "$dir/SHA256SUMS.txt" | cut -d' ' -f1)
[ "$want" = "$have" ] || { echo "SHA256SUMS.txt hashes to $have; the signed RELEASE.txt says $want." >&2; exit 1; }

rev=${RELEASE_KEYS_REV:-$tag}
keys=$(release_keys_at "$root" "$rev")
[ -n "$keys" ] || { echo "no release key list in $RELEASE_KEYS_SRC at $rev." >&2; exit 1; }
verified=""
for spki in $keys; do
    printf '%s' "$spki" | base64 -d > "$tmp/key.der"
    "$OPENSSL" pkey -pubin -inform DER -in "$tmp/key.der" -out "$tmp/key.pem" 2>/dev/null || continue
    if "$OPENSSL" pkeyutl -verify -pubin -inkey "$tmp/key.pem" -rawin \
        -in "$dir/RELEASE.txt" -sigfile "$dir/RELEASE.txt.sig" >/dev/null 2>&1; then
        verified=$(spki_fingerprint "$tmp/key.pem")
        break
    fi
done
[ -n "$verified" ] || { echo "RELEASE.txt.sig matches none of the keys $rev compiles in." >&2; exit 1; }
echo "$tag: RELEASE.txt verified by release key $verified, SHA256SUMS.txt matches it."
