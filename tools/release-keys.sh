# The release keys a given commit compiles in (ARCHITECTURE.md §9.4). Sourced, not run.
#
# Defines release_keys_at ROOT REV, which prints one base64 SPKI per line from ReleaseKey.java as
# it was at REV. Both the signing side (tools/sign-release.sh, "is the key I am about to sign with
# one the field accepts?") and the verifying side (tools/verify-release.sh, "was this release
# signed with a key that tag compiled in?") read the list this way, so they cannot disagree about
# what a key list is.
#
# The read is every string literal long enough to be a key, because the field is a List.of(...)
# spread over lines. That is a regex over Java source, and it is kept honest by the only two
# things that could break it: ReleaseKeyTest pins the fingerprints of what Java reads, and
# sign-release.sh refuses to sign with a key this does not find -- so a key split across two
# literals, or moved into a text block, is caught at the next release rather than in the field.
RELEASE_KEYS_SRC=node/src/main/java/io/jailscale/node/ReleaseKey.java
release_keys_at() {
    git -C "$1" show "$2:$RELEASE_KEYS_SRC" 2>/dev/null | sed -n 's/.*"\([A-Za-z0-9+/=]\{40,\}\)".*/\1/p'
}

# What a release tag looks like, and the one place it is written down: release.yml refuses to
# build anything else, sign-release.sh refuses to sign anything else, and Updates.compare in the
# node parses exactly this. A tag outside it (v0.2.0_rc1) would build and publish as a full
# release that every node then reports "cannot compare" on.
RELEASE_TAG_PATTERN='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
release_tag_ok() {
    printf '%s\n' "$1" | grep -Eq "$RELEASE_TAG_PATTERN"
}

# The release before $2 in $1's history, or empty. --match so a tag that is not a release (a
# benchmark baseline, a bisect marker) is never "the previous release", and --exclude so a
# pre-release is not either: nothing in the field was built from an rc, because releases/latest
# skips pre-releases and nodes only ever fetch that. Read by tools/sign-release.sh to find the key
# list the field accepts, and by tools/refresh-index.sh for the same reason.
release_previous_tag() {
    git -C "$1" describe --tags --match 'v*' --exclude 'v*-*' --abbrev=0 "$2^" 2>/dev/null || true
}

# A release tag as one number that sorts the way Updates.compare does, for shells that have no
# version sort: major, minor and patch in five digits each, then 1 for a release and 0 for a
# pre-release -- a snapshot is the build on the way to a version, so it sorts below it. The leading
# 1 is there so the result is never read as octal. Only meaningful for a tag release_tag_ok accepts.
release_version_key() {
    printf '%s\n' "$1" | awk '{
        v = $0; sub(/^v/, "", v)
        pre = 0; i = index(v, "-")
        if (i > 0) { pre = 1; v = substr(v, 1, i - 1) }
        n = split(v, p, ".")
        printf "1%05d%05d%05d%d", p[1] + 0, (n > 1 ? p[2] + 0 : 0), (n > 2 ? p[3] + 0 : 0), (pre ? 0 : 1)
    }'
}

# True when release tag $1 is strictly newer than release tag $2.
release_newer_than() {
    [ "$(release_version_key "$1")" -gt "$(release_version_key "$2")" ]
}
