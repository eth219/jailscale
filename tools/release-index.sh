# The signed pointer that says which release is current (docs/update-freshness). Sourced, not run.
#
# A release's RELEASE.txt says which release it *is*; nothing says which one is the newest, so
# whoever can publish can keep a node on an older -- genuinely signed -- release for as long as the
# index keeps naming it. This is the document that closes that: one small file, signed with the same
# release key, carrying a sequence number a client refuses to go backwards on and an expiry that
# makes a pointer nobody is re-issuing say so instead of going on being believed.
#
#   jailscale-index 1
#   seq: 7
#   tag: v0.1.10
#   issued: 2026-09-15T04:00:00Z
#   expires: 2026-12-14T04:00:00Z
#
# It lives as two assets of one fixed pre-release, re-uploaded in place, so the URL a client
# compiles in is the DOWNLOADS constant it already has with one more tag under it -- no new host, no
# new credential, and no second publishing path to keep honest. A pre-release because
# `releases/latest` must never point at it.
#
# Nothing in the field reads it yet: step 1 of docs/update-freshness is this file and the two
# scripts that use it, and it is deliberately separable from the client work so that publishing can
# start early and the first pointer a client ever verifies is not also the first one ever made.
#
# Defines the constants below plus index_when, index_field, index_fetch, index_verify and
# index_issue. index_issue needs kms_sign (tools/kms-key.sh), $OPENSSL (tools/openssl-ed25519.sh)
# and gh in scope; it says so rather than assuming it.

INDEX_TAG=release-index
INDEX_FILE=latest.txt
INDEX_SIG=latest.txt.sig
INDEX_FORMAT='jailscale-index 1'
# Months, not minutes: every re-issue is a person at a laptop calling KMS, because the key the
# release pipeline cannot reach is the whole point (ARCHITECTURE.md §9.4). 90 days is chosen
# against how often this project releases and is meant to be revisited with evidence.
#
# Checked here, where it is read, because `date` fails quietly: a `3m` or a `180 ` produces no
# instant at all, and an empty field in a document this signs is a pointer nobody can read and
# nothing here will overwrite.
INDEX_DAYS=${JAILSCALE_INDEX_DAYS:-90}
case $INDEX_DAYS in
    ''|*[!0-9]*)
        echo "JAILSCALE_INDEX_DAYS is a number of days, and this is not one: '$INDEX_DAYS'" >&2
        exit 1 ;;
esac

# An RFC 3339 instant in UTC, $1 days from now. GNU date and BSD date disagree about how to say
# that and agree about nothing useful in their version strings, so this asks GNU's spelling to work
# rather than asking which one this is; macOS's -d takes a daylight-saving argument and fails here.
if date -u -d '+1 day' >/dev/null 2>&1; then
    index_when() { date -u -d "+$1 days" +%Y-%m-%dT%H:%M:%SZ; }
else
    index_when() { date -u -v+"$1"d +%Y-%m-%dT%H:%M:%SZ; }
fi

# Every instant this writes is UTC in one fixed width, which is what makes `sort` a date
# comparison: two of these strings compare chronologically as text, and nothing here has to turn a
# date into a number on a shell that cannot.
index_before() {
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort | head -n 1)" = "$1" ]
}

# One field of the document, or empty. Last occurrence wins, which is what `Updates.Manifest.parse`
# does with a repeated field -- it assigns in a loop and never breaks. A document with two `tag:`
# lines is malformed whichever end you read it from; what must not happen is this tool reading one
# of them and a node reading the other, both reporting success over the same signed bytes.
index_field() {
    sed -n "s/^$2:[[:space:]]*//p" "$1" | tail -n 1
}

# Downloads the current pointer into $2. 0: it is there. 3: there is none -- either the release
# does not exist or it carries no pointer at all, which are the same thing to every caller. 1:
# anything else, which is emphatically not the same thing, because a sequence that restarts because
# a network was down is the sequence rule deleted. Half a pointer is a 1 for that reason too.
index_fetch() {
    _repo=$1
    _dir=$2
    mkdir -p "$_dir"
    # `gh release view`, and not the releases/tags API, because that endpoint does not return a
    # draft: a drafted release-index would read as "there is no pointer" here while index_issue's
    # own `gh release view` found it and uploaded into it. One existence check for one release.
    # The two streams stay apart: this value is compared for equality below, and a gh that writes
    # anything at all to stderr while succeeding -- an update notice, a warning a later version adds
    # -- would otherwise be read as "this release is a draft" and stop everything on a wrong answer.
    if ! _draft=$(gh release view -R "$_repo" "$INDEX_TAG" --json isDraft --jq .isDraft 2>"$_dir/.gh-err"); then
        _err=$(cat "$_dir/.gh-err")
        rm -f "$_dir/.gh-err"
        case $_err in
            # gh exits 1 for a missing release and for a network it could not reach alike, so the
            # reason is read out of the message. Anything else is a failure to look.
            *"not found"*|*404*) return 3 ;;
            *) printf '%s\n' "$_err" >&2; return 1 ;;
        esac
    fi
    rm -f "$_dir/.gh-err"
    if [ "$_draft" != "false" ]; then
        # Never 3: a draft's assets need a token, so this is a pointer that is published to nobody
        # and a sequence that must not be restarted over.
        echo "$INDEX_TAG is a draft. Its assets are not public, so no node can read the pointer;" >&2
        echo "publish that release again before re-issuing." >&2
        return 1
    fi
    # A download that failed is not an absent pointer either, and it is the same distinction: gh
    # says "no assets match the file pattern" when there is nothing there, and everything else it
    # can fail with -- a 5xx from the asset host, a rate limit, a directory it cannot write -- is a
    # failure to look. Returning 3 for those is what would let --first restart the sequence over a
    # pointer that is published and fine.
    if ! _err=$(gh release download -R "$_repo" "$INDEX_TAG" --dir "$_dir" \
        --pattern "$INDEX_FILE" --pattern "$INDEX_SIG" --clobber 2>&1 >/dev/null </dev/null); then
        case $_err in
            *"no assets match"*) return 3 ;;
            *) printf '%s\n' "$_err" >&2; return 1 ;;
        esac
    fi
    if [ -f "$_dir/$INDEX_FILE" ] && [ -f "$_dir/$INDEX_SIG" ]; then
        return 0
    fi
    if [ ! -e "$_dir/$INDEX_FILE" ] && [ ! -e "$_dir/$INDEX_SIG" ]; then
        return 3 # the release is there and carries no pointer at all
    fi
    # One half of a pair: an upload that did not finish, or an asset somebody removed. Never 3 --
    # a sequence must not restart over a document that is still published.
    echo "$INDEX_TAG carries only one half of a pointer; the other asset is missing." >&2
    return 1
}

# Checks a pointer in $1 against the key list in $2 the way a client will, and prints
# "SEQ TAG ISSUED EXPIRES FINGERPRINT" on success. Signature first: everything parsed out of these
# bytes is worth exactly what the signature over them is worth.
index_verify() {
    _dir=$1
    _keys=$2
    _fp=$(verify_with_keys "$_dir/$INDEX_FILE" "$_dir/$INDEX_SIG" "$_keys") || {
        echo "$INDEX_SIG matches none of the keys it was checked against." >&2
        return 1
    }
    head -n 1 "$_dir/$INDEX_FILE" | grep -qx "$INDEX_FORMAT" || {
        echo "$INDEX_FILE is not in a format this reads: $(head -n 1 "$_dir/$INDEX_FILE")" >&2
        return 1
    }
    _seq=$(index_field "$_dir/$INDEX_FILE" seq)
    _tag=$(index_field "$_dir/$INDEX_FILE" tag)
    _issued=$(index_field "$_dir/$INDEX_FILE" issued)
    _expires=$(index_field "$_dir/$INDEX_FILE" expires)
    printf '%s' "$_seq" | grep -qE '^[0-9]+$' || {
        echo "$INDEX_FILE has no seq, or one that is not a number: '$_seq'" >&2
        return 1
    }
    release_tag_ok "$_tag" || {
        echo "$INDEX_FILE names '$_tag', which is not a release tag." >&2
        return 1
    }
    for _t in "$_issued" "$_expires"; do
        printf '%s' "$_t" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' || {
            echo "$INDEX_FILE carries a time this does not read: '$_t'" >&2
            return 1
        }
    done
    index_before "$_issued" "$_expires" || {
        echo "$INDEX_FILE expires ($_expires) before it was issued ($_issued)." >&2
        return 1
    }
    printf '%s %s %s %s %s\n' "$_seq" "$_tag" "$_issued" "$_expires" "$_fp"
}

# Writes, signs, uploads and reads back a pointer naming $3 at sequence $4. $1 is the repository,
# $2 a directory to work in, $5 the public half of the signing key, already fetched.
#
# The order is: write, sign, verify what was signed, upload, download what was uploaded and compare.
# The last step is not ceremony -- an upload that half-happened leaves the assets naming different
# sequences, and every client then sees whichever one it got.
index_issue() {
    _repo=$1
    _work=$2
    _tag=$3
    _seq=$4
    _pub=$5
    command -v kms_sign >/dev/null 2>&1 || {
        echo "index_issue needs tools/kms-key.sh sourced." >&2
        return 1
    }
    _out=$_work/out
    mkdir -p "$_out"
    # Held in variables and checked, because a `date` that fails inside the printf arguments would
    # contribute an empty field and leave printf's own status at 0: `set -e` never sees it, and what
    # gets signed is a document every reader refuses and no script here will replace.
    _now=$(index_when 0)
    _until=$(index_when "$INDEX_DAYS")
    if [ -z "$_now" ] || [ -z "$_until" ]; then
        echo "this system's date could not say what time it is, or what it will be in $INDEX_DAYS days." >&2
        return 1
    fi
    printf '%s\nseq: %s\ntag: %s\nissued: %s\nexpires: %s\n' \
        "$INDEX_FORMAT" "$_seq" "$_tag" "$_now" "$_until" \
        > "$_out/$INDEX_FILE"
    kms_sign "$_out/$INDEX_FILE" "$_out/$INDEX_SIG"
    "$OPENSSL" pkeyutl -verify -pubin -inkey "$_pub" -rawin \
        -in "$_out/$INDEX_FILE" -sigfile "$_out/$INDEX_SIG" >/dev/null || {
        echo "the signature this just made does not verify under the key that made it." >&2
        return 1
    }
    if ! gh release view -R "$_repo" "$INDEX_TAG" >/dev/null 2>&1; then
        echo "creating the $INDEX_TAG release, which has never existed here ..."
        gh release create -R "$_repo" "$INDEX_TAG" --prerelease --title "release index" --notes \
"Not a release, and not something to download a jailscale from.

\`$INDEX_FILE\` is the signed pointer that says which release is current, and its assets are
replaced in place; the tag exists only to give them a stable URL. What it is for, and why it is
signed with the release key, is in [docs/update-freshness](../blob/main/docs/update-freshness/README.md).

A pre-release on purpose: \`releases/latest\` must never point here." >/dev/null
    fi
    # Uploaded until what is published is what was signed. gh sends the two assets one at a time, so
    # a failure between them leaves a new document beside the old signature -- a pointer that
    # verifies for nobody, and one that both scripts here refuse to overwrite, so the state is worst
    # exactly where a person is least able to fix it. Re-uploading the same pair is idempotent,
    # which makes retrying here, while the bytes are still on disk, the whole remedy.
    _try=1
    _back=$_work/back
    while :; do
        gh release upload -R "$_repo" "$INDEX_TAG" "$_out/$INDEX_FILE" "$_out/$INDEX_SIG" --clobber || true
        rm -rf "$_back"
        if index_fetch "$_repo" "$_back" >/dev/null 2>&1 \
            && cmp -s "$_out/$INDEX_FILE" "$_back/$INDEX_FILE" \
            && cmp -s "$_out/$INDEX_SIG" "$_back/$INDEX_SIG"; then
            break
        fi
        if [ "$_try" -ge 3 ]; then
            # The caller's temp directory goes when it exits, and a command naming files that are
            # about to be deleted is not advice. The pair is copied somewhere that survives first.
            _keep=$(mktemp -d)
            cp "$_out/$INDEX_FILE" "$_out/$INDEX_SIG" "$_keep/"
            echo "$INDEX_TAG does not carry what was just signed, after $_try attempts to upload it." >&2
            echo "It may now hold one of the two assets, which verifies for nobody, and this is the" >&2
            echo "one state the checks here will not overwrite. Finish it by hand:" >&2
            echo "  gh release upload -R $_repo $INDEX_TAG $_keep/$INDEX_FILE $_keep/$INDEX_SIG --clobber" >&2
            return 1
        fi
        echo "  what is published is not what was signed; uploading again ($_try) ..."
        _try=$((_try + 1))
    done
    echo
    cat "$_out/$INDEX_FILE"
}

# Which revision's key list a pointer in $2 should be checked against, for a clone at $1.
# $RELEASE_KEYS_REV when something set it (a CI checkout that has no tags), else the tag the pointer
# names, else this clone's HEAD.
#
# It prints the rev rather than setting one and printing the keys, because a caller reads it through
# a command substitution and nothing a subshell assigns comes back.
#
# Reading the tag out of bytes nobody has verified yet decides nothing: the verification is what
# accepts or refuses, every list in this clone's history is one this project shipped, and the worst
# a wrong guess does is fail to verify a pointer that is fine.
index_key_rev() {
    _rev=${RELEASE_KEYS_REV:-}
    if [ -z "$_rev" ]; then
        _rev=$(index_field "$2/$INDEX_FILE" tag)
        git -C "$1" rev-parse -q --verify "$_rev^{commit}" >/dev/null 2>&1 || _rev=HEAD
    fi
    printf '%s\n' "$_rev"
}
