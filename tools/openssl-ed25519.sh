# Finds an openssl that can sign with Ed25519, and sets $OPENSSL to it. Sourced, not run.
#
# macOS ships LibreSSL under the name openssl, and it does not do `pkeyutl -rawin`. Asking the
# version string is not enough -- the answer differs across LibreSSL releases -- so this signs and
# verifies a scratch message with each candidate and keeps the first that works.
_ed25519_works() {
    _d=$(mktemp -d)
    if "$1" genpkey -algorithm ed25519 -out "$_d/k.pem" 2>/dev/null \
        && printf 'x' > "$_d/m" \
        && "$1" pkeyutl -sign -inkey "$_d/k.pem" -rawin -in "$_d/m" -out "$_d/s" 2>/dev/null \
        && "$1" pkey -in "$_d/k.pem" -pubout -out "$_d/p.pem" 2>/dev/null \
        && "$1" pkeyutl -verify -pubin -inkey "$_d/p.pem" -rawin -in "$_d/m" -sigfile "$_d/s" >/dev/null 2>&1; then
        rm -rf "$_d"
        return 0
    fi
    rm -rf "$_d"
    return 1
}

OPENSSL=""
for _c in "${OPENSSL_BIN:-}" openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
    [ -n "$_c" ] || continue
    command -v "$_c" >/dev/null 2>&1 || continue
    if _ed25519_works "$_c"; then
        OPENSSL="$_c"
        break
    fi
done

if [ -z "$OPENSSL" ]; then
    echo "no openssl here can sign with Ed25519 (macOS ships LibreSSL, which cannot)." >&2
    echo "Install OpenSSL 3 -- brew install openssl@3 -- or set OPENSSL_BIN to one." >&2
    exit 1
fi
export OPENSSL

# The two forms of a public key that this project passes around, from a PEM file: the base64 DER
# SubjectPublicKeyInfo that ReleaseKey.PUBLIC_KEYS holds, and the fingerprint ReleaseKey prints --
# the first eight bytes of SHA-256 over that DER, as sixteen hex characters. Defined once so the
# key that release-key.sh tells you to paste and the one sign-release.sh says it signed with are
# computed the same way, and both match what the binary prints.
spki_base64() {
    "$OPENSSL" pkey -pubin -in "$1" -outform DER | base64 | tr -d '\n'
}
spki_fingerprint() {
    "$OPENSSL" pkey -pubin -in "$1" -outform DER | "$OPENSSL" dgst -sha256 -binary | od -An -tx1 \
        | tr -d ' \n' | cut -c1-16
}

# Verifies $2 as a signature over $1 under any one of the base64 SPKI keys in $3, and prints the
# fingerprint of the key that worked. Defined here rather than in each caller because "any key on
# the list may sign" is the rule ReleaseKey applies in the node, and a second copy of it is a
# second chance to apply it to a different list or to stop at the first key.
verify_with_keys() {
    _v=$(mktemp -d)
    for _spki in $3; do
        printf '%s' "$_spki" | base64 -d > "$_v/key.der" 2>/dev/null || continue
        "$OPENSSL" pkey -pubin -inform DER -in "$_v/key.der" -out "$_v/key.pem" 2>/dev/null || continue
        if "$OPENSSL" pkeyutl -verify -pubin -inkey "$_v/key.pem" -rawin \
            -in "$1" -sigfile "$2" >/dev/null 2>&1; then
            spki_fingerprint "$_v/key.pem"
            rm -rf "$_v"
            return 0
        fi
    done
    rm -rf "$_v"
    return 1
}
