# Resolves the Cloud KMS key version that signs releases (ARCHITECTURE.md §9.4). Sourced, not run.
#
# The key is named by $JAILSCALE_KMS_KEY, or by the one line in ~/.jailscale-release/kms-key that
# tools/release-key.sh writes. It is deliberately not a constant in this repository: a fork running
# its own hub signs with its own key, and nothing here should imply that one particular cloud
# project is what a jailscale release means.
#
# Sets KMS_PROJECT, KMS_LOCATION, KMS_KEYRING, KMS_KEY, KMS_VERSION, and defines kms_sign and
# kms_public_key.
KMS_CONFIG=${JAILSCALE_KMS_CONFIG:-$HOME/.jailscale-release/kms-key}
kms_name=${JAILSCALE_KMS_KEY:-}
if [ -z "$kms_name" ] && [ -r "$KMS_CONFIG" ]; then
    kms_name=$(tr -d ' \t\n' < "$KMS_CONFIG")
fi
if [ -z "$kms_name" ]; then
    echo "no release key configured. Set JAILSCALE_KMS_KEY, or run tools/release-key.sh to make one." >&2
    echo "It looks like:" >&2
    echo "  projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1" >&2
    exit 1
fi
command -v gcloud >/dev/null 2>&1 || { echo "this needs the gcloud CLI, logged in as the release account." >&2; exit 1; }

# One sed each rather than a split on "/", so a name in the wrong shape produces an empty field and
# the check below names it, instead of silently signing with whatever the components happened to be.
KMS_PROJECT=$(printf '%s' "$kms_name" | sed -n 's#^projects/\([^/]*\)/.*#\1#p')
KMS_LOCATION=$(printf '%s' "$kms_name" | sed -n 's#.*/locations/\([^/]*\)/.*#\1#p')
KMS_KEYRING=$(printf '%s' "$kms_name" | sed -n 's#.*/keyRings/\([^/]*\)/.*#\1#p')
KMS_KEY=$(printf '%s' "$kms_name" | sed -n 's#.*/cryptoKeys/\([^/]*\).*#\1#p')
KMS_VERSION=$(printf '%s' "$kms_name" | sed -n 's#.*/cryptoKeyVersions/\([^/]*\)$#\1#p')
KMS_VERSION=${KMS_VERSION:-1}
for _f in "$KMS_PROJECT" "$KMS_LOCATION" "$KMS_KEYRING" "$KMS_KEY"; do
    if [ -z "$_f" ]; then
        echo "this is not a KMS key version name: $kms_name" >&2
        exit 1
    fi
done
export KMS_PROJECT KMS_LOCATION KMS_KEYRING KMS_KEY KMS_VERSION

# The signature over $1, written to $2. Ed25519 in Cloud KMS is PureEdDSA, so there is no
# --digest-algorithm here and the whole file is the message; the output is the raw 64 bytes that
# ReleaseKey verifies, despite what `gcloud kms asymmetric-sign --help` says about base64.
kms_sign() {
    gcloud kms asymmetric-sign --project="$KMS_PROJECT" --location="$KMS_LOCATION" \
        --keyring="$KMS_KEYRING" --key="$KMS_KEY" --version="$KMS_VERSION" \
        --input-file="$1" --signature-file="$2"
}

kms_public_key() {
    gcloud kms keys versions get-public-key "$KMS_VERSION" --project="$KMS_PROJECT" \
        --location="$KMS_LOCATION" --keyring="$KMS_KEYRING" --key="$KMS_KEY" --output-file="$1"
}
