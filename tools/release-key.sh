#!/usr/bin/env sh
# Makes the Cloud KMS key that releases are signed with (ARCHITECTURE.md §9.4), and prints its
# public half in the form ReleaseKey.PUBLIC_KEYS wants.
#
#   tools/release-key.sh PROJECT [LOCATION] [KEYRING] [KEY]
#
# Run once. Cloud KMS rather than a file on a laptop: the private half is never on the machine that
# runs this, so nothing that gets onto that machine between releases can read it, every use is in
# Cloud Audit Logs, and a key that is believed compromised can be disabled rather than lived with.
# What it does not do is make a compromised laptop safe -- whoever holds the gcloud credentials can
# ask KMS to sign -- which is why signing is one command a person runs and looks at, not a step in
# a pipeline.
#
# NEVER grant this key to GitHub Actions, by Workload Identity Federation or any other route. A
# signature the release pipeline can make is worth exactly what the checksums beside it are worth,
# which is the reason this key exists at all. The provenance attestation in release.yml is the CI
# side of the story and is already there.
set -eu

project=${1:-}
location=${2:-asia-northeast3}
keyring=${3:-release}
key=${4:-signing}
if [ -z "$project" ]; then
    echo "usage: tools/release-key.sh PROJECT [LOCATION] [KEYRING] [KEY]" >&2
    exit 2
fi
command -v gcloud >/dev/null 2>&1 || { echo "this needs the gcloud CLI, logged in as the release account." >&2; exit 1; }

config=${JAILSCALE_KMS_CONFIG:-$HOME/.jailscale-release/kms-key}
if [ -e "$config" ]; then
    echo "$config already names a release key:" >&2
    cat "$config" >&2
    echo "Move it aside if you really mean to replace it. Every binary carrying the old public key" >&2
    echo "stops accepting downloads the moment you release under a different one." >&2
    exit 1
fi

gcloud services enable cloudkms.googleapis.com --project="$project"
gcloud kms keyrings create "$keyring" --location="$location" --project="$project" 2>/dev/null || true
# Asymmetric signing keys are not rotated on a schedule, and this one must not be: the public half
# is compiled into every binary, so a new version is a release, not a cron job.
gcloud kms keys create "$key" --location="$location" --keyring="$keyring" --project="$project" \
    --purpose=asymmetric-signing --default-algorithm=ec-sign-ed25519 --protection-level=software \
    --destroy-scheduled-duration=30d 2>/dev/null || true

name="projects/$project/locations/$location/keyRings/$keyring/cryptoKeys/$key/cryptoKeyVersions/1"
mkdir -p "$(dirname "$config")"
printf '%s\n' "$name" > "$config"

. "$(dirname "$0")/openssl-ed25519.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gcloud kms keys versions get-public-key 1 --project="$project" --location="$location" \
    --keyring="$keyring" --key="$key" --output-file="$tmp/pub.pem"
spki=$("$OPENSSL" pkey -pubin -in "$tmp/pub.pem" -outform DER | base64 | tr -d '\n')
fingerprint=$("$OPENSSL" pkey -pubin -in "$tmp/pub.pem" -outform DER | "$OPENSSL" dgst -sha256 -binary \
    | od -An -tx1 | tr -d ' \n' | cut -c1-16)

cat <<EOF

key           $name
fingerprint   $fingerprint
recorded in   $config

Paste this into ReleaseKey.PUBLIC_KEYS, commit it, and release from that commit:

    static final List<String> PUBLIC_KEYS = List.of(
        "$spki");

Until a build carries it, \`jailscale update --download\` refuses to download rather than
falling back to the checksum alone.

To ROTATE later, do not replace the entry: add the new key beside the old one, ship a release
signed with the OLD key, and only sign with the new one from the release after that. Binaries in
the field accept the list they were built with, so a key that appears and is used in the same
release is a key nothing out there has heard of.
EOF
