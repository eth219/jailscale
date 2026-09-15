# Verifying a release by hand

`jailscale update --download` does everything on this page for you: it picks
the right target, verifies `SHA256SUMS.txt` against the Ed25519 signature
published beside it, verifies the binary against that file, and prints the one
command that installs it. This page is for checking a download without a
`jailscale` on the machine, or for checking what the binary checked. The
reasoning behind the scheme is in
[ARCHITECTURE.md §9.4](ARCHITECTURE.md).

## What is signed

Every release carries `SHA256SUMS.txt`, `RELEASE.txt` and `RELEASE.txt.sig`.
`RELEASE.txt` is the only thing signed. It names the release's tag and the
SHA-256 of `SHA256SUMS.txt`, rather than being the checksum list itself, which
on its own would say nothing about *which* release it belongs to; signing the
list alone would let anyone who can publish republish an old, genuinely signed
release under a newer number.

The signing key lives in Cloud KMS and is used from the maintainer's own
machine after the build, never from the release workflow. Its public half is
compiled into the binary, so a build that carries no key refuses to download
rather than trusting the checksum file alone. The release workflow leaves a
draft; publishing is the signing script's job, and the `published` workflow
runs `tools/verify-release.sh` the moment a release goes public and puts one
back into draft if the signature does not hold. So a release that is published
is one that has been signed.

## What says which release is current

A release's `RELEASE.txt` says which release it *is*. Which one is *current* is
a second signed document, `latest.txt`, under the fixed `release-index`
pre-release: a sequence number, the tag, and an expiry, signed with the same
key (`docs/update-freshness`). That is what `jailscale update` reads — not
`releases/latest`, which nothing signs — and a node refuses a pointer whose
sequence is below the highest it has seen, so an old one cannot be put back up
in front of it. Past the expiry a node says it cannot tell whether it is
current rather than that it is up to date.

```sh
base=https://github.com/eth219/jailscale/releases/download/release-index
curl -fsSL -O "$base/latest.txt" -O "$base/latest.txt.sig"
openssl pkeyutl -verify -pubin -inkey release-key.pem -rawin \
  -in latest.txt -sigfile latest.txt.sig
cat latest.txt        # the tag it names is the release to install
```

## From a clone

```sh
tools/verify-release.sh v0.2.0          # downloads the three files with gh
tools/verify-release.sh v0.2.0 ./dir    # checks files already downloaded
tools/verify-release.sh --index         # the signed pointer, and how long it has left
tools/verify-release.sh --index ./dir
```

It checks a release the way the node does, against the key list that tag's own
`ReleaseKey.java` names.

## By hand

```sh
base=https://github.com/eth219/jailscale/releases/download/v0.2.0
curl -fsSL -O "$base/RELEASE.txt" -O "$base/RELEASE.txt.sig" -O "$base/SHA256SUMS.txt"
openssl pkeyutl -verify -pubin -inkey release-key.pem -rawin \
  -in RELEASE.txt -sigfile RELEASE.txt.sig    # the tag in it must be the one you downloaded
shasum -a 256 SHA256SUMS.txt                  # must equal the sha256sums: line in RELEASE.txt
shasum -a 256 --ignore-missing -c SHA256SUMS.txt
```

Keep the release's own filename until the checksum has been checked. Renaming
a binary on the way down leaves nothing in `SHA256SUMS.txt` to match, and
`--ignore-missing` then reports success for having verified nothing.

The public key is in
[`ReleaseKey.java`](../node/src/main/java/io/jailscale/node/ReleaseKey.java),
base64 of the DER SubjectPublicKeyInfo. To turn it into the PEM file above:

```sh
base64 -d > release-key.der            # paste the base64 from ReleaseKey.java
openssl pkey -pubin -inform DER -in release-key.der -out release-key.pem
```

## Build provenance

Separately, every released file carries a build attestation, which says which
workflow built it rather than who approved it:

```sh
gh attestation verify jailscale-darwin-arm64 --repo eth219/jailscale
```

This is Sigstore keyless signing. It is deliberately not what `--download`
checks: the identity it binds is the workflow's, so an account that has been
taken over can run the workflow and obtain a valid attestation for a binary of
its choosing. It answers "what built this"; the release key answers "who
approved this".

## Code signing

The binaries are not code-signed. That does not affect a `curl` download, but
macOS quarantines what a browser downloaded, and Windows SmartScreen warns for
the same reason:

```sh
xattr -d com.apple.quarantine jailscale
```
