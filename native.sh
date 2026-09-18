#!/bin/sh
# Builds the jailscale and jailhub native binaries with the same toolchain the release uses:
# GraalVM Community Edition on the 25.3 line (ARCHITECTURE.md §3.2).
#
# Usage: ./native.sh [extra mvnw args]
#   ./native.sh -DskipTests              what the release ships
#
# Why the release's toolchain and not whichever GraalVM the machine happens to have: a development
# machine that builds with something else measures something the release does not ship. That is not
# hypothetical -- §14's macOS binary sizes were 4.6 MiB under what v0.1.0 actually shipped for
# exactly that reason, and nothing noticed, because the budget gate only runs on linux.
set -eu

root="$(cd "$(dirname "$0")" && pwd)"

# $GRAALVM_HOME wins: it is how you point this at an installation of your own.
# In a function, so that searching does not disturb "$@" -- these are the caller's mvnw arguments.
first_with_native_image() {
  for candidate in "$@"; do
    if [ -x "$candidate/bin/native-image" ]; then echo "$candidate"; return; fi
  done
}

home=$(first_with_native_image \
  ${GRAALVM_HOME:+"$GRAALVM_HOME"} \
  /Library/Java/JavaVirtualMachines/graalvm-community-25.3*/Contents/Home \
  "$HOME"/Library/Java/JavaVirtualMachines/graalvm-community-25.3*/Contents/Home)

if [ -z "$home" ]; then
  echo "native-image not found. Install GraalVM CE 25.3:" >&2
  echo "" >&2
  # Homebrew's graalvm-jdk cask is Oracle's, not this; the CE builds are GitHub release assets,
  # which is where setup-graalvm finds them too. Pick the asset for your own platform.
  echo '  mkdir -p ~/Library/Java/JavaVirtualMachines' >&2
  echo '  gh release download -R graalvm/graalvm-ce-builds graal-25.3.4.1 \' >&2
  echo '    -p "graalvm-community-jdk-*_macos-aarch64_bin.tar.gz" -O /tmp/ce.tar.gz' >&2
  echo '  tar xzf /tmp/ce.tar.gz -C ~/Library/Java/JavaVirtualMachines' >&2
  echo "" >&2
  echo "or point GRAALVM_HOME at an existing one. Another GraalVM will build the binaries, but the" >&2
  echo "numbers in ARCHITECTURE.md §14 are the release toolchain's." >&2
  exit 1
fi

echo "native-image: $("$home/bin/native-image" --version | tail -1)"

export JAVA_HOME="$home" GRAALVM_HOME="$home"
exec "$root/mvnw" -B -ntp -Pnative package "$@"
