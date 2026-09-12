#!/bin/sh
# Builds the jailscale and jailhub native binaries with the same toolchain the release uses:
# Liberica NIK for JDK 25 (ARCHITECTURE.md §3.2).
#
# Usage: ./native.sh [extra mvnw args]
#   ./native.sh -DskipTests              what the release ships
#   ./native.sh -DskipTests -Ppgo        profile-guided, needs Oracle GraalVM (see below)
#
# Why the release's toolchain and not whichever GraalVM the machine happens to have: a development
# machine that builds with something else measures something the release does not ship. That is not
# hypothetical -- §14's macOS binary sizes were 4.7 MiB under what v0.1.0 actually shipped for
# exactly that reason, and nothing noticed, because the budget gate only runs on linux.
#
# -Ppgo builds against the profiles committed under profiles/ and needs Oracle GraalVM, which is
# not what the release uses: profile-guided optimization is a local option here, worth 10 MiB and a
# fifth of the idle RSS, and worth CPU only on the platform the profile was collected on (§14,
# profiles/README.md). Installing Oracle GraalVM means agreeing to the GraalVM Free Terms and
# Conditions: https://www.oracle.com/downloads/licenses/graal-free-license.html
set -eu

root="$(cd "$(dirname "$0")" && pwd)"

# -Ppgo needs Oracle GraalVM; everything else wants the release's Liberica NIK. Pick by what was
# asked for, so neither choice silently builds with the other one's toolchain.
want=nik
for arg in "$@"; do
  case "$arg" in -Ppgo|-Ppgo,*|*,pgo|*,pgo,*|-Ppgo-instrument*) want=oracle ;; esac
done

# $GRAALVM_HOME wins in both cases: it is how you point this at an installation of your own.
# In a function, so that searching does not disturb "$@" -- these are the caller's mvnw arguments.
first_with_native_image() {
  for candidate in "$@"; do
    if [ -x "$candidate/bin/native-image" ]; then echo "$candidate"; return; fi
  done
}

if [ "$want" = oracle ]; then
  name="Oracle GraalVM for JDK 25"
  home=$(first_with_native_image \
    ${GRAALVM_HOME:+"$GRAALVM_HOME"} \
    /Library/Java/JavaVirtualMachines/graalvm-jdk-25*/Contents/Home \
    "$HOME"/Library/Java/JavaVirtualMachines/graalvm-jdk-25*/Contents/Home)
  install_hint='  brew install --cask graalvm-jdk@25'
else
  name="Liberica NIK for JDK 25"
  home=$(first_with_native_image \
    ${GRAALVM_HOME:+"$GRAALVM_HOME"} \
    /Library/Java/JavaVirtualMachines/bellsoft-liberica-vm-openjdk25*/Contents/Home \
    "$HOME"/Library/Java/JavaVirtualMachines/bellsoft-liberica-vm-openjdk25*/Contents/Home)
  # Liberica NIK is not on Homebrew and BellSoft's release API only serves NIK up to JDK 21; the
  # JDK 25 line is published as GitHub release assets, which is also where setup-graalvm finds it.
  install_hint='  mkdir -p ~/Library/Java/JavaVirtualMachines
  gh release download -R bell-sw/LibericaNIK -p "bellsoft-liberica-vm-openjdk25*macos-aarch64.tar.gz" -O /tmp/nik.tar.gz
  tar xzf /tmp/nik.tar.gz -C ~/Library/Java/JavaVirtualMachines'
fi

if [ -z "$home" ]; then
  echo "native-image not found. Install $name:" >&2
  echo "" >&2
  echo "$install_hint" >&2
  echo "" >&2
  echo "or point GRAALVM_HOME at an existing one. Another GraalVM will build the binaries, but the" >&2
  echo "numbers in ARCHITECTURE.md §14 are the release toolchain's." >&2
  exit 1
fi

echo "native-image: $("$home/bin/native-image" --version | tail -1)"

if [ "$want" = oracle ]; then
  # The committed profiles are gzipped: they are JSON and compress about six to one, which keeps a
  # refresh at a megabyte of history instead of six. native-image reads the plain file, so unpack
  # whichever are missing or stale.
  for gz in "$root"/profiles/*.iprof.gz; do
    [ -f "$gz" ] || continue
    plain="${gz%.gz}"
    if [ ! -f "$plain" ] || [ "$gz" -nt "$plain" ]; then
      gunzip -c "$gz" > "$plain"
    fi
  done
fi

export JAVA_HOME="$home" GRAALVM_HOME="$home"
exec "$root/mvnw" -B -ntp -Pnative package "$@"
