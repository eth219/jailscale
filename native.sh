#!/bin/sh
# Builds the jailscale and jailhub native binaries with the same toolchain the release uses:
# Oracle GraalVM for JDK 25 (ARCHITECTURE.md §3.2).
#
# Usage: ./native.sh [extra mvnw args]
#   ./native.sh -DskipTests              a plain build
#   ./native.sh -DskipTests -Ppgo        with the profiles committed under profiles/ (§14)
#
# Why this toolchain and not the Community Edition keg this script used to default to: the release
# is built with Oracle GraalVM, and a development machine that builds with something else measures
# something the release does not ship. That is not hypothetical -- §14's macOS binary sizes were
# 4.7 MiB under what v0.1.0 actually shipped for exactly that reason, and nothing noticed because
# the budget gate only ran on linux. PGO needs Oracle GraalVM too; it is not in the CE.
#
# Installing it means agreeing to the GraalVM Free Terms and Conditions, which is also the licence
# the released binaries carry: https://www.oracle.com/downloads/licenses/graal-free-license.html
set -eu

# $GRAALVM_HOME wins, then the Homebrew cask, then a tarball unpacked into the user's JVM directory.
for candidate in \
  "${GRAALVM_HOME:-}" \
  /Library/Java/JavaVirtualMachines/graalvm-25.jdk/Contents/Home \
  "$HOME"/Library/Java/JavaVirtualMachines/graalvm-jdk-25*/Contents/Home
do
  [ -n "$candidate" ] || continue
  if [ -x "$candidate/bin/native-image" ]; then
    GRAALVM_HOME="$candidate"
    break
  fi
done

if [ ! -x "${GRAALVM_HOME:-}/bin/native-image" ]; then
  cat >&2 <<'MSG'
native-image not found. Install Oracle GraalVM for JDK 25, either

  brew install --cask graalvm-jdk@25

or, without sudo,

  mkdir -p ~/Library/Java/JavaVirtualMachines
  curl -fsSL https://download.oracle.com/graalvm/25/latest/graalvm-jdk-25_macos-aarch64_bin.tar.gz \
    | tar xz -C ~/Library/Java/JavaVirtualMachines

or point GRAALVM_HOME at an existing one. A Community Edition GraalVM will build the binaries but
not with a profile: PGO is not in the CE, and the numbers in ARCHITECTURE.md §14 are the release
toolchain's.
MSG
  exit 1
fi

echo "native-image: $("$GRAALVM_HOME/bin/native-image" --version | tail -1)"

# The committed profiles are gzipped: they are JSON and compress about six to one, which keeps a
# refresh at a megabyte of history instead of six. native-image reads the plain file, so unpack
# whichever are missing or stale.
root="$(cd "$(dirname "$0")" && pwd)"
for gz in "$root"/profiles/*.iprof.gz; do
  [ -f "$gz" ] || continue
  plain="${gz%.gz}"
  if [ ! -f "$plain" ] || [ "$gz" -nt "$plain" ]; then
    gunzip -c "$gz" > "$plain"
  fi
done

export JAVA_HOME="$GRAALVM_HOME" GRAALVM_HOME
exec "$(dirname "$0")/mvnw" -B -ntp -Pnative package "$@"
