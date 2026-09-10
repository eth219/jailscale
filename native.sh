#!/bin/sh
# Builds the jailscale and jailhub native binaries with the Homebrew GraalVM CE keg.
# Usage: ./native.sh [extra mvnw args]     e.g. ./native.sh -DskipTests
set -eu
: "${GRAALVM_HOME:=/opt/homebrew/opt/graalvm/libexec/graalvm.jdk/Contents/Home}"
if [ ! -x "$GRAALVM_HOME/bin/native-image" ]; then
  echo "native-image not found under $GRAALVM_HOME (brew install graalvm)" >&2
  exit 1
fi
export JAVA_HOME="$GRAALVM_HOME" GRAALVM_HOME
exec "$(dirname "$0")/mvnw" -B -ntp -Pnative package "$@"
