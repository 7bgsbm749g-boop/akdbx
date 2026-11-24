#!/bin/sh
# Build the akdbx Android helper dex from source.
# Needs JDK 17 (javac) and Android build-tools 35.0.0 (d8) with platform 35.
#   JAVA_HOME=/path/to/jdk ANDROID_SDK=/path/to/sdk android/helper/build.sh
# The output is src/akdbx/android_assets/akdbx-android-helper.dex (or the file
# named by AKDBX_HELPER_OUTPUT). After a change, set HELPER_SHA256 in
# src/akdbx/android_route.py to the printed hash and run
#   AKDBX_UPDATE_ANDROID_HELPER=1 python -m pytest -q tests/test_android_route.py -k helper
# once to record the source hash.
set -eu
here="$(cd -- "$(dirname -- "$0")" && pwd)"
repo="$(cd -- "$here/../.." && pwd)"
: "${JAVA_HOME:?set JAVA_HOME to a JDK 17}"
: "${ANDROID_SDK:?set ANDROID_SDK to an Android SDK with build-tools 35.0.0 and platforms/android-35}"
jar="$ANDROID_SDK/platforms/android-35/android.jar"
d8="$ANDROID_SDK/build-tools/35.0.0/d8"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/classes" "$work/dex"
find "$here/src" -name '*.java' | LC_ALL=C sort > "$work/sources"
"$JAVA_HOME/bin/javac" -encoding UTF-8 --release 8 -nowarn -g:none -cp "$jar" -d "$work/classes" @"$work/sources" 2>&1 \
  | grep -v 'warning: \[options\]' || true
find "$work/classes" -name '*.class' | LC_ALL=C sort > "$work/classlist"
[ -s "$work/classlist" ] || { echo "javac produced no classes" >&2; exit 1; }
# Fixed file times keep the build reproducible.
find "$work/classes" -exec touch -h -d '2000-01-01T00:00:00Z' {} +
PATH="$JAVA_HOME/bin:$PATH" "$d8" --release --min-api 30 --lib "$jar" --output "$work/dex" $(cat "$work/classlist")
output="${AKDBX_HELPER_OUTPUT:-$repo/src/akdbx/android_assets/akdbx-android-helper.dex}"
mkdir -p "$(dirname -- "$output")"
cp "$work/dex/classes.dex" "$output"
sha256sum "$output"
