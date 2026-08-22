#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

set -euo pipefail
cd "$(dirname "$0")/.."

# Set JAVA_HOME if not already set, preferring the Android Studio bundled JDK on macOS.
if [[ -z "${JAVA_HOME:-}" ]] && [[ "$(uname)" == "Darwin" ]]; then
  studio_jdk="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
  if [[ -d "${studio_jdk}" ]]; then
    export JAVA_HOME="${studio_jdk}"
  fi
fi

# Ensure the current branch is main.
branch=$(git rev-parse --abbrev-ref HEAD)
if [[ "${branch}" != "main" ]]; then
  echo "Error: Release must be performed from the 'main' branch." >&2
  exit 1
fi

# Prevent uncommitted changes from being released accidentally.
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Error: Working directory is not clean. Commit or stash changes first." >&2
  exit 1
fi

echo "Stamping version..."
./Scripts/stamp-version.sh

echo "Running compliance checks..."
./gradlew check

echo "Building signed production APK for website distribution..."
./gradlew app:assembleRelease

echo "Release APK generated successfully."
echo "Location: app/build/outputs/apk/release/app-release.apk"
