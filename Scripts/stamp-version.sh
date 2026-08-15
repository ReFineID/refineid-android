#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

# Stamp the same release pair used by ReFineID-Apple:
#
#   versionName = YY.M.D
#   buildNumber = H * 10 + M / 10
#
# Every component is UTC and the date has no zero padding. Gradle derives the
# globally increasing Android versionCode as YYMMDD000 + buildNumber.

set -euo pipefail
cd "$(dirname "$0")/.."

read -r yy mm dd hh mn <<<"$(date -u '+%y %m %d %H %M')"
version="${yy}.$((10#$mm)).$((10#$dd))"
build=$((10#$hh * 10 + 10#$mn / 10))
version_code=$((10#$yy * 10000000 + 10#$mm * 100000 + 10#$dd * 1000 + build))

case "${1:-}" in
  --dry-run)
    echo "would stamp ${version} (${build}), versionCode ${version_code}"
    exit 0
    ;;
  "") ;;
  *)
    echo "unknown argument: ${1}" >&2
    exit 2
    ;;
esac

properties="version.properties"
[[ "$(grep -c '^versionName=' "$properties")" -eq 1 ]] || {
  echo "${properties} must contain exactly one versionName" >&2
  exit 1
}
[[ "$(grep -c '^buildNumber=' "$properties")" -eq 1 ]] || {
  echo "${properties} must contain exactly one buildNumber" >&2
  exit 1
}

temporary="$(mktemp "${properties}.tmp.XXXXXX")"
trap 'rm -f "$temporary"' EXIT
chmod 0644 "$temporary"
awk -v version="$version" -v build="$build" '
  /^versionName=/ { print "versionName=" version; next }
  /^buildNumber=/ { print "buildNumber=" build; next }
  { print }
' "$properties" >"$temporary"
mv "$temporary" "$properties"
trap - EXIT

if ! grep -q "^versionName=${version}$" "$properties" ||
  ! grep -q "^buildNumber=${build}$" "$properties"; then
  echo "stamp did not take in ${properties}" >&2
  exit 1
fi

echo "stamped ${version} (${build}), versionCode ${version_code}"
