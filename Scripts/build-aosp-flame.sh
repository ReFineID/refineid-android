#!/usr/bin/env bash
# Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

set -euo pipefail
export LC_ALL=C

readonly EXIT_FAILURE=1
readonly EXIT_USAGE=2
readonly EXPECTED_ARGUMENT_COUNT=0
readonly EXPECTED_HOST_KERNEL="Linux"
readonly EXPECTED_HOST_ARCHITECTURE="x86_64"
readonly REQUIRED_BUILD_FREE_SPACE_GIB=150
readonly KIB_PER_GIB=1048576
readonly REQUIRED_BUILD_FREE_SPACE_KIB=$((REQUIRED_BUILD_FREE_SPACE_GIB * KIB_PER_GIB))
readonly REQUIRED_GRADLE_JAVA_FEATURE=26
readonly LUNCH_TARGET="aosp_flame-userdebug"
readonly REFINEID_RELATIVE_PATH="packages/apps/ReFineID"
readonly SHARED_VENDOR_MAKEFILE="vendor/google_devices/coral/proprietary/device-vendor.mk"
readonly GOOGLE_VENDOR_MAKEFILE="vendor/google_devices/flame/device-partial.mk"
readonly QUALCOMM_VENDOR_MAKEFILE="vendor/qcom/flame/device-partial.mk"
readonly BUILT_REFINEID_APK="product/priv-app/ReFineID/ReFineID.apk"
readonly BUILT_KEYCHAIN_APK="system/app/KeyChain/KeyChain.apk"
readonly CERTIFICATE_DIGEST_LABEL="Signer #1 certificate SHA-256 digest"

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
AOSP_ROOT="$(cd "${REPOSITORY_ROOT}/../../.." && pwd -P)"
readonly AOSP_ROOT
readonly EXPECTED_REPOSITORY_ROOT="${AOSP_ROOT}/${REFINEID_RELATIVE_PATH}"

fail() {
  echo "$1" >&2
  exit "$EXIT_FAILURE"
}

signer_digest() {
  local apk="$1"
  "$APKSIGNER" verify --print-certs "$apk" 2>/dev/null |
    awk -F': ' -v label="$CERTIFICATE_DIGEST_LABEL" '$1 == label {print $2; exit}'
}

if [[ "$#" -ne "$EXPECTED_ARGUMENT_COUNT" ]]; then
  echo "usage: $0" >&2
  exit "$EXIT_USAGE"
fi

[[ "$(uname -s)" == "$EXPECTED_HOST_KERNEL" ]] ||
  fail "the Android 13 platform build requires Linux"
[[ "$(uname -m)" == "$EXPECTED_HOST_ARCHITECTURE" ]] ||
  fail "the Android 13 platform build requires x86_64"
[[ -f "${AOSP_ROOT}/build/envsetup.sh" ]] || fail "AOSP build/envsetup.sh is missing"
[[ -d "$EXPECTED_REPOSITORY_ROOT" ]] ||
  fail "ReFineID must be checked out at ${REFINEID_RELATIVE_PATH}"
RESOLVED_EXPECTED_REPOSITORY_ROOT="$(cd "$EXPECTED_REPOSITORY_ROOT" && pwd -P)"
readonly RESOLVED_EXPECTED_REPOSITORY_ROOT
[[ "$RESOLVED_EXPECTED_REPOSITORY_ROOT" == "$REPOSITORY_ROOT" ]] ||
  fail "this repository must be the AOSP packages/apps/ReFineID checkout"

FREE_SPACE_KIB="$(df -Pk "$AOSP_ROOT" | awk 'NR == 2 {print $4}')"
readonly FREE_SPACE_KIB
[[ "$FREE_SPACE_KIB" =~ ^[0-9]+$ ]] || fail "could not measure AOSP build storage"
[[ "$FREE_SPACE_KIB" -ge "$REQUIRED_BUILD_FREE_SPACE_KIB" ]] ||
  fail "the synced tree needs at least ${REQUIRED_BUILD_FREE_SPACE_GIB} GiB free to build"

[[ -n "${JAVA_HOME:-}" ]] || fail "JAVA_HOME must select OpenJDK 26 for the app build"
[[ -x "${JAVA_HOME}/bin/java" ]] || fail "JAVA_HOME does not contain java"
JAVA_FEATURE="$(
  "${JAVA_HOME}/bin/java" -XshowSettings:properties -version 2>&1 |
    awk -F= '/java.specification.version/ {gsub(/[[:space:]]/, "", $2); print $2}'
)"
readonly JAVA_FEATURE
[[ "$JAVA_FEATURE" == "$REQUIRED_GRADLE_JAVA_FEATURE" ]] ||
  fail "JAVA_HOME must select OpenJDK ${REQUIRED_GRADLE_JAVA_FEATURE}"

[[ -f "${AOSP_ROOT}/${SHARED_VENDOR_MAKEFILE}" ]] ||
  fail "the shared Pixel 4 vendor makefile is missing"
[[ -f "${AOSP_ROOT}/${GOOGLE_VENDOR_MAKEFILE}" ]] ||
  fail "the licensed Google Pixel 4 vendor files are missing"
[[ -f "${AOSP_ROOT}/${QUALCOMM_VENDOR_MAKEFILE}" ]] ||
  fail "the licensed Qualcomm Pixel 4 vendor files are missing"

"${REPOSITORY_ROOT}/Scripts/apply-aosp-patches.sh" --check-applied "$AOSP_ROOT"
"${REPOSITORY_ROOT}/Scripts/stage-aosp-prebuilt.sh"

unset JAVA_HOME
cd "$AOSP_ROOT"
# shellcheck source=/dev/null
source build/envsetup.sh
lunch "$LUNCH_TARGET"
m ReFineID KeyChain framework-minus-apex apksigner
m

[[ -n "${ANDROID_PRODUCT_OUT:-}" ]] || fail "Android product output is unset"
readonly PRODUCT_APK="${ANDROID_PRODUCT_OUT}/${BUILT_REFINEID_APK}"
readonly KEYCHAIN_APK="${ANDROID_PRODUCT_OUT}/${BUILT_KEYCHAIN_APK}"
[[ -f "$PRODUCT_APK" ]] || fail "the product image is missing ReFineID"
[[ -f "$KEYCHAIN_APK" ]] || fail "the product image is missing KeyChain"
APKSIGNER="$(find "${AOSP_ROOT}/out/host" -type f -name apksigner -perm -u+x -print -quit)"
readonly APKSIGNER
[[ -x "$APKSIGNER" ]] || fail "the AOSP host apksigner is missing"
"$APKSIGNER" verify "$PRODUCT_APK" >/dev/null || fail "the product ReFineID APK is not signed"
"$APKSIGNER" verify "$KEYCHAIN_APK" >/dev/null || fail "the product KeyChain APK is not signed"
REFINEID_SIGNER_DIGEST="$(signer_digest "$PRODUCT_APK")"
readonly REFINEID_SIGNER_DIGEST
KEYCHAIN_SIGNER_DIGEST="$(signer_digest "$KEYCHAIN_APK")"
readonly KEYCHAIN_SIGNER_DIGEST
[[ -n "$REFINEID_SIGNER_DIGEST" ]] || fail "the ReFineID signer cannot be identified"
[[ "$REFINEID_SIGNER_DIGEST" == "$KEYCHAIN_SIGNER_DIGEST" ]] ||
  fail "ReFineID and KeyChain are not signed by the same platform certificate"

echo "aosp_flame_image=ready"
