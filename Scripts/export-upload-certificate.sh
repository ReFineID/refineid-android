#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

set -euo pipefail
cd "$(dirname "$0")/.."

pkcs11_lib="${REFINEID_PKCS11_LIB:-/usr/local/lib/librefineid_pkcs11_sign.dylib}"
output_cert="${1:-upload_cert.pem}"

if [[ ! -f "${pkcs11_lib}" ]]; then
  if [[ -f "/Library/OpenSC/lib/opensc-pkcs11.so" ]]; then
    pkcs11_lib="/Library/OpenSC/lib/opensc-pkcs11.so"
  elif [[ -f "/usr/local/lib/opensc-pkcs11.so" ]]; then
    pkcs11_lib="/usr/local/lib/opensc-pkcs11.so"
  else
    echo "Error: PKCS#11 module not found at ${pkcs11_lib}" >&2
    echo "Set REFINEID_PKCS11_LIB environment variable to the path of your PKCS#11 driver." >&2
    exit 1
  fi
fi

if ! command -v pkcs11-tool >/dev/null 2>&1; then
  echo "Error: pkcs11-tool is required to extract certificate. Install OpenSC (e.g. brew install opensc)." >&2
  exit 1
fi

temporary_der="$(mktemp /tmp/cert_der.XXXXXX)"
trap 'rm -f "${temporary_der}"' EXIT

echo "Reading qualified signing certificate (PIN 2) from hardware card..."
pkcs11_tool_cmd=(pkcs11-tool --module "${pkcs11_lib}" --read-object --type cert)

if pkcs11-tool --module "${pkcs11_lib}" --list-objects | grep -qi "Sign"; then
  "${pkcs11_tool_cmd[@]}" --label "Sign" --output-file "${temporary_der}" 2>/dev/null || \
  "${pkcs11_tool_cmd[@]}" --output-file "${temporary_der}"
else
  "${pkcs11_tool_cmd[@]}" --output-file "${temporary_der}"
fi

openssl x509 -inform der -in "${temporary_der}" -out "${output_cert}"
chmod 0644 "${output_cert}"

echo "Public upload certificate exported successfully to: ${output_cert}"
echo ""
echo "Certificate details:"
openssl x509 -in "${output_cert}" -noout -subject -issuer -dates -fingerprint -sha256
echo ""
echo "To register or rotate in Google Play Console:"
echo "1. Open Google Play Console -> Setup -> App Integrity -> Play App Signing"
echo "2. Upload ${output_cert} as your Upload Key Certificate."
