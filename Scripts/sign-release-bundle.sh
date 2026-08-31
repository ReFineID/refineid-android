#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Signs an Android App Bundle (.aab) with the developer's hardware identity card
# Qualified Signing Key (PIN 2) via the PKCS#11 provider.
#
# Security: The PIN 2 is never stored, hardcoded, or saved to disk. It is entered
# interactively via terminal prompt, environment variable (PIN2), or hardware reader pinpad.

set -euo pipefail
cd "$(dirname "$0")/.."

# Set JAVA_HOME if not already set.
if [[ -z "${JAVA_HOME:-}" ]] && [[ "$(uname)" == "Darwin" ]]; then
  studio_jdk="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
  if [[ -d "${studio_jdk}" ]]; then
    export JAVA_HOME="${studio_jdk}"
  else
    export JAVA_HOME="$(/usr/libexec/java_home 2>/dev/null || echo "/opt/homebrew/opt/openjdk")"
  fi
fi

bundle_path="${1:-app/build/outputs/bundle/release/app-release.aab}"

if [[ ! -f "${bundle_path}" ]]; then
  echo "Error: Bundle file not found at ${bundle_path}" >&2
  echo "Run './gradlew bundleRelease' first." >&2
  exit 1
fi

pkcs11_lib="${REFINEID_PKCS11_LIB:-/usr/local/lib/librefineid_pkcs11_sign.dylib}"
if [[ ! -f "${pkcs11_lib}" ]]; then
  if [[ -f "/Library/OpenSC/lib/opensc-pkcs11.so" ]]; then
    pkcs11_lib="/Library/OpenSC/lib/opensc-pkcs11.so"
  elif [[ -f "/usr/local/lib/opensc-pkcs11.so" ]]; then
    pkcs11_lib="/usr/local/lib/opensc-pkcs11.so"
  else
    echo "Error: PKCS#11 module not found at ${pkcs11_lib}" >&2
    echo "Set REFINEID_PKCS11_LIB to the path of your PKCS#11 bridge." >&2
    exit 1
  fi
fi

# Prompt securely for PIN 2 if not provided via environment variable
pin_arg=""
if [[ -n "${PIN2:-}" ]]; then
  pin_arg="pass:${PIN2}"
elif [[ -t 0 ]]; then
  read -s -r -p "Enter Identity Card PIN 2 (Qualified Signature): " user_pin
  echo ""
  if [[ -n "${user_pin}" ]]; then
    pin_arg="pass:${user_pin}"
  else
    pin_arg="pass:"
  fi
else
  pin_arg="pass:"
fi

pkcs11_cfg="$(mktemp /tmp/refineid_bundle_pkcs11.XXXXXX.cfg)"
trap 'rm -f "${pkcs11_cfg}"' EXIT
cat << EOF > "${pkcs11_cfg}"
name = ReFineIDSign
library = ${pkcs11_lib}
slotListIndex = 0
EOF

echo "Signing ${bundle_path} with hardware identity card (PIN 2)..."

jarsigner_cmd=(
  "${JAVA_HOME}/bin/jarsigner"
  -keystore NONE
  -storetype PKCS11
  -providerClass sun.security.pkcs11.SunPKCS11
  -providerArg "${pkcs11_cfg}"
  -storepass:env _TEMP_PIN_PASS
  -sigalg SHA256withRSA
  -digestalg SHA-256
  "${bundle_path}"
)

# Export pass temporarily in memory for jarsigner execution only
if [[ "${pin_arg}" == pass:* ]]; then
  export _TEMP_PIN_PASS="${pin_arg#pass:}"
else
  export _TEMP_PIN_PASS=""
fi

"${jarsigner_cmd[@]}" "Sign" 2>/dev/null || "${jarsigner_cmd[@]}" "1"

unset _TEMP_PIN_PASS

echo "Verifying bundle signature..."
"${JAVA_HOME}/bin/jarsigner" -verify "${bundle_path}"

echo "Android App Bundle successfully signed with hardware identity card."
