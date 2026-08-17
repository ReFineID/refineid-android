# ReFineID for Android

Native Android support for Finnish identity cards and standards-based browser
authentication.

This repository contains the native card application, a debug-only browser
harness, and the app and AOSP boundaries needed to expose the same
non-exportable key through Android KeyChain. A custom platform image is still
required for independent browsers.

The long-term target is authentication from normal Android browsers, including
reference services such as Suomi.fi. An in-app browser is useful as an
instrumented development harness, but it is not the product boundary.

## Current status

- Android 13 and newer
- Native Kotlin and Jetpack Compose shell
- CCID USB-reader discovery and permission handling
- Generic CCID activation and retained USB session
- ATR and protocol validation through a narrow JNI bridge to pinned
  `refineid-core`
- Typed PKCS#15 application selection over APDU- or T=0 TPDU-level readers
- Bounded authentication-certificate read and public-key classification
- Credential-free qualified-certificate read across citizen and organization
  card directory layouts
- Counter-safe PIN1 status and credential-reference preflight
- Counter-safe, credential-free PIN2 status and qualified-signature policy
- One-shot PIN1 VERIFY, RSA PKCS#1/PSS authentication signing across
  SHA-256/384/512, and P-384 authentication signing across SHA-256/384
- Mandatory local verification against the retained authentication certificate
- One-shot PIN2 VERIFY and SHA-384 qualified signing for RSA-3072 and P-384,
  bound to the exact qualified certificate with mandatory local verification
- Canonical detached PAdES CMS assembly for RSA-3072 and P-384, with strict DER
  parsing and exact signed-attribute reconstruction
- Bounded classic and cross-reference-stream PDF revisions with object-stream
  resolution, invisible signature fields, fixed byte ranges, repeat-signing
  support, and qpdf compatibility checks
- One-shot PAdES-B-B orchestration plus an owned post-card capability that binds
  the exact card certificate, signed attributes, verified signature, and
  prepared PDF revision
- Independent OpenSSL, qpdf, and Poppler validation for synthetic RSA-3072 and
  P-384 end-to-end PAdES output, including signed-byte tamper rejection
- Bounded canonical RFC 3161 request/response binding with an explicitly
  unverified token type
- Strict TSA CMS signature, signed-attribute, ESS certificate, timestamp-only
  certificate-profile, exact TSA-name, and offline exclusive-anchor PKIX
  verification before promotion to an owned verified-token capability
- PAdES-B-T CMS assembly that binds each verified token to the exact stored
  signature value and emits canonical, sorted, deduplicated unsigned attributes
- Bounded, byte-preserving PDF DSS revisions with deduplicated new evidence and
  fail-closed retention of earlier certificate, OCSP, CRL, VRI, and extension data
- Exact DER certificate facts, direct-issuer checks, nonce-bound authenticated
  OCSP responses, and complete authenticated CRLs for validation evidence
- Bounded signer/TSA path collection with explicit anchors, AIA issuer lookup,
  OCSP-first status, full-CRL fallback, and role-preserving revocation failures
- Authenticated DSS followed by an exact-imprint RFC 3161 document timestamp,
  with synthetic end-to-end B-LTA checks through OpenSSL, qpdf, and Poppler
- Bounded live TSA, AIA, OCSP, and CRL transport with public-address and
  redirect policy, exact response limits, injected time/randomness, and
  verify-before-use RFC 3161 trust promotion
- Injected synchronous PAdES-B-LTA completion in the fixed signature-timestamp,
  validation, DSS, and archive-timestamp order, with exact digest checks and
  clearing of all intermediate owners
- Debug-only terse ordered timestamp-authority settings with Keystore-protected
  passwords, HTTPS-only credentials, Restore Defaults, and off-main storage
- Debug-only terse PDF choose/save/PIN2 PAdES-B-LTA harness with holder-configured
  authority trust, pinned signer trust, Apple-compatible retry, cancellation,
  and off-main storage and network work
- Live card-free RFC 3161 acquisition verified on the Android 13 Pixel 4 under
  holder-configured authority trust
- Secure, debug-only on-device signing harness; no manual harness in release
- Debug-only, origin-pinned WebView client-certificate harness backed by the
  retained smart-card session
- Card-backed JCA provider for Chromium's full SHA-2 RSA and P-384
  authentication schemes
- Exact-digest signing boundary with mandatory local verification for platform
  and Gecko-style adapters
- AOSP KeyChain descriptor, exact-digest contract, framework JCA provider,
  service-side grant/generation bridge, native chooser discovery,
  browser-liveness token, and statically trusted provider-binding patches for
  the exact Android 13 Pixel 4 base
- Privileged external-key service with a generation-bound USB backend, secure
  caller-labelled PIN prompt, platform-only background launch permission,
  one-result replay, and coarse failures
- Product priv-app import and a dedicated non-network SELinux app domain for
  the Android 13 Pixel 4 image
- Fingerprint-pinned public FINEID intermediates shared by the diagnostic and
  system-KeyChain paths, with fail-closed direct-issuer verification
- Live diagnostic handshake verified through Chromium's holder-PIN request
- Live credential-free publication of the card leaf and its verified issuing
  intermediate through the external-key provider
- Live credential-free qualified-certificate and PIN2 preflight checks
- NFC reader-mode discovery with a credential-free contactless
  `EF.CardAccess` probe that recognizes the published FINEID PACE profile
- One-shot contactless operations behind PACE and secure messaging with a
  holder-entered CAN: certificate read, counter-safe PIN1 preflight, and
  authentication signing through the shared browser card service
- Transport-selecting external-key provider session with generation-routed
  signing, so the privileged KeyChain boundary serves USB and contactless
  cards alike
- No embedded browser, Internet permission, or logging in the release build
- Compose UI Test v2 and UI Automator 2.4 instrumentation on a physical device

An ordinary APK cannot publish its process-local external key to every other
browser process. System-browser support therefore uses the included privileged
platform integration; see `docs/architecture/0011-browser-authentication-boundary.md`
and the concrete AOSP design in
`docs/architecture/0012-platform-keychain-external-key.md`.

Product UI is deliberately terse. Explanations and diagnostics belong in
documentation or developer tooling.

Versions follow the Apple release pair: `YY.M.D` and a ten-minute UTC build
number. Android encodes the date and build into its monotonically increasing
`versionCode`; see `docs/architecture/0006-calendar-versioning.md`.

## Source hierarchy

- fineid-spec defines protocol behavior.
- refineid-core is the preferred reusable Rust implementation.
- refineid-mono-internal is a compatibility and coverage oracle.
- ReFineID-Apple is the product-behavior and UX reference.

This repository and the referenced ReFineID sources are licensed under
Apache-2.0.

## Local build

Install JDK 26, Android SDK platform 37, NDK 28.2.13676358, Rust 1.97,
the aarch64-linux-android and x86_64-linux-android Rust targets, cargo-ndk, and
ShellCheck 0.11. Then set JAVA_HOME and ANDROID_SDK_ROOT. Build and run checks
with:

    ./gradlew check
    ./gradlew assembleDebug
    ./gradlew connectedDebugAndroidTest

Machine-specific SDK paths belong in the ignored local.properties file.

For an AOSP checkout containing this repository at `packages/apps/ReFineID`,
follow the pinned Pixel 4
[`BUILD.md`](platform/aosp/android-13.0.0_r31/BUILD.md) runbook. To stage only
the minimized unsigned release artifact, use:

    Scripts/stage-aosp-prebuilt.sh

The AOSP module signs that ignored artifact with the build-local platform key;
no signing key or signed platform artifact belongs in this repository.

The `check` task treats Kotlin compiler and Android Lint warnings as errors,
runs Detekt and ktlint, tests and lints the Rust bridge with rustfmt and Clippy,
runs ShellCheck, proves that the application and AOSP provider wire contracts
match, builds the minimized release APK, and verifies that release bytecode
contains no logging calls or diagnostic trace literals. It also verifies that
the merged release manifest has no Internet permission and explicitly rejects
cleartext traffic.

## Security

Never place a real PIN, CAN, PUK, certificate, card dump, APDU trace, personal
identifier, or device/network identifier in source control, tests, screenshots,
issues, or CI logs. Tests use synthetic identities and protocol data only.

Licensed under the Apache License, Version 2.0.
