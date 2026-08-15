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
- One-shot PIN1 VERIFY and RSA/P-384 authentication signing
- Mandatory local verification against the retained authentication certificate
- One-shot PIN2 VERIFY and SHA-384 qualified signing for RSA-3072 and P-384,
  bound to the exact qualified certificate with mandatory local verification
- Canonical detached PAdES CMS assembly for RSA-3072 and P-384, with strict DER
  parsing and exact signed-attribute reconstruction
- Bounded classic-PDF incremental revisions with invisible signature fields,
  fixed byte ranges, repeat-signing support, and qpdf compatibility checks
- One-shot PAdES-B-B orchestration that binds the exact card certificate,
  signed attributes, verified card signature, and prepared PDF revision
- Independent OpenSSL, qpdf, and Poppler validation for synthetic RSA-3072 and
  P-384 end-to-end PAdES output, including signed-byte tamper rejection
- Bounded canonical RFC 3161 request/response binding with an explicitly
  unverified token type
- Strict TSA CMS signature, signed-attribute, ESS certificate, timestamp-only
  certificate-profile, exact TSA-name, and offline exclusive-anchor PKIX
  verification before promotion to an owned verified-token capability
- PAdES-B-T CMS assembly that binds each verified token to the exact stored
  signature value and emits canonical, sorted, deduplicated unsigned attributes
- Debug-only terse PDF choose/save/PIN2 harness; release stays hidden until the
  complete validation-evidence and archive stages reach PAdES-B-LTA
- Secure, debug-only on-device signing harness; no manual harness in release
- Debug-only, origin-pinned WebView client-certificate harness backed by the
  retained smart-card session
- Card-backed JCA provider for Chromium's RSA and P-384 authentication schemes
- Exact-digest signing boundary with mandatory local verification for platform
  and Gecko-style adapters
- AOSP KeyChain descriptor, exact-digest contract, framework JCA provider,
  service-side grant/generation bridge, native chooser discovery,
  browser-liveness token, and statically trusted provider-binding patches for
  the exact Android 13 Pixel 4 base
- Privileged external-key service with a generation-bound USB backend, secure
  caller-labelled PIN prompt, one-result replay, and coarse failures
- Product priv-app import and a dedicated non-network SELinux app domain for
  the Android 13 Pixel 4 image
- Fingerprint-pinned FINEID intermediate set, present only in debug builds
- Live diagnostic handshake verified through Chromium's holder-PIN request
- Live credential-free qualified-certificate and PIN2 preflight checks
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
runs ShellCheck, builds the minimized release APK, and verifies that release
bytecode contains no logging calls or diagnostic trace literals.

## Security

Never place a real PIN, CAN, PUK, certificate, card dump, APDU trace, personal
identifier, or device/network identifier in source control, tests, screenshots,
issues, or CI logs. Tests use synthetic identities and protocol data only.

Licensed under the Apache License, Version 2.0.
