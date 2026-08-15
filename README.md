# ReFineID for Android

Native Android support for Finnish identity cards and standards-based browser
authentication.

This repository is at the hardware-foundation stage. The first vertical slice
uses an Android USB Host connection to a CCID reader. It will discover a card,
perform a PIN-authorized RSA signature, and verify that signature locally
before browser integration is added.

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
- Counter-safe PIN1 status and credential-reference preflight
- One-shot PIN1 VERIFY and RSA/P-384 authentication signing
- Mandatory local verification against the retained authentication certificate
- Secure, debug-only on-device signing harness; no manual harness in release
- Compose UI Test v2 and UI Automator 2.4 instrumentation on a physical device

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
the aarch64-linux-android and x86_64-linux-android Rust targets, and cargo-ndk.
Then set JAVA_HOME and ANDROID_SDK_ROOT. Build and run checks with:

    ./gradlew check
    ./gradlew assembleDebug

Machine-specific SDK paths belong in the ignored local.properties file.

## Security

Never place a real PIN, CAN, PUK, certificate, card dump, APDU trace, personal
identifier, or device/network identifier in source control, tests, screenshots,
issues, or CI logs. Tests use synthetic identities and protocol data only.

Licensed under the Apache License, Version 2.0.
