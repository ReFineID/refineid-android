# RAPP on Android

Status date: 2026-08-16. This describes the Android side of the Remote
Authorization Proxy Protocol: what exists now, why it is built this way, and
what the next agent has to do.

## Why Android needs it

RAPP is what lets a computer use a card it cannot read itself. The holder
presents the card to their phone, approves the operation there, and the
computer receives only the result. On Android that makes the phone the
authorizer: the card, the CAN, PIN 1 and PIN 2 stay on the device the holder
is holding, and a laptop needs no card reader at all.

Apple already implements both roles. Android implementing the same protocol is
what turns a proven pair of devices into a cross-platform one.

## The protocol is not implemented here

`refineid-lib-core` in the shared Rust repository is the authority for RAPP
framing, state transitions, role legality, failure policy, and cryptography.
Nothing in Kotlin decides protocol. The same crate backs the Apple binding, so
a Kotlin peer and a Swift peer cannot drift apart in the ways two hand-written
implementations always eventually do.

Change the protocol in Rust first, make its tests pass, regenerate this
binding, and only then adapt the Android integration.

## What is in the repository

`native/refineid-rapp-android/` is a thin crate whose only job is to produce a
shared object for Android:

- It depends on `refineid-lib-core` with the `bindings` feature and re-exports
  it, which links that crate's UniFFI scaffolding into a `cdylib`. The library
  crate itself builds as `rlib` and `staticlib` for the Apple binding and
  cannot produce a `.so` for Android on its own.
- The shared object must be named `librefineid_lib_core.so`, because the
  generated binding loads its Rust side by the scaffolding crate's name. That
  is why this wrapper sets `[lib] name = "refineid_lib_core"`.
- `src/bin/refineid-uniffi-bindgen-kotlin.rs` generates the binding, mirroring
  the Apple repository's Swift generator.
- `generated/uniffi/refineid_lib_core/refineid_lib_core.kt` is the generated
  binding, about 6,400 lines, in package `uniffi.refineid_lib_core`. It is
  committed so a build does not depend on regenerating it, and it must be
  regenerated and committed together with the Rust revision that defines its
  ABI.

The Gradle wiring in `app/build.gradle.kts` follows the existing pinned-core
pattern: `buildRappDebug` and `buildRappRelease` run `cargo ndk` for
`arm64-v8a` and `x86_64`, their output directories are added as `jniLibs`, and
the generated Kotlin is added as a source directory. The binding calls Rust
through JNA, which the application did not previously need, so `jna` with the
`aar` artifact type is now a dependency.

## Rebuilding the binding

From the crate directory, with the NDK available:

```sh
cargo ndk -t arm64-v8a -t x86_64 -o jniLibs build --release
cargo run --bin refineid-uniffi-bindgen-kotlin -- \
    generate --library jniLibs/arm64-v8a/librefineid_lib_core.so \
    --language kotlin --out-dir generated --no-format
```

The crate currently depends on `refineid-lib-core` by relative path, because
the RAPP source is not published yet. That is a temporary arrangement and is
the same assumption the Apple generator makes. Replace it with a pinned git
revision as soon as the crate is pushed, so an Android build stops depending
on one developer's directory layout.

## Measured so far

- `refineid-lib-core` compiles for `aarch64-linux-android` and
  `x86_64-linux-android` with the pinned 1.97 toolchain.
- The wrapper produces `librefineid_lib_core.so` for both ABIs.
- The Kotlin binding generates from the built library and exposes the RAPP
  surface: `RappPairingBridge`, `RappSessionBridge`, `RappOperationBridge`,
  `RappPairVault`, `RappOperationVault`, and the operation, pairing and
  liveness value types.
- Gradle configures with the new tasks registered.

Nothing on Android has spoken to a peer yet. There is no pairing UI, no
authorization prompt, no card execution path, and no evidence of
interoperability with the Apple implementation.

## What the next agent does

1. Implement the platform side the generated bridges require, mirroring the
   Apple layer file for file where it makes sense: random and key material,
   a device vault backed by the Android keystore, a pair catalog, a framed
   transport, and a card executor that performs authorized work through the
   existing NFC and APDU paths.
2. Present the holder-visible parts: QR pairing, a visible paired state, and
   an authorization prompt that names the requester, the operation, and which
   credential it will consume. The requester must never render or collect the
   CAN, PIN 1 or PIN 2.
3. Keep the fail-stop rules the Rust core enforces: an invalid card
   credential, an authenticated protocol violation, or an ambiguous card
   completion tears the session down and requires the holder to act. Do not
   add an Android-side recovery path that the protocol does not have.
4. Prove interoperability against the Apple implementation, not against
   another Android device: pair a phone with a Mac, then record one card
   status read, one browser authentication, and one document signature.
5. Only then describe Android RAPP as working, and update this document with
   the exact commits, devices and operating system versions used.
