# ADR 0003: Native ATR border

Status: Accepted

Date: 2026-08-15

## Context

Card power-on returns an Answer to Reset through an untrusted USB transport.
Android needs the protocol rules already implemented by `refineid-core`, while
JNI should expose neither a broad Rust API nor native object lifetimes.

## Decision

The Android native crate pins the public `refineid-core` revision recorded in
`Cargo.lock` and exports one operation: validate an ATR and return its
convention and whether it advertises a non-T=0 protocol as a small status code.

The Kotlin transport accepts only a complete CCID data block with an active
card and at most the ISO 7816-3 maximum of 33 ATR bytes. The bridge copies the
Java byte array into Rust, constructs the typed core ATR, and returns only
T=0-direct, T=0-inverse, non-T=0-direct, non-T=0-inverse, invalid, or
bridge-error state. A TPDU reader is admitted only for T=0 because the current
native adapter implements T=0 TPDUs; an APDU-level reader owns that protocol
and may admit either valid class. Every temporary native and Kotlin-owned copy
is zeroized after use. Raw bytes are not logged or shown in product UI.

The bridge is built as a native library for `arm64-v8a` and `x86_64`, using the
pinned Android NDK and Rust dependency lockfile. Kotlin does not receive a
native pointer or own a Rust object.

## Physical evidence

On a physical Android USB Host device, a generic class-matched CCID interface
completed slot-status and automatic-voltage power-on exchanges. The returned
ATR passed the native core validator and the app reached ready/card-present
state. No APDU, PIN operation, raw response, reader identity, or card identity
was recorded.

## Consequences

The verified boundary proves packaging, JNI symbol resolution, CCID power-on,
and core ATR parsing on the physical architecture. Application selection now
has separate evidence in ADR 0004. Certificate access, PIN verification,
signing, and browser authentication require their own bounded APIs and
evidence.
