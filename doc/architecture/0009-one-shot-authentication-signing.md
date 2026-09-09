# ADR 0009: One-shot authentication signing

Status: Accepted

Date: 2026-08-15

## Context

Browser client-certificate authentication needs a signature from the card's
authentication key. A signing result is usable only if the operation protects
the retry counter, presents a freshly entered PIN exactly once, preserves the
card-command ordering required by FINEID, and verifies the returned bytes
against the selected certificate before releasing them.

FINEID S1 v4.2 sections 3.5, 3.6, 3.7.2.3, and 3.8 define the relevant chain:
header-only VERIFY status, credential VERIFY, MSE:SET DST, PSO:HASH, and
PSO:COMPUTE DIGITAL SIGNATURE. Nothing may interleave after the external digest
has been loaded and before the signature command completes.

## Decision

One synchronous Rust operation owns the card transport from a fresh PIN1
preflight through the final signature response. It:

1. reconstructs a typed PIN1 from owned mutable bytes;
2. resolves the credential-reference scheme and probes the current state;
3. enforces the public core's consumer retry-floor policy;
4. submits one credential VERIFY through the non-replayable transport path;
5. selects the authentication key and algorithm;
6. hashes the caller's bounded message and performs PSO:HASH followed directly
   by PSO:COMPUTE DIGITAL SIGNATURE; and
7. returns a fixed-shape RSA or raw P-384 ECDSA signature.

The Android bridge supports RSA PKCS#1 v1.5 and RSA-PSS with SHA-256, SHA-384,
or SHA-512, plus P-384 ECDSA with SHA-256 or SHA-384. Each algorithm has one
stable JNI code and one exact output length. New codes are appended without
renumbering an existing message or prehashed request. The bridge admits at most
a 1-MiB message and returns either a tagged signature or one coarse failure
tag. It never returns a raw status word, retry count, backend exception, or
credential detail from this operation.

`refineid-core` revision
`d264da6c55d8cbd6fdf4cc41179731ecc1a20e1e` supplies all eight signing paths
and typed SHA-256, SHA-384, and SHA-512 digest values. Missing SHA-2 operations
and the SHA-512 refinement were added to the public core rather than being
reimplemented in Android.

## Credential custody

The debug-only manual harness uses Compose `SecureTextField` in hidden mode.
The state is remembered only for the current composition, is not saveable,
accepts at most twelve decimal digits, and is cleared before dispatch and on
disposal. The activity disables screenshots, autofill, content capture, and
backup.

PIN1 is copied directly from the mutable text sequence into one mutable byte
array without creating a `String`. The Kotlin owner transfers that same array
to at most one JNI call and clears it in a `finally` block. JNI immediately
copies and clears the Java array; Rust transfers its copy into the non-clonable,
zeroizing `Pin1` refinement type. No layer exposes a PIN accessor, formatter,
serializer, cache, command-line option, or log event.

A rejected or uncertain credential operation is terminal. There is no
automatic VERIFY retry. A later attempt requires a new field entry and a new
explicit button press.

## Local verification gate

The retained USB session owns the authentication certificate and selects only
algorithms compatible with its classified public-key profile. Android parses
a short-lived copy of that certificate and verifies the returned signature
with the platform cryptography provider. Raw P-384 `r || s` is strictly
converted to DER for JCA. RSA-PSS uses the selected SHA-2 algorithm for both
the message digest and MGF1, a digest-length salt, and the standard trailer
field.

On a key-profile mismatch, malformed signature, provider failure, or invalid
signature, the signature owner is cleared and only a typed failure escapes.
The debug harness also clears successful diagnostic signatures immediately.
Future browser code may receive a successful signature owner only after this
gate.

## Diagnostics and release behavior

Debug tracing records algorithm, typed stage outcome, lengths, and timing.
Credential transfers remain wholly redacted. Release uses the empty trace sink,
and the optimized APK must pass the DEX no-logging verifier.

The manual signing card is compiled only into debug builds. It is a hardware
diagnostic, not browser integration or product UI. The reusable signer accepts
the caller's message and requested algorithm so a later browser adapter can
bind it to the real authentication request without weakening this boundary.

## Physical evidence

The physical gate is complete only after a user enters PIN1 on the device, the
card produces a signature, and Android's local verification succeeds. Evidence
records only that typed outcome; it does not retain the PIN, signature,
certificate, status word, retry count, reader identity, card identity, or
device identity.

On 2026-08-15, the validated debug build completed that gate on a physical
Android 13 device with an attached CCID reader and card. One explicit on-device
submission produced one credential exchange, one card signature, and a
successful platform-local verification. No identifying or credential material
was retained as evidence.

The later SHA-384 and SHA-512 RSA routes pass scripted card-transport tests,
host cryptographic verification, and synthetic Android 13 JCA tests. They are
not yet recorded as live card-signature validation.
