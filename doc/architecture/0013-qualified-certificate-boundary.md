# ADR 0013: Qualified-certificate boundary

Status: Accepted

Date: 2026-08-15

## Context

Qualified document signing needs the public certificate in EF.4332 before it
can build signed attributes or ask for PIN2. Citizen and organization cards do
not expose the surrounding signature directory identically. Citizen cards use
the DF.5016 file-identifier path. Organization cards publish DF.ESIGN under its
ASCII `E.SIGN` application name, and a file-identifier SELECT is not a reliable
substitute for making that directory current.

Reading a qualified certificate is credential-free. It must therefore be
independently testable on hardware before the port introduces any
retry-consuming PIN2 operation.

## Decision

The Android native crate pins the public core revision that selects the
signature directory in this order:

1. DF.ESIGN by the specified `E.SIGN` application identifier;
2. child DF by the specified file identifier 5016; and
3. any file by that same file identifier for older selector variants.

The read then selects EF.4332, bounds the DER object by its declared length,
and reconstructs a supported public-key profile before any bytes cross JNI.
Authentication and qualified certificates have distinct owned Kotlin types,
while their key-profile and strict reply vocabulary are shared. Closing either
type clears its owned DER buffer.

The qualified-certificate API accepts no credential and can reach only the
public block-exchange callback. A retained USB session reselects the PKCS#15
application after the read before returning to its caller. This preserves the
authentication context expected by subsequent browser operations. If the card
or transport is no longer in a state where restoration is safe, the method
returns a coarse failure instead of sending another command.

Debug builds trace only the operation, public key profile, object length,
coarse result, and duration. Release builds retain no logging calls or trace
literals. Neither build logs certificate bytes, identifiers, reader metadata,
or status words.

## Verification

Scripted core tests lock the named selector, both file-identifier fallbacks,
and their ordering. Android unit tests lock the shared JNI reply decoder,
ownership clearing, malformed-reply rejection, and distinct qualified type.

An opt-in UI Automator hardware test grants USB permission when needed, waits
for the retained card session, reads the qualified certificate, and asserts
only that a typed, non-empty public certificate was returned. It has no PIN
input and never submits a credential:

    ./gradlew connectedDebugAndroidTest \
      -Pandroid.testInstrumentationRunnerArguments.class=fi.refineid.android.ui.LiveQualifiedCertificateUiAutomatorTest \
      -Pandroid.testInstrumentationRunnerArguments.refineidLiveQualifiedCertificate=true

The connected RSA card completed the public read and the following PKCS#15
context restoration. This validates the citizen-card path only. Organization
card and contactless validation remain separate hardware gates.

## Consequences

This boundary proves certificate discovery, not qualified signing. PIN2
preflight, one-shot VERIFY, card signing, local signature verification,
document assembly, and the holder-facing signing journey remain later slices.

Traversing the MF is not yet suitable for the current contactless
secure-messaging session because that traversal can tear the channel down.
The first qualified-signing hardware target therefore remains the connected
contact reader.
