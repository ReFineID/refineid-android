# ADR 0014: Qualified-signature boundary

Status: Accepted

Date: 2026-08-15

## Context

Qualified document signing is the first Android card operation that uses PIN2.
A failed or replayed VERIFY can consume a retry, so transport convenience must
never turn one holder decision into more than one credential command. The
signed content also has to remain bound to the exact qualified certificate
shown to the document-signing layer.

The reference product signs with SHA-384: RSA cards use PKCS#1 v1.5 and P-384
cards use ECDSA. PIN-reference numbering differs between citizen and
organization cards, and organization-card signing requires DF.ESIGN to remain
current after its certificate is read.

## Decision

PIN2 status is available as a separate credential-free preflight. The native
core resolves the card's PIN-reference numbering and then sends a header-only
PIN2 VERIFY through the public exchange path. It returns only the resolved
scheme, a typed counter state, and the shared core policy verdict. Unknown or
low-confidence states fail closed.

A signing request owns one freshly constructed `Pin2Submission`. Its native
operation performs this fixed sequence:

1. reject an invalid PIN shape or oversized content locally;
2. hash the exact signed content with SHA-384;
3. repeat the counter-safe PIN2 preflight immediately before use;
4. reread EF.4332 inside the same exclusive card operation;
5. require byte-for-byte equality with the caller's retained certificate and
   require its key profile to match the requested algorithm;
6. send that PIN2 in exactly one credential VERIFY; and
7. sign with the qualified-signature key using RSA-3072 PKCS#1 SHA-384 or raw
   P-384 ECDSA SHA-384.

Neither transport correction nor error handling may replay the credential
command. The one-shot Kotlin and Rust owners clear PIN buffers after transfer.
Native replies expose fixed signature shapes or coarse failures, never card
status words or credential bytes.

Android verifies every returned signature locally against the retained
qualified certificate and the exact signed content before releasing it to the
caller. A verification failure destroys the returned bytes. When the result
leaves the transport in a known state, the retained session reselects PKCS#15
before later authentication work; indeterminate transport failures do not send
speculative recovery commands.

Debug builds trace operation names, algorithms, public lengths, coarse states,
policy decisions, local-verification results, and durations. Release builds
retain no logging calls or trace literals. Neither build logs PIN2, certificate
contents, signed content, signature bytes, card identifiers, or status words.

## Verification

Scripted native tests lock the public-only preflight, both PIN-reference
schemes, the policy floor, certificate and profile checks before credential
access, one VERIFY followed by one signing chain, non-replay after a wrong PIN,
and both supported signature shapes. Kotlin tests lock the JNI vocabulary,
one-shot ownership, malformed-reply rejection, RSA verification, and raw-to-DER
P-384 verification.

An opt-in UI Automator test validates only the counter-safe preflight on real
hardware. It has no PIN field, cannot call the credential exchange path, and
does not request a signature:

    ./gradlew connectedDebugAndroidTest \
      -Pandroid.testInstrumentationRunnerArguments.class=fi.refineid.android.ui.LivePin2PreflightUiAutomatorTest \
      -Pandroid.testInstrumentationRunnerArguments.refineidLivePin2Preflight=true

The connected RSA citizen card completed that preflight. A live qualified
signature remains intentionally untested until PIN2 is entered directly by the
holder with recovery available and the live retry state accepted immediately
before submission.

## Consequences

The card-signing primitive is now ready for document signed-attribute assembly
and a terse holder-confirmation UI. RSA-2048 and P-256 qualified signing are not
part of this boundary; adding them requires explicit core signature shapes,
algorithms, and equivalent local-verification coverage. Organization cards and
contactless operation remain separate hardware gates.
