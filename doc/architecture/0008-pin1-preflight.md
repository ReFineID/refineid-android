# ADR 0008: Counter-safe PIN1 preflight

Status: Accepted

Date: 2026-08-15

## Context

A wrong credential-bearing VERIFY decrements the card's PIN1 retry counter.
Authentication must therefore know the live counter and the card's credential
reference numbering before it prompts for or sends a PIN.

FINEID S1 v4.2 section 3.5.1.1 gives header-only VERIFY a distinct meaning:
it queries whether the PIN is already verified or reports the remaining
attempts. It presents no PIN and performs no credential comparison. The public
`refineid-core`, mature internal implementation, and Apple product use this
form as the counter-safe preflight. They also resolve citizen versus
organizational credential numbering by probing the card rather than trusting
card-model or reader-model identity.

## Decision

After selecting the PKCS#15 application, Android asks `refineid-auth` to
resolve the reference numbering and query PIN1. The public `CardTransport`
path carries only header-only VERIFY commands. The credential transport entry
point is unreachable from this operation.

JNI returns a fixed, tagged result containing only:

- the resolved citizen or organizational reference scheme;
- verified, remaining, locked, no-information, or unrecognized state;
- a bounded retry nibble when the state supplies one; and
- the public core's consumer-authentication policy verdict.

Kotlin rejects malformed lengths, tags, schemes, state/count combinations,
and policy contradictions. A successful result is cached with the
authentication certificate inside the retained USB session. Replacing or
closing that session closes the certificate owner and discards the reference
scheme and PIN state together.

Every VERIFY-shaped transfer is classified as sensitive at the final logging
boundary. Debug tracing redacts its header and length wholesale and records
only the typed operation result, response status, and timing. Release tracing
remains empty and is checked in the optimized DEX.

## Physical evidence

On 2026-08-15, a generic class-matched TPDU reader and T=0 card completed two
consecutive header-only PIN1 queries over one retained Android USB Host
session. Both returned the same healthy state, proving that the first query did
not decrement the counter. The app retained the session and reached ready
state. The credential transport was never entered, and the trace contained no
VERIFY header, credential bytes, reader identity, card identity, or device
identity.

## Consequences

Reference resolution and an initial counter-safe PIN1 state are now available
to the future authentication operation. A real VERIFY must still obtain a
fresh status inside the same exclusive native operation, enforce the returned
policy, collect explicit on-device consent, consume one mutable PIN value
exactly once through the credential path, and zeroize it on every return path.
No PIN entry, credential VERIFY, or card signature is claimed by this slice.
