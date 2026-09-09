# ADR 0007: Authentication certificate custody

Status: Accepted

Date: 2026-08-15

## Context

Browser authentication needs the card's authentication certificate and its
public key. Certificate DER is public but identifying, so it may exist in the
live authentication session but must not enter UI diagnostics, persisted
state, backups, tests, or source control. The card and USB transport are
untrusted byte origins.

The legacy FINEID authentication leaf is EF.4331 under the PKCS#15 application.
The public `refineid-core`, mature internal implementation, and Apple product
agree on that path and on reading exactly the DER-declared object length.

## Decision

The native core reselects the PKCS#15 application, selects EF.4331, and reads
the DER object in bounded chunks. It then consumes the unvalidated certificate
through `refineid-x509`, reconstructing a typed RSA or elliptic-curve public
key. Only RSA-2048, RSA-3072, ECDSA P-256, and ECDSA P-384 profiles are
admitted.

JNI returns a tagged reply containing the classified profile and at most one
16-KiB certificate. Every malformed tag, unexpected payload, unsupported key,
invalid DER, oversized object, or transport fault fails closed. The JNI reply
array is cleared after Kotlin takes an owned copy. That copy belongs to the
claimed USB session and is cleared when the session closes or is replaced.

Debug traces may record the typed profile, byte count, command headers, status
words, and timing. They never record certificate bytes, names, serial numbers,
issuer fields, fingerprints, reader identity, card identity, or device
identity. Product UI remains unchanged.

## Physical evidence

On 2026-08-15, a generic class-matched TPDU reader and T=0 card completed the
typed PKCS#15 selection and a multi-chunk EF.4331 read on Android USB Host. The
core reconstructed a supported RSA profile, the certificate stayed owned by
the retained session, and the app reached ready state. No credential command
was sent and no certificate content or identity field was recorded.

## Consequences

The session now has the leaf DER and reconstructed key profile needed for
signature verification and later TLS client-certificate presentation. Issuer
chain resolution, alternate authentication slots, PIN presentation, card
signing, and browser integration remain separate slices with their own
evidence.
