# ADR 0026: System-browser certificate chain

## Status

Accepted.

## Context

The external-key provider published the active card's authentication leaf but
left its CA-certificate bytes empty. Android's KeyChain chooser uses the chain
when applying TLS acceptable-issuer hints, and a browser needs the issuing
certificate to send a complete client-certificate chain. A valid card
signature alone does not repair a missing chain.

The issuing certificates are public CA material. Some older FINEID cards expose
the authentication leaf without a usable issuing-certificate file, while the
same stable public intermediates are already fingerprint-pinned for the
diagnostic browser path and in the Apple application.

## Decision

The four fingerprint-pinned FINEID intermediate resources are part of every
application variant, including the minimized platform release. They contain no
cardholder or private-key material and do not require network access.

`AuthenticationIssuerCertificateStore` accepts the card leaf only as one exact
DER certificate. A candidate must be a CA, permit certificate signing when its
key-usage extension is present, have a subject equal to the leaf issuer, and
cryptographically verify the leaf signature. The store returns a fresh owned
DER copy of the first matching pinned candidate.

The privileged backend publishes the stable authentication alias only when
that complete relationship exists. The same condition gates removal and every
signature request, so an old grant cannot keep signing after the identity
becomes unpublishable. Missing, malformed, empty, mismatched, or failing issuer
sources make the provider unavailable before PIN entry.

Unknown future issuers currently fail closed. Adding an authenticated on-card
issuer read is the compatibility fallback; publishing a leaf-only identity is
not.

## Verification

An OpenSSL interoperability test creates two synthetic CA certificates with
the same subject but different keys and a leaf signed by only one. The store
skips the name-matching wrong key, returns the exact issuer, returns independent
owned copies, and rejects malformed, trailing, and non-CA inputs. Backend tests
prove the issuer bytes cross the provider snapshot and that a missing issuer
prevents publication, removal, signing, and PIN authorization.

The existing Android test verifies the four bundled fingerprints, current
validity, CA profiles, and uniqueness. The minimized release APK's resource
table retains all four resources. A credential-free UI Automator run on the
physical Android 13 Pixel 4 read the attached card leaf, selected the pinned
issuer, verified the direct signature, and observed the complete provider
chain. It did not request or submit a PIN and did not print certificate
contents.

## Consequences

The application side now supplies the certificate chain required by the
patched KeyChain chooser and independent TLS clients. A full Soong image build
and Chrome/Firefox handshakes remain necessary to validate the complete
cross-process path.
