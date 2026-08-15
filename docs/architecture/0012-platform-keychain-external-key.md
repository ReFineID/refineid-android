# ADR 0012: Platform KeyChain external-key integration

Status: Accepted

Date: 2026-08-15

## Context

ADR 0011 establishes that an app-owned WebView and a process-local JCA
provider are diagnostic tools, not the system-browser result. Chrome,
Firefox, and other independent applications obtain client-certificate
identities through Android `KeyChain`.

Current AOSP assumes that every selectable client private key is an
AndroidKeyStore entry:

- `IKeyChainService.requestPrivateKey` returns a Keystore2 grant string;
- `KeyChain.getKeyPair` reconstructs an AndroidKeyStore key from that grant;
- `KeyChainService` reads certificates and grants from AndroidKeyStore; and
- `KeyChainActivity` enumerates `AndroidKeyStore.aliases()` and retains only
  key entries.

The administrative install path does not provide an escape hatch.
`DevicePolicyManager.installKeyPair` converts the supplied `PrivateKey` to an
encoded `PKCS8EncodedKeySpec`, and the KeyChain AIDL accepts those encoded
private-key bytes. A FINEID authentication key cannot use this path because
the private key is non-exportable and remains on the card.

A credential-management policy can choose an alias for an exact package and
URI, but the current grant path still requires the alias to identify an
AndroidKeyStore key. Policy can remove a chooser interaction; it cannot create
an external key.

The current ReFineID application now has both complete-message and
exact-digest signing boundaries. Both routes use one holder-entered PIN1,
serialize USB use, validate the card key profile, and locally verify the card
signature before returning it.

## Decision

The Pixel/AOSP work will add an external-key branch to `KeyChain`. It will not
model the card as an AndroidKeyStore or KeyMint key and will not patch
Keystore2 for the first implementation.

The platform branch consists of four boundaries:

1. `KeyChainService` owns aliases, grants, certificate access, and the
   connection to a statically trusted external-key provider.
2. `KeyChain.getPrivateKey` returns a framework-owned, non-exportable
   `PrivateKey` for an external alias.
3. A framework JCA provider recognizes only that private-key class, hashes or
   validates its input, and asks `KeyChainService` to sign an exact digest.
4. A privileged ReFineID service obtains a fresh PIN1 through its secure UI,
   signs through the retained USB session, locally verifies the result, and
   returns only the verified signature or a coarse failure.

This keeps ordinary browser code on the normal `KeyChain` and JCA paths. No
Chrome or Firefox fork is required for the supported rows in the matrix below.

## Platform shape

### Alias and certificate discovery

External providers are declared in the system image, not registered by an
arbitrary installed application. A provider is identified by a component
protected with a signature-level bind permission and a matching priv-app and
SELinux policy.

The provider exposes active public identities. KeyChain assigns a stable,
non-personal alias in its own namespace; the alias must not contain a card
serial, certificate subject, identity code, reader model, or device detail.
The leaf certificate and chain are read dynamically from the active card.

`KeyChainActivity` unions active external aliases with AndroidKeyStore aliases
before applying the existing key-type, issuer, user-selectable, and policy
filters. Its adapter obtains the external certificate through
`KeyChainService`; it does not pretend that the alias is a KeyStore key entry.

`containsKeyPair`, `setGrant`, certificate retrieval, alias removal, and grant
cleanup gain an explicit external-alias branch. Existing AndroidKeyStore
behavior remains unchanged.

### Private-key descriptor

A new hidden parcelable response replaces the assumption that
`requestPrivateKey` can return only a Keystore2 grant:

- `KEYSTORE_GRANT` carries the existing grant string;
- `EXTERNAL_KEY` carries the KeyChain-owned alias, key algorithm, public-key
  parameters, and an active provider generation; and
- no response means absent, inactive, or unauthorized, as today.

The existing AIDL method remains during migration. A new method returns the
typed response so platform components can be updated without overloading the
grant-string syntax.

For an external response, the framework constructs an RSA or EC
`KeyChainExternalPrivateKey`. It returns `null` from `getEncoded`, reports no
export format, carries only public parameters and an opaque alias, and cannot
be serialized into private-key material.

### Framework JCA provider

The platform installs a JCA provider visible in every application process.
Its services declare `KeyChainExternalPrivateKey` as the supported key class,
so ordinary software and AndroidKeyStore keys continue to fall through to
their existing providers.

For hashed JCA algorithms, the provider hashes incrementally in the calling
browser process and sends only the final digest across Binder. It never sends
the TLS transcript or buffers a Binder-sized message. The external service
accepts only named algorithms and exact digest lengths.

The provider implements:

- `SHA256withRSA`;
- `SHA256withRSA/PSS`;
- `SHA256withECDSA`;
- `SHA384withECDSA`;
- `NONEwithRSA`, with strict parsing of a supported RSA DigestInfo; and
- `NONEwithECDSA`, accepting only a supported digest length.

It deliberately does not expose raw RSA private-key encryption. The card API
accepts a digest and performs RSA-PSS encoding internally; it cannot apply an
arbitrary modulus-wide private operation.

### Sign call

The hidden KeyChain sign call is synchronous because JCA `Signature.sign()` is
synchronous. The framework provider invokes it only from the browser's crypto
worker, never a main thread.

The request carries:

- the KeyChain-owned external alias;
- one closed algorithm identifier;
- an exact-length digest; and
- the provider generation observed when the key was obtained.

It does not carry a caller UID or package as a trusted field.
`KeyChainService` derives the Binder caller UID, verifies the alias grant and
active generation, resolves the installed package for holder-facing consent,
and only then proxies to the trusted ReFineID service.

The result is either a signature of the algorithm's fixed shape or a coarse
typed failure. Transport details, card status words, certificate contents,
PIN shape, and retry-counter values do not cross into the browser process.

## Browser algorithm matrix

| Caller path | Input received by platform provider | Card operation | Status |
| --- | --- | --- | --- |
| Chromium `SHA256withRSA` | Complete message | SHA-256 digest, RSA PKCS#1 v1.5 | Supported |
| Chromium `SHA256withRSA/PSS` | Complete message | SHA-256 digest, native RSA-PSS | Supported; direct JCA support prevents Chromium's raw-RSA fallback |
| Chromium `SHA256withECDSA` | Complete message | SHA-256 digest, P-384 ECDSA | Supported |
| Chromium `SHA384withECDSA` | Complete message | SHA-384 digest, P-384 ECDSA | Supported |
| Gecko `NoneWithECDSA` | Precomputed digest | P-384 ECDSA selected by exact digest length | Supported for SHA-256 and SHA-384 |
| Gecko `NoneWithRSA` | PKCS#1 input prepared by NSS | Strictly extract a supported SHA-256 digest, then native RSA PKCS#1 v1.5 | Implementable; the exact NSS DigestInfo shape requires an independent Firefox test |
| Gecko `raw` for RSA-PSS | Modulus-wide EMSA-PSS encoded block | No matching card operation | Unsupported in unmodified Firefox for RSA-PSS |

Gecko currently implements its RSA-PSS path by performing EMSA-PSS encoding
itself and asking Java for `RSA/None/NoPadding`. The original digest cannot be
recovered from that randomized encoded block. Supporting this row requires a
Gecko change that passes the digest and PSS parameters, or a different card
interface; weakening the card boundary to emulate raw RSA is not an option.

The primary ECDSA card path does not have this limitation.

## One-result replay lease

Gecko's PKCS #11 adapter currently calls its signing function once to learn
the output length and again to obtain the signature. Performing two card
operations would prompt twice and spend two PIN-protected operations for one
TLS signature.

After one locally verified result, the ReFineID service therefore retains a
one-result replay lease keyed by:

- Binder caller UID;
- alias and provider generation;
- algorithm; and
- exact digest.

The lease permits one retrieval, expires after a short named timeout, and
zeroizes its signature bytes on retrieval, replacement, provider-generation
change, detach, service shutdown, or expiry. It stores no PIN. A third request
requires a new holder-approved operation.

This works for Gecko's deterministic RSA PKCS#1 and ECDSA inputs. It cannot
repair Gecko RSA-PSS because independently generated EMSA-PSS inputs may use
different salts and therefore do not match the lease key.

## Consent and security invariants

- Alias selection uses the existing KeyChain chooser or an explicit
  credential-management policy. A browser never self-grants an alias.
- Every new card operation requires fresh holder PIN1 entry. PIN values are
  neither cached nor sent through KeyChain or the browser process.
- The secure prompt identifies the requesting application. The JCA boundary
  does not carry a trustworthy web origin, so the design does not claim
  origin-level consent beyond Android's existing UID grant model.
- The browser controls the data it asks its granted key to sign, as it already
  does for ordinary KeyChain keys. ReFineID accepts only the narrow
  authentication algorithms and still requires holder action.
- Every signature is verified against the currently selected authentication
  certificate before it crosses the provider boundary.
- Card operations remain serialized and credential APDUs remain at-most-once.
- Binder death, detach, generation mismatch, prompt cancellation, timeout, and
  caller interruption fail closed and clear pending state.
- Debug builds record only sanitized type, length, caller, timing, and outcome
  metadata. ReFineID release builds emit no logs.
- Platform signing keys, priv-app allowlists for a particular build, and any
  real card or identity material are never committed.

## Patch series

The first Pixel patch series is ordered so each boundary can be tested before
the next one depends on it:

1. Add hidden typed descriptors, algorithm/failure constants, and AIDL tests.
2. Add `KeyChainExternalPrivateKey` and the external JCA provider with
   synthetic Binder tests.
3. Add KeyChainService external aliases, grants, certificates, provider
   generation checks, and proxy signing.
4. Extend KeyChainActivity discovery and filtering for external identities.
5. Add the signature permission, priv-app declaration, service binding, and
   SELinux policy.
6. Add the ReFineID privileged service, secure prompt coordinator, and
   one-result replay lease over the existing digest-signing boundary.
7. Run independent Chrome and Firefox client-authentication tests, including
   cancellation, detach, wrong-card generation, process death, and the matrix
   limitations above.

The initial implementation targets the connected Pixel 4. A full AOSP build
requires a separate build volume or remote builder; it is not attempted in
the application repository's current local disk budget.

## Rejected alternatives

- Importing or copying the private key: impossible for a non-exportable card
  key and contrary to the security model.
- Installing only an application JCA provider: providers are process-local and
  do not appear in independent browsers.
- Treating the key as a synthetic Keystore2/KeyMint key immediately: this
  expands the trusted and vendor-facing patch surface without being necessary
  for KeyChain browser callers.
- Credential-management policy alone: it selects existing aliases but does
  not implement an external key.
- Raw RSA emulation: the card deliberately exposes only named signature
  operations and cannot safely implement arbitrary private-key exponentiation.
- Keeping the WebView as production authentication: it does not satisfy the
  independent system-browser requirement.

## Verification required for completion

- AOSP unit tests prove typed descriptor parsing, UID-bound grants, provider
  generation invalidation, certificate filtering, and fail-closed Binder
  behavior.
- Framework provider tests prove exact algorithm/input mapping and ordinary-key
  provider fall-through.
- ReFineID tests prove one fresh PIN per card operation, mandatory local
  verification, one-result replay, zeroization, detach, timeout, and process
  death behavior.
- Physical Pixel tests prove that Chrome and Firefox independently receive the
  alias through `KeyChain`, complete a supported TLS client-authentication
  handshake, and cannot use the alias without a grant and holder action.
- Release artifact inspection continues to prove that ReFineID contains no
  logging calls or trace literals.

## Upstream references

- [AOSP `KeyChain`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/keystore/java/android/security/KeyChain.java)
- [AOSP `IKeyChainService`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/keystore/java/android/security/IKeyChainService.aidl)
- [AOSP `KeyChainService`](https://android.googlesource.com/platform/packages/apps/KeyChain/+/refs/heads/main/src/com/android/keychain/KeyChainService.java)
- [AOSP `KeyChainActivity`](https://android.googlesource.com/platform/packages/apps/KeyChain/+/refs/heads/main/src/com/android/keychain/KeyChainActivity.java)
- [AOSP `DevicePolicyManager.installKeyPair`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/app/admin/DevicePolicyManager.java)
- [Chromium Android TLS signature mapping](https://chromium.googlesource.com/chromium/src/+/HEAD/net/ssl/ssl_platform_key_android.cc)
- [Chromium Android JCA bridge](https://chromium.googlesource.com/chromium/src/+/HEAD/net/android/java/src/org/chromium/net/AndroidKeyStore.java)
- [Gecko Android KeyChain bridge](https://hg.mozilla.org/mozilla-central/raw-file/tip/mobile/android/geckoview/src/main/java/org/mozilla/gecko/ClientAuthCertificateManager.java)
- [Gecko Android PKCS #11 backend](https://hg.mozilla.org/mozilla-central/raw-file/tip/security/manager/ssl/osclientcerts/src/backend_android.rs)
