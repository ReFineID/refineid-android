# Android 13 Pixel 4 platform patches

This directory carries the ReFineID AOSP patch series for the Pixel 4 build
`TP1A.221005.002.B2`, which maps to the AOSP tag `android-13.0.0_r31`.

The series currently contains the descriptor, exact-digest contract,
browser-process JCA, KeyChain service-policy, native chooser-discovery,
caller-liveness, and trusted-provider binding steps from ADR 0012. It preserves
the existing Keystore2 grant path and adds a non-exportable external key plus a
narrowly routed signature provider. KeyChain now owns a stable non-personal
alias, grant checks, caller-package resolution, active-generation checks,
validated certificate snapshots, signature-shape checks, and an exact-component
Binder connection guarded by a dedicated signature permission and install-time
trust checks. The native chooser unions active external aliases with
AndroidKeyStore aliases before applying its existing user-selectability,
key-type, and issuer filters. The privileged ReFineID service, system-image
declarations, and SELinux policy have not landed, so this series still exposes
no card key.

## Upstream bases

| AOSP project | Base commit | Patch directory |
| --- | --- | --- |
| `platform/frameworks/base` | `9cc5d58d0254f472ae071b29ccf4fae93ca1cc3d` | `patches/frameworks-base` |
| `platform/packages/apps/KeyChain` | `97a7bc2ba75391487ecd3f23153cfb1ce293d6fe` | `patches/packages-apps-KeyChain` |

Apply each directory's patches to its corresponding project with `git am`, in
filename order. New AIDL methods are appended to the interface so all existing
Binder transaction numbers remain unchanged.

## Current verification

- Both project patch sequences pass sequential application checks and full
  `git am` replay in filename order from their exact upstream bases.
- The framework AIDL interface generates with Build Tools 36; the only
  excluded warning is its pre-existing Android 13 interface-wide
  missing-permission annotation. The private provider AIDL generates with
  every warning treated as an error.
- New framework and KeyChain boundary sources compile as Java 11 with warnings
  treated as errors. The complete Android 13 KeyChain service compiles against
  an Android 13 hidden-API framework, excluding only warnings already present
  in the upstream service.
- Descriptor and signature-contract parcel round trips, defensive copies,
  close behavior, algorithm mappings, coarse failures, and sanitized string
  forms pass on the physical Android 13 Pixel 4 using synthetic values only.
- Framework-provider tests cover streaming SHA-256/SHA-384, fixed RSA-PSS,
  strict Firefox-style `NoneWithRSA` and `NoneWithECDSA`, software-key provider
  fall-through, one-shot requests, generic failures, and non-exportability.
  The same JCA routing paths pass in Android's runtime on the physical Pixel 4
  with a synthetic signing operation; no reader or card command is involved.
- Twelve service-manager tests cover certificate validation, defensive copies,
  alias publication, generation and algorithm rejection, interrupted and
  closed requests, caller attribution, provider failures, output shape,
  removal, and sanitized string forms. An isolated Android-runtime harness on
  the physical Pixel accepts synthetic RSA and P-384 identities, rejects
  P-256, and exercises descriptor/signing/generation paths without a reader or
  card command.
- The modified native chooser and its tests compile against the Android 13
  hidden-API framework. A host semantic harness verifies external-certificate
  issuer and key-type filtering plus ordered, deduplicated alias merging.
- Seven host tests cover the bound-provider protocol, caller and liveness-token
  forwarding, coarse failure mapping, defensive copies, close behavior, and
  exact component, permission, privilege, UID, and signature trust checks.
  Android-runtime validation on the physical Pixel covers the opaque Binder
  token and provider parcelables, including sender-side byte clearing for
  returned values, using synthetic data only.
- The framework and KeyChain diffs pass Gitleaks.

The patch series has not yet passed a Soong platform build. Android 11 and
newer platform builds are unsupported on macOS, and Google's current
[AOSP workstation guidance](https://source.android.com/docs/setup/start/requirements)
budgets at least 400 GB of free space. Use a 64-bit Linux builder for the full
image and device-test stages.

Never add platform signing keys, device identifiers, network addresses, real
card material, credentials, or card traces to this directory.
