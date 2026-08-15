# Android 13 Pixel 4 platform patches

This directory carries the ReFineID AOSP patch series for the Pixel 4 build
`TP1A.221005.002.B2`, which maps to the AOSP tag `android-13.0.0_r31`.

The series currently contains the descriptor, exact-digest contract,
browser-process JCA, and KeyChain service-policy steps from ADR 0012. It
preserves the existing Keystore2 grant path and adds a non-exportable external
key plus narrowly routed signature provider. KeyChain now owns a stable
non-personal alias, grant checks, caller-package resolution, active-generation
checks, validated certificate snapshots, signature-shape checks, and an
injectable provider boundary. The production boundary remains unavailable
until the signature-protected service binding and privileged ReFineID service
land, so this series still exposes no card key.

## Upstream bases

| AOSP project | Base commit | Patch directory |
| --- | --- | --- |
| `platform/frameworks/base` | `9cc5d58d0254f472ae071b29ccf4fae93ca1cc3d` | `patches/frameworks-base` |
| `platform/packages/apps/KeyChain` | `97a7bc2ba75391487ecd3f23153cfb1ce293d6fe` | `patches/packages-apps-KeyChain` |

Apply each directory's patches to its corresponding project with `git am`, in
filename order. New AIDL methods are appended to the interface so all existing
Binder transaction numbers remain unchanged.

## Current verification

- Both project patch sequences pass `git apply --check` in filename order from
  their exact upstream bases.
- The AIDL interface generates with Build Tools 36; all new warnings are
  errors. The only suppressed error is the pre-existing Android 13
  interface-wide missing-permission-annotation warning.
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
- The framework and KeyChain diffs pass Gitleaks.

The patch series has not yet passed a Soong platform build. Android 11 and
newer platform builds are unsupported on macOS, and Google's current
[AOSP workstation guidance](https://source.android.com/docs/setup/start/requirements)
budgets at least 400 GB of free space. Use a 64-bit Linux builder for the full
image and device-test stages.

Never add platform signing keys, device identifiers, network addresses, real
card material, credentials, or card traces to this directory.
