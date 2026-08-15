# Android 13 Pixel 4 platform patches

This directory carries the ReFineID AOSP patch series for the Pixel 4 build
`TP1A.221005.002.B2`, which maps to the AOSP tag `android-13.0.0_r31`.

The series currently contains the compatibility-only first step from ADR 0012.
It adds a hidden typed private-key descriptor while preserving the existing
Keystore2 grant path. It does not yet expose an external card key.

## Upstream bases

| AOSP project | Base commit | Patch directory |
| --- | --- | --- |
| `platform/frameworks/base` | `9cc5d58d0254f472ae071b29ccf4fae93ca1cc3d` | `patches/frameworks-base` |
| `platform/packages/apps/KeyChain` | `97a7bc2ba75391487ecd3f23153cfb1ce293d6fe` | `patches/packages-apps-KeyChain` |

Apply each directory's patches to its corresponding project with `git am`, in
filename order. The new AIDL method is appended to the interface so all
existing Binder transaction numbers remain unchanged.

## Current verification

- Both patches pass `git apply --check` against their exact upstream bases.
- The AIDL interface generates with Build Tools 36; all new warnings are
  errors. The only suppressed error is the pre-existing Android 13
  interface-wide missing-permission-annotation warning.
- The descriptor and its test compile as Java 17 with warnings treated as
  errors, excluding the deprecation warning introduced by the newer local
  AndroidX test runner.
- Descriptor parcel round trips, defensive copies, and sanitized string forms
  pass on the physical Android 13 Pixel 4 using synthetic values only.
- The framework and KeyChain diffs pass Gitleaks.

The patch series has not yet passed a Soong platform build. Android 11 and
newer platform builds are unsupported on macOS, and Google's current
[AOSP workstation guidance](https://source.android.com/docs/setup/start/requirements)
budgets at least 400 GB of free space. Use a 64-bit Linux builder for the full
image and device-test stages.

Never add platform signing keys, device identifiers, network addresses, real
card material, credentials, or card traces to this directory.
