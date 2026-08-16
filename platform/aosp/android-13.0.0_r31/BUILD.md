# Build the Pixel 4 image

This runbook builds the pinned Android 13 `aosp_flame-userdebug` image. It does
not download separately licensed vendor files, unlock a bootloader, or flash a
device.

## Builder

Use an x86_64 Linux host. Before checkout, provide at least 400 GB of free
space; after checkout, the build script requires 150 GiB to remain free. Google
recommends 64 GiB of RAM. These are the current
[AOSP workstation requirements](https://source.android.com/docs/setup/start/requirements).

The ReFineID Gradle build requires OpenJDK 26 through `JAVA_HOME`. After staging
the app, the build script clears `JAVA_HOME` so AOSP can select its pinned Java
toolchain.

Patch applicability can be checked on any current Git host without a full AOSP
checkout:

    Scripts/audit-aosp-patches.sh

The audit creates sparse temporary checkouts of only the exact upstream files
touched by the series. `--replay` additionally runs the complete release gate,
stages the unsigned APK, replays every `git am`, and compares the resulting
trees with the expected patch trees. Replay requires the Android SDK and JDK 26
but not the proprietary Pixel archives.

## Source

Create and sync the exact AOSP tag:

    repo init \
      -u https://android.googlesource.com/platform/manifest \
      -b android-13.0.0_r31
    repo sync -c --no-tags

The tag maps to Pixel build `TP1A.221005.002.B2` in Google's
[build-number table](https://source.android.com/docs/setup/reference/build-numbers).

## Pixel binaries

A physical Pixel build needs the matching proprietary binaries. Download both
Pixel 4 (`flame`) archives from Google's
[driver-binary page](https://developers.google.com/android/drivers/), verify
their SHA-256 digests, unpack them at the AOSP root, and run each extraction
script. The extraction scripts present their respective licenses.

| Archive | SHA-256 |
| --- | --- |
| [`google_devices-flame-tp1a.221005.002.b2-22399ead.tgz`](https://dl.google.com/dl/android/aosp/google_devices-flame-tp1a.221005.002.b2-22399ead.tgz) | `fc2bc6cd2fde8d96641d624d68260b5392ad62e3d031d81659fad21d654f57e0` |
| [`qcom-flame-tp1a.221005.002.b2-358af558.tgz`](https://dl.google.com/dl/android/aosp/qcom-flame-tp1a.221005.002.b2-358af558.tgz) | `4793dcccf3c61593110ce35efafa5f60064fcc84f4921ed79be676027b33ee03` |

After extraction, these files must exist:

    vendor/google_devices/coral/proprietary/device-vendor.mk
    vendor/google_devices/flame/device-partial.mk
    vendor/qcom/flame/device-partial.mk

The binaries and generated `vendor/` trees are not part of ReFineID and must
not be copied into this public repository.

## ReFineID and patches

Clone this repository at its fixed product path:

    git clone \
      https://github.com/ReFineID/refineid-android \
      packages/apps/ReFineID

From the AOSP root, first verify all pinned bases without changing them:

    packages/apps/ReFineID/Scripts/apply-aosp-patches.sh \
      --check-base "$PWD"

Configure a Git committer identity before this check; applying the patch series
creates local AOSP commits.

Then build the unsigned, minimized app and apply all patch series:

    packages/apps/ReFineID/Scripts/apply-aosp-patches.sh "$PWD"

The command preflights every complete series in a temporary Git index before
modifying any AOSP project. It stops on a dirty or mismatched checkout.

## Build

With `JAVA_HOME` still selecting OpenJDK 26, run:

    packages/apps/ReFineID/Scripts/build-aosp-flame.sh

The script verifies the exact final patch trees and vendor files, stages the
unsigned release APK, builds the changed framework modules plus `KeystoreTests`
and `KeyChainTests`, builds the full image, and checks that the installed
ReFineID and KeyChain APKs share the platform signer. It also refuses an AOSP
tree whose manifest checkout is not the exact `android-13.0.0_r31` commit.

After the patched image is running, verify it from the same clean Linux
checkout:

    packages/apps/ReFineID/Scripts/verify-aosp-flame-device.sh

The verifier checks the exact source and manifest revisions, device build,
installed product paths and bytes, platform signer relationship, privileged
regular-UID package state, permissions, provider discovery, enforcing
`refineid_app` SELinux domain, and every new `KeystoreTests` and
`KeyChainTests` class. It suppresses raw `atest` output so a device identifier
does not enter captured build output.

This is the platform gate, not the browser result. Continue with
[`BROWSER-ACCEPTANCE.md`](BROWSER-ACCEPTANCE.md) for the independent Chrome,
Firefox, and valid-card service checks.

## Flash gate

The bootloader must be unlocked before a custom image can be flashed. Unlocking
requires physical confirmation and erases all user data. The first full flash
also uses a data wipe. See Google's
[Fastboot instructions](https://source.android.com/docs/setup/test/running).

Keep flashing outside the build scripts. Before it is authorized, confirm a
recoverable device backup, the matching factory image, OEM unlocking, and a
direct host USB data connection. Wireless ADB and the card-reader connection
are not available in bootloader mode.
