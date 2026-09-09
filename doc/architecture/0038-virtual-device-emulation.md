# ADR 0038: Android Virtual Device emulation workflow

Status: Accepted

Date: 2026-08-22

## Context

Development, UI validation, and regression testing require rapid local device
execution. Unlike physical devices which are required for hardware CCID and NFC
PACE verification, an emulated environment allows reproducible local testing of
application lifecycle, Compose rendering, navigation, and background services.

On macOS (Apple Silicon), the Android Emulator runs as a hardware-accelerated
virtual machine through macOS \`Hypervisor.framework\`, executing the actual
Android Linux kernel, system services, and the ART runtime.

## Decision

1. **CLI-Managed Virtual Devices**:
   AVDs are managed via the standard \`android\` CLI tool:
   - Create device profile: \`android emulator create medium_phone\`
   - Launch device: \`android emulator start medium_phone\`
   - Stop device: \`android emulator stop medium_phone\`

2. **Automated Deployment**:
   Release or debug artifacts can be deployed directly to the running emulator:
   \`\`\`bash
   adb -s emulator-5554 install "app/build/outputs/apk/release/refineid-${versionName}.${buildNumber}.apk"
   adb -s emulator-5554 shell am start -n fi.refineid.android/.MainActivity
   \`\`\`

3. **Hardware Boundary Scope**:
   Emulators validate UI layout, permissions, and framework service bindings.
   Real smart card hardware exchanges (USB CCID / NFC PACE) remain verified on
   physical devices (e.g. Pixel devices) as mandated by repository engineering
   guidelines.

## Consequences

- Local test cycles do not require an attached physical device for non-card flows.
- CI and local development can spin up and tear down standardized virtual devices
  on demand.
