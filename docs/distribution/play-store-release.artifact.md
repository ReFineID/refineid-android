# Play Store Release Process

Status: Active

Date: 2026-08-22

## Context

The ReFineID Android app is distributed through the Google Play Store. To ensure
consistent, secure, and compliant releases, the distribution process is
automated using the Gradle Play Publisher (GPP) plugin and a dedicated release
script.

## Automation

The `com.github.triplet.play` plugin manages the communication with the Google
Play Developer API. It is configured in the `:app` module to:

1. Use a service account for authentication, loaded from `play.properties`.
2. Default to the `internal` test track for new uploads.
3. Build and upload Android App Bundles (AAB).

The `Scripts/release-play-store.sh` orchestrates the release sequence:

- **Branch Validation**: Requires the `main` branch.
- **State Validation**: Requires a clean git working directory.
- **Versioning**: Calls `Scripts/stamp-version.sh` to update `versionName` and
  `versionCode` based on the current UTC time.
- **Compliance**: Runs `./gradlew check` to verify lint, Detekt, Rust Clippy,
  and release-specific security checks (no logging, network isolation).
- **Publishing**: Executes `publishReleaseBundle` to upload the bundle to the
  internal track.

## Configuration

Credentials and environment-specific settings are kept in `play.properties` at
the repository root. This file is excluded from version control to prevent
secret leakage.

A template is provided in `play.properties.example`:

```properties
# Google Play Store credentials
# The path is relative to the repository root.
serviceAccountCredentials=path/to/service-account.json
```

## Security Consequences

- Google Play service account keys must never be committed to the repository.
- The release script enforces a clean `main` branch to ensure that only
  reviewed and compliant code reaches the Play Store.
- Version stamping happens just before the build to ensure unique, traceable
  artifacts.
- The `./gradlew check` step ensures that release-specific security constraints,
  such as the absence of forbidden logging materials and mandatory network
  isolation, are honored.
