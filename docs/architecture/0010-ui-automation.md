# ADR 0010: Native Android UI automation

Status: Accepted

Date: 2026-08-15

## Context

The Android port needs the same kind of user-journey automation that the Apple
application obtains from XCUITest. ReFineID also has two distinct UI scopes:
its own Compose hierarchy and flows that cross into Android system UI or a
browser. A single Android framework is not the best tool for both scopes.

Authentication tests must never embed or retrieve a real PIN. An automated
hardware test must not submit a guessed credential or consume a retry. Screen
captures and hierarchy dumps are also unsuitable wherever holder information
or credential input could be visible.

## Decision

Instrumented UI tests run from `app/src/androidTest` under
`AndroidJUnitRunner` and use two Google-provided layers:

- Compose UI Test v2 drives and asserts the app-owned Compose hierarchy. Its
  synchronization with recomposition makes it the default for screen behavior.
- UI Automator 2.4 drives opaque-box, cross-process journeys involving system
  permission UI, browser applications, and other Android-owned windows. It is
  the direct counterpart to the cross-application part of XCUITest.

Product controls carry stable, locale-independent test tags. The root enables
`testTagsAsResourceId`, making the same contract visible through Compose
semantics and the accessibility tree used by UI Automator. Tests do not select
product controls by translated labels.

The suite verifies the secure field semantics, input bounds, one-shot synthetic
submission, field clearing, disabled signing state, permission action,
card-absence behavior, terse browser-action visibility, real application
launch, and accessibility-tree visibility. Device-side tests also exercise the
four browser JCA algorithms and the fingerprint-pinned issuer set through the
Android runtime. The UI Automator launcher uses a normal explicit Android
intent; the app is not granted network access merely to support a test-only
shell launcher.

## Credential and evidence policy

UI tests may use named synthetic PIN-shaped values only with fake callbacks.
They must never read a credential from an environment variable, Gradle
property, file, command line, device clipboard, screenshot, or accessibility
dump. A physical signing run remains holder-driven: automation may bring the
app to the secure field and observe a coarse result, but it does not enter or
submit the credential.

Test artifacts must not contain page text from an authenticated browser,
certificate contents, card or reader identifiers, device identifiers, network
addresses, status words, retry counts, or signature bytes. Release builds keep
the manual authentication surface absent.

## Execution

Run local and instrumented UI checks with:

    ./gradlew check connectedDebugAndroidTest

`connectedDebugAndroidTest` is a physical-device or emulator gate. Browser
integration will extend the UI Automator layer rather than introducing a
third-party driver.
