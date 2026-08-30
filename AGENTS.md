# ReFineID Android repository instructions

These rules apply to the entire repository. Less is more; terse is better.

## Product

- System-browser authentication remains the end state. The in-app browser is
  a supported login vehicle on stock Android: any HTTPS site, both card
  transports, every signature behind the holder's PIN.
- Android also serves as the RAPP reader for the other ReFineID platforms.
- User-facing UI is terse. Explanations, status, and diagnostics belong in
  documentation and developer tooling, not product copy.
- Keep card transport, identity-card protocol, browser integration, and UI as
  separate boundaries. Keep Android framework types out of protocol logic so
  JVM unit tests can use synthetic descriptors and byte sequences.
- fineid-spec governs protocol behavior. Prefer refineid-core for reusable
  shipped logic; refineid-mono-internal is the implementation oracle and
  ReFineID-Apple the product-behavior and UX reference.

## Security

- Do not leak personal or private information in commits: no real PIN, PUK,
  CAN, private key, card serial, personal certificate, identity code, device
  serial, network address, APDU capture, or reader/card dump.
- Committed tests use synthetic identities and protocol fixtures. Real-card
  evidence stays local and contains no identifying values.
- Shipped code collects PIN and CAN on device, holds them only as mutable
  short-lived memory, and zeroizes them after use.
- Debug tracing serves development and may record whatever protocol detail the
  work needs; keep credential values out of anything persisted or committed.
  Release builds emit no logs and no Internet access; keep the sink in variant
  source sets and inspect release artifacts for trace literals.
- Do not deliberately consume a PIN retry unless the recovery procedure and
  retry count are known.
- Disable application backup and screen capture wherever sensitive data can
  appear.

## Engineering

- Verify from specifications, don't wild guess. Cite what a source proves, and
  say what it does not. Where observation contradicts documentation, the
  recorded exchange wins and is cited as observation, not spec.
- If something is not working, it is by default a bug in our code or test
  harness, not a feature of the platform. "Impossible/blocked" claims require
  exchange-level evidence from a clean-slate repro.
- Hardware claims require an observed exchange on a physical device.
- Every transport parser validates lengths, message type, slot, sequence, and
  response status before exposing payload bytes.
- Add tests for malformed and truncated inputs, not just successful paths.
- No magic codes: name every protocol code, size, offset, and limit, or derive
  it from a named domain constant.
- Comments describe what the code does or the constraint it honors, never why
  it changed. A past bug, a deprecation, the reasoning for a fix belongs in
  the git commit message, not the source.
- Record findings and durable knowledge as repository documentation under
  `docs/`, written for public distribution, not in private or per-session
  assistant memory. A committed document is the shared source of truth; redact
  anything the Security section forbids before writing it down.
- Kotlin follows standard Kotlin conventions; ASCII only in source and
  committed fixtures unless protocol fidelity requires exact bytes.
- Keep the toolchain strict: warnings are errors everywhere (Kotlin extra
  warnings, full Android lint, detekt, ktlint via Spotless, Clippy, rustfmt,
  ShellCheck). `./gradlew check` runs all of it.
- The quality gates are mandatory git hooks, not suggestions. Run
  `Scripts/install-hooks.sh` once per clone (`Scripts/bootstrap-macos.sh`
  does it); pre-commit runs the fast gates, pre-push runs the full
  `./gradlew check`. Never commit or push with `--no-verify`, never disable,
  weaken, or work around a gate to land a change, and never leave the hooks
  uninstalled. This binds every contributor, human and AI agent alike: fix
  the finding, or raise the policy question openly instead of dodging it.
  GitHub Actions reruns the same `./gradlew check` floor on every push and
  pull request; a red check on the remote is a defect to fix immediately,
  not a status to explain away.
- Commit often when the build and lint are clean. Push when a feature is
  ready. Subject and body only: no AI attribution, co-author, sign-off, or
  review trailers.
- Never put a git worktree under `/tmp`; keep worktrees beside the repository.
- When stuck, research with fellow AI available.

## Licensing

- This repository and the referenced ReFineID sources are Apache-2.0.
- Retain existing copyright and license notices when adapting source between
  repositories.
