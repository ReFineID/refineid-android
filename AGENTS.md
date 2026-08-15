# ReFineID Android repository instructions

These rules apply to the entire repository.

## Product boundary

- The end state is native/system-browser authentication, not merely an embedded
  WebView.
- An embedded browser may be used as a diagnostic harness.
- User-facing UI is terse. Put explanations, implementation status, and
  diagnostic detail in documentation or developer tooling, not product copy.
- Debug builds carry a comprehensive sanitized trace. Release builds emit no
  logs at all; keep the sink in variant source sets and inspect release
  artifacts for trace literals and logging calls.
- Keep card transport, identity-card protocol, browser integration, and UI as
  separate boundaries.
- Treat fineid-spec as authoritative protocol behavior. Prefer refineid-core
  for reusable shipped logic. Use refineid-mono-internal as an implementation
  oracle and ReFineID-Apple as the product-behavior reference.

## Public-repository security

- Never commit or print a real PIN1, PIN2, PUK, CAN, private key, card serial,
  personal certificate, identity code, device serial, network address, APDU
  capture, or reader/card dump.
- Never put secrets into command lines, process arguments, Gradle properties,
  fixtures, screenshots, issue templates, exception messages, analytics, or
  CI output.
- PIN and CAN values must be collected on device, held only as mutable
  short-lived memory, and zeroized after use.
- Redact VERIFY commands and all sensitive APDU/PACE payloads wholesale at the
  logging boundary. Debug traces may record instruction, non-secret command
  header, lengths, status words, timings, and typed control flow; never raw
  response payloads or credential-command lengths.
- Use synthetic identities and protocol fixtures in committed tests. Real-card
  evidence stays local and contains no identifying values.
- Do not deliberately consume a PIN retry unless the recovery procedure and
  retry count are known.
- Disable application backup and screen capture wherever sensitive data can
  appear.

## Engineering

- Kotlin source follows standard Kotlin naming and formatting conventions.
- Source and committed fixtures are ASCII unless protocol fidelity requires
  exact non-ASCII data.
- Do not use magic values in production code or tests. Give protocol codes,
  fixture values, sizes, offsets, limits, and other non-obvious literals
  descriptive names, or derive them from named domain constants. Cite the
  governing specification section in implementation comments where useful.
- Keep Android framework types out of protocol logic so JVM unit tests can use
  synthetic descriptors and byte sequences.
- Every transport parser must validate lengths, message type, slot, sequence,
  and response status before exposing payload bytes.
- Hardware claims require an observed exchange on a physical device. Record
  only sanitized evidence.
- Add tests for malformed and truncated inputs, not just successful paths.
- Do not add AI attribution or co-author trailers to commits.

## Licensing

- This repository and all ReFineID source repositories named above are
  Apache-2.0.
- Retain existing copyright and license notices when adapting source between
  repositories.
