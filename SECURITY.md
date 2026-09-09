# Security Policy
 
ReFineID handles card credentials and retry-limited operations. Please report
security issues privately to petri.koistinen@refineid.fi or through GitHub's
**Report a vulnerability** action on the repository Security tab. Do not open a
public issue for a suspected secret leak, credential-handling flaw, card-lockout
risk, or signature bypass.

Never include a real PIN, PUK, candidate PIN length, private key, personal identity code,
certificate private material, or raw credential APDU in a report. Use structural
descriptions and synthetic values. Maintainers can arrange a safer evidence
transfer when needed.

## Inviolable Rule #1: PIN codes NEVER travel over any network

PIN codes (PIN1 and PIN2) NEVER leave the mobile device when accessed via RAPP.
RAPP must absolutely deny and preclude all attempts to transport PIN codes anywhere:
- The protocol wire format has no field or message for PIN codes.
- PIN1 remains in protected on-device cache on the phone.
- PIN2 prompts appear exclusively on the mobile device screen.
- Remote clients and browsers operate via a protected authentication path without any PIN prompts or transport.

## Inviolable Rule #2: Zero PIN and PIN-length logging across all environments

PIN codes (PIN1, PIN2), PUK, and CAN are never logged in any development, test,
staging, or production context. Furthermore, PIN lengths and candidate digit counts
must never be logged or rendered in error messages, audit records, or diagnostic traces.
Length disclosures leak secret entropy and reduce keyspace security. Diagnostic output,
tracing (`AppTrace`), event logs, and `Display`/`Error`/exception messages must never include
PIN values, PIN lengths, or candidate digit counts. If specialized debugging is ever
needed, it is done via temporary private harnesses and never checked into the repository.

