# ADR 0002: CCID message border

Status: Accepted

Date: 2026-08-15

## Context

Android USB Host exposes endpoints and byte transfers, not smart-card
semantics. Bytes returned by a reader are external input. A malformed length,
stale sequence, wrong slot, or unexpected response type must not reach the card
protocol layer.

The normative source is the USB-IF Smart Card CCID Specification, Revision 1.1:

- Section 6 defines the common 10-byte bulk-message header.
- Sections 6.1.1 and 6.1.3 define power-on and slot-status commands.
- Sections 6.2.1 and 6.2.2 define data-block and slot-status replies.
- Section 6.2.6 defines card state, command state, and failure reporting.

## Decision

CCID framing is a pure Kotlin border with no Android framework types.

Host-origin values are the fixed message type, automatic voltage selection,
reserved zero bytes, and a locally allocated sequence. The caller supplies a
validated slot. Reader-origin values are untrusted until one parser checks:

- at least the 10-byte header is present;
- the little-endian payload length is within the specification maximum;
- the received byte count exactly equals header plus declared payload;
- message type is the one required by the command;
- slot and sequence echo the command;
- reserved status bits are zero;
- card and command states are defined values;
- response-specific chain or clock state is defined;
- slot-status responses have no payload.

Failures are typed and contain only metadata, never response bytes. A successful
data block owns a defensive payload copy, has a redacted string form, and can be
zeroized after consumption.

The encoder supports get slot status, automatic-voltage power on, and one
bounded `XfrBlock`. Transfer bytes are owned and zeroized; the descriptor
selects whether they represent a TPDU or APDU. A separate credential entry
point consumes its input once.

## Failure story

Malformed or mismatched input is a protocol-desynchronization fault. The caller
closes the claimed USB session and does not guess, retry a credential command,
or expose raw bytes. A CCID-declared command failure and time extension remain
typed protocol results rather than parser failures.
