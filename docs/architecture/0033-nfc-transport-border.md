# ADR 0033: NFC transport border

Status: Accepted

Date: 2026-08-17

## Context

The product end state includes contactless operation: the Apple reference
opens a card presented on a contactless reader with the access number printed
on its face. On Android, `NfcAdapter` reader mode delivers a discovered tag,
and `IsoDep` moves complete ISO 7816-4 APDUs over ISO/IEC 14443-4.

A FINEID contactless session protects every PKCS#15 operation behind PACE
with the card access number, followed by secure messaging. Both exist in
`refineid-core` (`refineid-pace`), but they require CAN entry, session state
that survives one native call, and their own counter-framed hardware
evidence. None of that belongs in the first contactless slice.

`EF.CardAccess` (file identifier `011C` under the MF) is the one file
designed to be read before PACE: it advertises the PACE protocol variants
and domain parameters the card supports (ICAO 9303-11 section 9.2, BSI
TR-03110-3 appendix A.1.1.4). Reading it is credential-free, works on the
plain interface, and proves the entire Android NFC transport stack against
a real card.

The governing sources are:

- ISO/IEC 14443-4 for ISO-DEP framing (owned by Android's `IsoDep`);
- ICAO 9303-11 section 9.2 and BSI TR-03110-3 appendices A.1.1.1 and
  A.1.1.4 for `EF.CardAccess` and `PACEInfo`;
- FINEID S4-2 for the published PACE profile:
  `id-PACE-ECDH-GM-AES-CBC-CMAC-256`, version 2, on brainpoolP384r1 under
  the FINEID `parameterId` `0x10`.

## Decision

NFC is a second transport behind the existing native block-exchange border.
Kotlin owns discovery and byte movement; Rust owns every command byte and
every parse, exactly as on USB.

1. Reader mode binds to the foreground activity with NFC-A, NFC-B, and the
   NDEF-check skip. Each discovered tag yields one `IsoDep` channel, opened
   and closed on a dedicated worker thread with a bounded transceive
   timeout. A device without an NFC antenna shows no contactless control at
   all, mirroring the Apple reference.
2. The channel adapts to the same `NativeBlockExchange` callback the CCID
   session uses, at APDU exchange level. The Kotlin adapter validates
   lengths only: a command must fit the tag's maximum transceive length,
   and a response must carry at least its two status bytes and stay within
   the extended-length bound. A lost tag is the typed no-card outcome; any
   other transceive failure is timeout-with-unknown-state, because the
   card's state is genuinely unknown.
3. One new native operation, `probe_card_access`, selects the MF, selects
   file `011C`, reads one bounded DER object, and parses the
   `SecurityInfos` set. Host APDUs originate only from typed
   `refineid-core` builders. The parser recognizes a closed set of PACE
   protocol OIDs, skips spec-legal unrecognized siblings without retaining
   a byte, rejects trailing bytes past the outer TLV, and fails loudly
   when no recognized entry remains. Only a typed summary crosses JNI:
   whether the published FINEID profile is advertised, and the recognized
   entry count.
4. There is no ATR on ISO-DEP, so the contactless recognition gate is the
   parsed `EF.CardAccess`, not ATR validation. The card-side answer decides
   the terse UI outcome: recognized, not supported, or a transport error.

No credential crosses the NFC border in this slice. PACE, secure
messaging, CAN custody, and any contactless PKCS#15 operation are later
slices with their own borders; the PACE channel composes as a transport
beneath the same native operations when it arrives.

## Failure story

Tag loss at any point returns the reader to waiting; another tap starts
over. A select or read rejected by status word, an empty or oversized
file, malformed BER, and a file with no recognized PACE entry are all the
same holder-facing answer: this card is not supported here. Exchange
faults and bridge failures stay distinct transport errors. Debug traces
record adapter state, coarse results, lengths, and timings; never file
bytes, OIDs, or identifiers. Release builds trace nothing.

## Verification

Rust unit tests lock the closed OID set, the published-profile predicate,
sibling skipping, trailing-byte and truncation rejection, the error
mapping, and the JNI reply encoding, including a production
`EF.CardAccess` capture that carries only public protocol parameters.
Kotlin unit tests lock the strict reply decoder, the exchange length
gates, the typed transceive outcomes, and the status mapping.

## Physical evidence

On 2026-08-17, a production old-generation card resting on the physical
Pixel 4 was discovered through reader mode, and the credential-free
`EF.CardAccess` probe completed over ISO-DEP in tens of milliseconds:
one recognized `PACEInfo` entry advertising the published FINEID
profile, surfaced as the terse recognized state. Repeated discoveries
of the resting card reproduced the same result. No credential command
was sent, and no card or device identifier was recorded.
