# ADR 0004: APDU transport border

Status: Accepted

Date: 2026-08-15

## Context

The Android USB layer must move APDUs without becoming a second FINEID
implementation. The public `refineid-core` already owns typed ISO 7816
commands, PKCS#15 reads, retry-safe PIN operations, and card-side signing.
Android supplies the physical CCID exchange.

The governing sources are:

- USB-IF CCID Revision 1.1, functional descriptor offsets 40 and 44,
  sections 6.1.4 and 6.2.1;
- FINEID S1 v4.2 sections 3.3, 3.5, 3.6, 3.7, and 3.8, plus Annex B;
- FINEID S4-1 v4.2 sections 4.1 and 5.

## Trust origins and predicates

Three independent borders admit bytes:

1. Host APDUs originate only from typed `refineid-core` builders. JNI does
   not expose an arbitrary application-facing APDU constructor.
2. USB descriptors originate in the reader. A Kotlin constructor validates
   descriptor framing, the selected CCID interface, one defined exchange
   level, automatic APDU parameter handling, and the declared message bound.
3. CCID replies originate in the reader and remain untrusted until the common
   parser validates length, type, slot, sequence, status, and response-specific
   fields. An APDU reply must contain at least its two status bytes.

Readers declaring T=0 TPDU, short-APDU, or short-and-extended-APDU exchange are
admitted. Character-level and T=1 TPDU exchange require protocol engines that
are outside this slice. Treating a TPDU payload as an APDU would be wrong.

## Decision

Rust owns a synchronous logical card operation and calls an Android transport
object for individual APDU exchanges. The transport has distinct public and
credential methods.

The public path may apply the one wrong-`Le` correction authorized by the
typed command. The credential path consumes its command and submits it once;
it never corrects or retries that command. Both paths may settle a `61xx`
response with new, credential-free GET RESPONSE commands. Chaining is bounded
by response length and forward progress.

For APDU-level readers, Kotlin wraps one APDU in `PC_to_RDR_XfrBlock`. For a
T=0 TPDU reader, Rust lowers the typed command to one of the three T=0 TPDU
forms before Kotlin wraps it. Case 4 omits its trailing expected length and
uses the ordinary typed `61xx`/GET RESPONSE path. Both modes use zero BWI and
level parameter and must fit the validated reader message bound. A complete
successful `RDR_to_PC_DataBlock` is returned to Rust; intermediate buffers are
zeroized. Debug tracing records sanitized metadata only.

The native operation retains the claimed USB session from the counter-safe PIN
status probe through VERIFY and signing. A reset, application reselection,
reader removal, timeout, malformed reply, or generation change invalidates the
operation and any credential state.

## Credential gate

FINEID S1 section 3.5 states that an empty-data VERIFY reports verification
state and remaining attempts without decrementing the counter, while a failed
credential VERIFY decrements it. Therefore Android must:

1. select the FINEID application;
2. resolve the credential numbering and probe PIN1 status;
3. refuse operation at the core consumer retry floor;
4. obtain explicit user consent and secure PIN entry;
5. submit exactly one typed VERIFY;
6. sign only after the card reports successful verification.

No automatic credential retry is permitted. PIN arrays are mutable,
short-lived, excluded from state restoration and diagnostics, and zeroized on
every return path.

## Failure story

Malformed descriptors or CCID frames close the session as protocol
desynchronization. Reader loss, card absence, reset, timeout, and backend
failure remain distinct transport outcomes for the core. A wrong PIN is a
typed card outcome carrying only the remaining count. Any credential transport
uncertainty destroys the candidate and requires a fresh user action; it never
replays the command.

This slice proves transport semantics only after a non-credential APDU is
observed on physical Android hardware. PIN and signing claims require their own
counter-framed hardware evidence.

## Physical evidence

On 2026-08-15, a generic class-matched TPDU reader and T=0 card were exercised
through Android USB Host. The claimed interface remained open after reset and
ATR validation while the native core built and submitted the typed PKCS#15
application selection. The card returned normal completion and the app retained
the ready session. A subsequent refresh released the interface, opened a new
session, and repeated the selection successfully. No credential command was
sent, and no raw ATR, response payload, reader identity, device identity, or
card identity was recorded.
