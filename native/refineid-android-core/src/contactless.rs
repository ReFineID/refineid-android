//! One-shot contactless card operations behind the PACE secure channel.
//!
//! Each operation owns one raw ISO-DEP transport for its whole lifetime:
//! it runs the PACE handshake with the holder's card access number,
//! wraps the transport in secure messaging, selects the PKCS#15
//! application, and performs exactly one logical operation before
//! returning the exchange to the JNI border. No channel state survives
//! the call; the next operation runs PACE again. The secure-messaging
//! layer is itself a card transport, so the reviewed public operations
//! run unchanged above it (FINEID S4-2; BSI TR-03110).

use std::sync::Mutex;

use refineid_apdu::{CardTransport, TransportOutcome};
use refineid_emrtd::{
    CscaAnchor, CscaAnchors, EmrtdOps, ParsedMrzTd1, authenticate_document, parse_card_face_image,
};
use refineid_pace::{Can, PaceError, PaceSession, SmTransport, UnvalidatedCan, run_pace_with_can};
use refineid_pkcs15::{Pkcs15Error, Pkcs15Ops};

use crate::authentication_signer::{
    AuthenticationSignFailure, AuthenticationSignature, AuthenticationSigningAlgorithm,
    AuthenticationSigningInput, authenticate_and_sign,
};
use crate::card_certificate::{
    CardCertificate, CertificateReadFailure, map_pkcs15_error, read_authentication_certificate,
    read_qualified_certificate,
};
use crate::card_transport::{AndroidCardTransport, SingleBlockExchange};
use crate::pin1_status::{Pin1Preflight, Pin1PreflightFailure, probe_pin1_preflight};
use crate::pin2_status::{Pin2Preflight, Pin2PreflightFailure, probe_pin2_preflight};
use crate::qualified_signer::{
    QualifiedCertificateSource, QualifiedSignFailure, QualifiedSignature,
    QualifiedSigningAlgorithm, qualified_sign,
};

/// Coarse failures of the secure-channel front door, before any
/// operation-specific vocabulary applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecureChannelFailure {
    /// Card left the field during the handshake.
    CardUnavailable,
    /// The card refused the handshake; almost always a wrong CAN.
    PaceRejected,
    /// The exchange failed, desynchronized, or left state uncertain.
    Transport,
    /// A local shape or facility failure that never touched the card.
    Bridge,
}

/// The host half of one live contactless secure-messaging session: the
/// PACE keys and the send-sequence counter, held between JNI calls for as
/// long as the reader keeps the RF field up. The card keeps its matching
/// half alive across that same field; rebuilding [`SmTransport`] from this
/// stored session on each call keeps host and card in step, so every
/// operation after the connect skips the PACE handshake and pays only a
/// cheap PKCS#15 re-select. Dropping the field (close, card removed) clears
/// the slot and the keys with it. One slot: the reader drives one card at a
/// time, and a fresh connect supersedes whatever it held.
static HELD_SESSION: Mutex<Option<PaceSession>> = Mutex::new(None);

/// Adopt the live session for reuse by the next operation under the same
/// field. A poisoned lock silently drops the session: the next operation
/// finds no session and the holder reconnects, which is the safe outcome.
fn store_held_session(session: PaceSession) {
    if let Ok(mut slot) = HELD_SESSION.lock() {
        *slot = Some(session);
    }
}

/// Take the live session, leaving the slot empty. The caller either rebuilds
/// the channel and stores the advanced session back, or lets it drop and the
/// keys with it.
fn take_held_session() -> Option<PaceSession> {
    HELD_SESSION.lock().ok().and_then(|mut slot| slot.take())
}

/// Drop any held session and the keys with it. Idempotent: closing an
/// already-closed session is a no-op.
pub(crate) fn contactless_close() {
    if let Ok(mut slot) = HELD_SESSION.lock() {
        *slot = None;
    }
}

/// The latest face photo bytes extracted from EF.DG2 under secure messaging.
static LAST_READ_FACE_PHOTO: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// The latest MRZ document number extracted from EF.DG1 under secure
/// messaging; the printed card number that makes exported photo file
/// names globally unique.
static LAST_READ_DOCUMENT_NUMBER: Mutex<Option<String>> = Mutex::new(None);

/// Passive authentication was not attempted for the last read (no
/// eMRTD files, or no trust anchors installed).
pub(crate) const VERIFICATION_NOT_PERFORMED: i32 = 0;
/// Passive authentication ran and the document verified: SOD
/// signature, DG1 and DG2 hashes, and the DSC-to-CSCA chain.
pub(crate) const VERIFICATION_PASSED: i32 = 1;
/// Passive authentication ran and the document did not verify.
pub(crate) const VERIFICATION_FAILED: i32 = 2;

/// The latest passive-authentication verdict, one of the
/// `VERIFICATION_*` codes above.
static LAST_READ_VERIFICATION: Mutex<i32> = Mutex::new(VERIFICATION_NOT_PERFORMED);

/// Trusted CSCA anchor certificates (DER), installed by the platform
/// at startup and consumed by every subsequent card read. Raw bytes
/// are stored and parsed per read, so an unparsable anchor surfaces at
/// verification time instead of poisoning installation.
static CSCA_ANCHOR_DERS: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

pub(crate) fn get_last_read_verification() -> i32 {
    LAST_READ_VERIFICATION
        .lock()
        .map_or(VERIFICATION_NOT_PERFORMED, |guard| *guard)
}

pub(crate) fn set_last_read_verification(verdict: i32) {
    if let Ok(mut guard) = LAST_READ_VERIFICATION.lock() {
        *guard = verdict;
    }
}

pub(crate) fn add_csca_anchor(anchor_der: Vec<u8>) {
    if let Ok(mut guard) = CSCA_ANCHOR_DERS.lock() {
        guard.push(anchor_der);
    }
}

pub(crate) fn clear_csca_anchors() {
    if let Ok(mut guard) = CSCA_ANCHOR_DERS.lock() {
        guard.clear();
    }
}

/// Parse the installed anchor DERs into a verification-ready set.
/// `None` when no anchors are installed or none parse.
fn installed_csca_anchors() -> Option<CscaAnchors> {
    let ders = CSCA_ANCHOR_DERS.lock().ok()?;
    let anchors: Vec<CscaAnchor> = ders
        .iter()
        .filter_map(|der| CscaAnchor::from_der(der).ok())
        .collect();
    if anchors.is_empty() {
        None
    } else {
        Some(CscaAnchors::new(anchors))
    }
}

pub(crate) fn get_last_read_face_photo() -> Option<Vec<u8>> {
    LAST_READ_FACE_PHOTO
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

pub(crate) fn set_last_read_face_photo(photo: Option<Vec<u8>>) {
    if let Ok(mut guard) = LAST_READ_FACE_PHOTO.lock() {
        *guard = photo;
    }
}

pub(crate) fn get_last_read_document_number() -> Option<String> {
    LAST_READ_DOCUMENT_NUMBER
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

pub(crate) fn set_last_read_document_number(document_number: Option<String>) {
    if let Ok(mut guard) = LAST_READ_DOCUMENT_NUMBER.lock() {
        *guard = document_number;
    }
}

/// One PACE handshake, then the PKCS#15 selection, authentication
/// certificate read, and counter-safe PIN1 preflight inside the same
/// secure-messaging session. This is the contactless session opener:
/// everything the browser path caches arrives under one handshake.
pub(crate) fn contactless_open<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    can_bytes: Vec<u8>,
) -> (
    Result<(CardCertificate, Pin1Preflight), CertificateReadFailure>,
    Exchange,
) {
    let mut secure = match open_secure_channel(transport, can_bytes) {
        Ok(secure) => secure,
        Err((exchange, failure)) => {
            return (Err(certificate_channel_failure(failure)), exchange);
        }
    };
    let result = secure
        .select_pkcs15_application()
        .map_err(map_pkcs15_error)
        .and_then(|()| read_authentication_certificate(&mut secure))
        .and_then(|certificate| {
            probe_pin1_preflight(&mut secure)
                .map(|preflight| (certificate, preflight))
                .map_err(open_preflight_failure)
        });
    if result.is_ok() {
        read_minimal_emrtd_data_from_secure_channel(&mut secure);
    }
    (result, secure.into_inner().into_exchange())
}

/// PACE, then secure messaging, then the one-shot preflight, VERIFY,
/// and signing sequence. The PIN is zeroized on every path that stops
/// before the reviewed signer consumes it.
pub(crate) fn contactless_authenticate_and_sign<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    can_bytes: Vec<u8>,
    algorithm: AuthenticationSigningAlgorithm,
    mut pin_bytes: Vec<u8>,
    input: AuthenticationSigningInput<'_>,
) -> (
    Result<AuthenticationSignature, AuthenticationSignFailure>,
    Exchange,
) {
    let mut secure = match open_secure_channel(transport, can_bytes) {
        Ok(secure) => secure,
        Err((exchange, failure)) => {
            pin_bytes.fill(0);
            return (Err(sign_channel_failure(failure)), exchange);
        }
    };
    if let Err(error) = secure.select_pkcs15_application() {
        pin_bytes.fill(0);
        return (
            Err(sign_selection_failure(error)),
            secure.into_inner().into_exchange(),
        );
    }
    let result = authenticate_and_sign(&mut secure, algorithm, pin_bytes, input);
    (result, secure.into_inner().into_exchange())
}

/// The persistent-session opener. One PACE handshake, then the PKCS#15
/// selection, authentication-certificate read, and counter-safe PIN1
/// preflight -- byte for byte the one-shot [`contactless_open`] sequence.
/// The one difference is the ending: on full success the live
/// secure-messaging session (keys and send-sequence counter) is retained,
/// so the sign that follows reuses this channel instead of running PACE a
/// second time. A failed open retains nothing and the holder reconnects.
pub(crate) fn contactless_connect<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    can_bytes: Vec<u8>,
) -> (
    Result<(CardCertificate, Pin1Preflight), CertificateReadFailure>,
    Exchange,
) {
    // A fresh connect supersedes any session a prior card left behind.
    contactless_close();
    let mut secure = match open_secure_channel(transport, can_bytes) {
        Ok(secure) => secure,
        Err((exchange, failure)) => {
            return (Err(certificate_channel_failure(failure)), exchange);
        }
    };
    let result = secure
        .select_pkcs15_application()
        .map_err(map_pkcs15_error)
        .and_then(|()| read_authentication_certificate(&mut secure))
        .and_then(|certificate| {
            probe_pin1_preflight(&mut secure)
                .map(|preflight| (certificate, preflight))
                .map_err(open_preflight_failure)
        });
    if result.is_ok() {
        read_minimal_emrtd_data_from_secure_channel(&mut secure);
    }
    let (transport, session) = secure.into_parts();
    if result.is_ok() {
        store_held_session(session);
    }
    (result, transport.into_exchange())
}

/// The authentication signature on an already-open session: no PACE, only
/// a cheap PKCS#15 re-select before VERIFY and signing on the retained
/// channel. The PIN is zeroized on every path that stops before the
/// reviewed signer consumes it. On completion the advanced session is
/// retained for any further operation under the same field. A missing
/// session -- never connected, or the field dropped between calls -- is a
/// bridge fault: the holder connects again to prove a fresh CAN.
pub(crate) fn contactless_authenticate_and_sign_on_session<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    algorithm: AuthenticationSigningAlgorithm,
    mut pin_bytes: Vec<u8>,
    input: AuthenticationSigningInput<'_>,
) -> (
    Result<AuthenticationSignature, AuthenticationSignFailure>,
    Exchange,
) {
    let Some(session) = take_held_session() else {
        pin_bytes.fill(0);
        return (
            Err(AuthenticationSignFailure::Bridge),
            transport.into_exchange(),
        );
    };
    let mut secure = SmTransport::new(transport, session);
    if let Err(error) = secure.select_pkcs15_application() {
        pin_bytes.fill(0);
        // The channel is troubled; drop the session and require a reconnect.
        return (
            Err(sign_selection_failure(error)),
            secure.into_inner().into_exchange(),
        );
    }
    let result = authenticate_and_sign(&mut secure, algorithm, pin_bytes, input);
    // Keep the advanced session alive for any further operation this field.
    let (transport, session) = secure.into_parts();
    store_held_session(session);
    (result, transport.into_exchange())
}

/// Serve the qualified-certificate read across the PACE secure channel.
/// Secure messaging is itself a card transport, so the reviewed
/// EF.4332 read runs unchanged above it, exactly as on the wired path.
impl<T: CardTransport> QualifiedCertificateSource for SmTransport<T> {
    fn read_qualified_certificate_for_signing(
        &mut self,
    ) -> Result<CardCertificate, CertificateReadFailure> {
        read_qualified_certificate(self)
    }
}

/// PACE, then the PKCS#15 selection and one qualified-certificate read
/// inside the same secure-messaging session. The one-shot channel does
/// not carry the wired path's context-restore step: the next operation
/// opens a fresh handshake, so no auth-context state has to survive.
pub(crate) fn contactless_read_qualified_certificate<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    can_bytes: Vec<u8>,
) -> (Result<CardCertificate, CertificateReadFailure>, Exchange) {
    let mut secure = match open_secure_channel(transport, can_bytes) {
        Ok(secure) => secure,
        Err((exchange, failure)) => {
            return (Err(certificate_channel_failure(failure)), exchange);
        }
    };
    let result = secure
        .select_pkcs15_application()
        .map_err(map_pkcs15_error)
        .and_then(|()| read_qualified_certificate(&mut secure));
    (result, secure.into_inner().into_exchange())
}

/// PACE, then the PKCS#15 selection and a counter-safe PIN2 preflight
/// inside secure messaging. The session CAN was proven at connect, so
/// a channel refusal here folds to a transport anomaly, not a CAN fault.
pub(crate) fn contactless_probe_pin2<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    can_bytes: Vec<u8>,
) -> (Result<Pin2Preflight, Pin2PreflightFailure>, Exchange) {
    let mut secure = match open_secure_channel(transport, can_bytes) {
        Ok(secure) => secure,
        Err((exchange, failure)) => {
            return (Err(pin2_channel_failure(failure)), exchange);
        }
    };
    let result = secure
        .select_pkcs15_application()
        .map_err(pin2_selection_failure)
        .and_then(|()| probe_pin2_preflight(&mut secure));
    (result, secure.into_inner().into_exchange())
}

/// PACE, then the PKCS#15 selection and one qualified signature inside
/// secure messaging. The PIN2 is zeroized on every path that stops
/// before the reviewed signer consumes it.
pub(crate) fn contactless_qualified_sign<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    can_bytes: Vec<u8>,
    algorithm: QualifiedSigningAlgorithm,
    mut pin_bytes: Vec<u8>,
    content: &[u8],
    expected_certificate: &[u8],
) -> (Result<QualifiedSignature, QualifiedSignFailure>, Exchange) {
    let mut secure = match open_secure_channel(transport, can_bytes) {
        Ok(secure) => secure,
        Err((exchange, failure)) => {
            pin_bytes.fill(0);
            return (Err(qualified_channel_failure(failure)), exchange);
        }
    };
    if let Err(error) = secure.select_pkcs15_application() {
        pin_bytes.fill(0);
        return (
            Err(qualified_selection_failure(error)),
            secure.into_inner().into_exchange(),
        );
    }
    let result = qualified_sign(
        &mut secure,
        algorithm,
        pin_bytes,
        content,
        expected_certificate,
    );
    (result, secure.into_inner().into_exchange())
}

/// Reconstruct the typed CAN and run the PACE handshake. On failure the
/// exchange is handed back so the JNI border can inspect it.
fn open_secure_channel<Exchange: SingleBlockExchange>(
    mut transport: AndroidCardTransport<Exchange>,
    can_bytes: Vec<u8>,
) -> Result<SmTransport<AndroidCardTransport<Exchange>>, (Exchange, SecureChannelFailure)> {
    let Some(can) = reconstruct_can(can_bytes) else {
        return Err((transport.into_exchange(), SecureChannelFailure::Bridge));
    };
    if let Err(failure) = abort_stale_secure_messaging(&mut transport) {
        return Err((transport.into_exchange(), failure));
    }
    match run_pace_with_can(&mut transport, can) {
        Ok(session) => Ok(SmTransport::new(transport, session)),
        Err(error) => {
            let failure = map_pace_error(&error);
            Err((transport.into_exchange(), failure))
        }
    }
}

/// Return a connection possibly left inside an earlier secure-messaging
/// session to plain state before the handshake.
///
/// ISO 7816-4 terminates a secure-messaging session when a plain APDU
/// arrives, and the card may reject that terminating command with a
/// status word (observed on the production FINEID card: the first plain
/// command after a completed session is refused, the next is processed
/// in plain). One replay-safe, credential-free SELECT MF absorbs that
/// termination deterministically; its status word is deliberately not
/// interpreted, and only transport-level faults stop the open.
fn abort_stale_secure_messaging<T: CardTransport>(
    transport: &mut T,
) -> Result<(), SecureChannelFailure> {
    match transport.select_mf() {
        Ok(()) | Err(Pkcs15Error::Status(_)) => Ok(()),
        Err(Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved)) => {
            Err(SecureChannelFailure::CardUnavailable)
        }
        Err(
            Pkcs15Error::Transport(_)
            | Pkcs15Error::Outcome(
                TransportOutcome::TimeoutUnknownState
                | TransportOutcome::CardReset
                | TransportOutcome::ProtocolDesync
                | TransportOutcome::Response(_),
            ),
        ) => Err(SecureChannelFailure::Transport),
        Err(
            Pkcs15Error::Aid(_)
            | Pkcs15Error::Command(_)
            | Pkcs15Error::Empty
            | Pkcs15Error::TooLarge
            | Pkcs15Error::InvalidData(_),
        ) => Err(SecureChannelFailure::Bridge),
    }
}

/// Rebuild the typed CAN from its owned digit bytes; the Kotlin entry
/// gate makes a local shape failure a bridge fault, not a card outcome.
fn reconstruct_can(can_bytes: Vec<u8>) -> Option<Can> {
    let text = match String::from_utf8(can_bytes) {
        Ok(text) => text,
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.fill(0);
            return None;
        }
    };
    Can::reconstruct(UnvalidatedCan::from_owned_text(text)).ok()
}

fn map_pace_error<E>(error: &PaceError<E>) -> SecureChannelFailure {
    match error {
        PaceError::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            SecureChannelFailure::CardUnavailable
        }
        PaceError::Status(_, _) | PaceError::AuthMismatch => SecureChannelFailure::PaceRejected,
        PaceError::Transport(_)
        | PaceError::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync
            | TransportOutcome::Response(_),
        )
        | PaceError::Ber(_)
        | PaceError::UnexpectedResponse(_)
        | PaceError::InvalidPoint => SecureChannelFailure::Transport,
        PaceError::Encoding | PaceError::Random(_) => SecureChannelFailure::Bridge,
    }
}

fn certificate_channel_failure(failure: SecureChannelFailure) -> CertificateReadFailure {
    match failure {
        SecureChannelFailure::CardUnavailable => CertificateReadFailure::CardUnavailable,
        SecureChannelFailure::PaceRejected => CertificateReadFailure::PaceRejected,
        SecureChannelFailure::Transport => CertificateReadFailure::Transport,
        SecureChannelFailure::Bridge => CertificateReadFailure::Bridge,
    }
}

/// Preflight failures inside the opened channel fold onto the open
/// reply's shared failure vocabulary.
fn open_preflight_failure(failure: Pin1PreflightFailure) -> CertificateReadFailure {
    match failure {
        Pin1PreflightFailure::CardUnavailable => CertificateReadFailure::CardUnavailable,
        Pin1PreflightFailure::Transport => CertificateReadFailure::Transport,
        Pin1PreflightFailure::Bridge => CertificateReadFailure::Bridge,
    }
}

fn sign_channel_failure(failure: SecureChannelFailure) -> AuthenticationSignFailure {
    match failure {
        SecureChannelFailure::CardUnavailable => AuthenticationSignFailure::CardUnavailable,
        SecureChannelFailure::PaceRejected => AuthenticationSignFailure::PaceRejected,
        SecureChannelFailure::Transport => AuthenticationSignFailure::Transport,
        SecureChannelFailure::Bridge => AuthenticationSignFailure::Bridge,
    }
}

fn sign_selection_failure<E>(error: Pkcs15Error<E>) -> AuthenticationSignFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            AuthenticationSignFailure::CardUnavailable
        }
        Pkcs15Error::Aid(_) | Pkcs15Error::Command(_) => AuthenticationSignFailure::Bridge,
        Pkcs15Error::Status(_)
        | Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(_)
        | Pkcs15Error::Empty
        | Pkcs15Error::TooLarge
        | Pkcs15Error::InvalidData(_) => AuthenticationSignFailure::Transport,
    }
}

/// The session CAN was proven at connect, so a PACE refusal on this
/// later probe is a transport anomaly rather than a holder-facing fault.
fn pin2_channel_failure(failure: SecureChannelFailure) -> Pin2PreflightFailure {
    match failure {
        SecureChannelFailure::CardUnavailable => Pin2PreflightFailure::CardUnavailable,
        SecureChannelFailure::PaceRejected | SecureChannelFailure::Transport => {
            Pin2PreflightFailure::Transport
        }
        SecureChannelFailure::Bridge => Pin2PreflightFailure::Bridge,
    }
}

fn pin2_selection_failure<E>(error: Pkcs15Error<E>) -> Pin2PreflightFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            Pin2PreflightFailure::CardUnavailable
        }
        Pkcs15Error::Aid(_) | Pkcs15Error::Command(_) => Pin2PreflightFailure::Bridge,
        Pkcs15Error::Status(_)
        | Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(_)
        | Pkcs15Error::Empty
        | Pkcs15Error::TooLarge
        | Pkcs15Error::InvalidData(_) => Pin2PreflightFailure::Transport,
    }
}

/// A channel refusal folds to a transport anomaly: qualified signing
/// carries no CAN-facing outcome, and the session CAN was already proven.
fn qualified_channel_failure(failure: SecureChannelFailure) -> QualifiedSignFailure {
    match failure {
        SecureChannelFailure::CardUnavailable => QualifiedSignFailure::CardUnavailable,
        SecureChannelFailure::PaceRejected | SecureChannelFailure::Transport => {
            QualifiedSignFailure::Transport
        }
        SecureChannelFailure::Bridge => QualifiedSignFailure::Bridge,
    }
}

fn qualified_selection_failure<E>(error: Pkcs15Error<E>) -> QualifiedSignFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            QualifiedSignFailure::CardUnavailable
        }
        Pkcs15Error::Aid(_) | Pkcs15Error::Command(_) => QualifiedSignFailure::Bridge,
        Pkcs15Error::Status(_)
        | Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(_)
        | Pkcs15Error::Empty
        | Pkcs15Error::TooLarge
        | Pkcs15Error::InvalidData(_) => QualifiedSignFailure::Transport,
    }
}

fn read_minimal_emrtd_data_from_secure_channel<T: CardTransport + Pkcs15Ops + EmrtdOps>(
    secure: &mut T,
) {
    set_last_read_face_photo(None);
    set_last_read_verification(VERIFICATION_NOT_PERFORMED);
    if secure.select_emrtd_application().is_ok() {
        if let Ok(Some(mrz)) = secure.read_mrz_td1() {
            set_last_read_document_number(Some(mrz.document_number));
        } else {
            set_last_read_document_number(None);
        }
        let _ = secure.select_pkcs15_application();
    } else {
        set_last_read_document_number(None);
    }
}

#[allow(dead_code)]
fn read_face_photo_from_secure_channel<T: CardTransport + Pkcs15Ops + EmrtdOps>(
    secure: &mut T,
) -> Option<Vec<u8>> {
    set_last_read_verification(VERIFICATION_NOT_PERFORMED);
    if secure.select_emrtd_application().is_err() {
        set_last_read_document_number(None);
        return None;
    }
    let files = secure.read_passive_authentication_files().ok();
    let _ = secure.select_pkcs15_application();
    let Some(files) = files else {
        set_last_read_document_number(None);
        return None;
    };
    let mrz = ParsedMrzTd1::parse(files.mrz.as_bytes());
    set_last_read_document_number(mrz.map(|parsed| parsed.document_number));
    // Passive authentication: the DSC comes from the card's own SOD,
    // the CSCA anchor from the platform-installed set. Without anchors
    // the verdict stays "not performed" -- never a fabricated pass.
    if let Some(anchors) = installed_csca_anchors() {
        let verdict =
            authenticate_document(&files.security_object, &files.mrz, &files.face, &anchors);
        set_last_read_verification(if verdict.is_ok() {
            VERIFICATION_PASSED
        } else {
            VERIFICATION_FAILED
        });
    }
    parse_card_face_image(files.face.as_bytes()).map(|image| image.into_bytes())
}

#[cfg(test)]
mod tests {
    use refineid_apdu::{StatusWord, TransportOutcome};
    use refineid_pace::PaceError;

    use super::{
        SecureChannelFailure, map_pace_error, open_preflight_failure, pin2_channel_failure,
        qualified_channel_failure, reconstruct_can,
    };
    use crate::card_certificate::CertificateReadFailure;
    use crate::pin1_status::Pin1PreflightFailure;
    use crate::pin2_status::Pin2PreflightFailure;
    use crate::qualified_signer::QualifiedSignFailure;

    // A syntactically valid but meaningless CAN for shape tests only;
    // never a real card value.
    const SYNTHETIC_CAN_DIGITS: &[u8] = b"000000";
    const NON_DIGIT_CAN: &[u8] = b"00000A";
    const SHORT_CAN: &[u8] = b"00000";

    #[test]
    fn accepts_only_six_digit_can_shapes() {
        assert!(reconstruct_can(SYNTHETIC_CAN_DIGITS.to_vec()).is_some());
        assert!(reconstruct_can(NON_DIGIT_CAN.to_vec()).is_none());
        assert!(reconstruct_can(SHORT_CAN.to_vec()).is_none());
        assert!(reconstruct_can(Vec::new()).is_none());
    }

    #[test]
    fn maps_pace_errors_onto_channel_failures() {
        assert_eq!(
            map_pace_error::<&str>(&PaceError::Outcome(TransportOutcome::NoCard)),
            SecureChannelFailure::CardUnavailable
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::AuthMismatch),
            SecureChannelFailure::PaceRejected
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::Status(
                "mutual-auth",
                StatusWord::AuthenticationFailed,
            )),
            SecureChannelFailure::PaceRejected
        );
        assert_eq!(
            map_pace_error(&PaceError::Transport("backend")),
            SecureChannelFailure::Transport
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::Outcome(TransportOutcome::ProtocolDesync)),
            SecureChannelFailure::Transport
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::Encoding),
            SecureChannelFailure::Bridge
        );
    }

    #[test]
    fn folds_preflight_failures_onto_the_open_vocabulary() {
        assert_eq!(
            open_preflight_failure(Pin1PreflightFailure::CardUnavailable),
            CertificateReadFailure::CardUnavailable
        );
        assert_eq!(
            open_preflight_failure(Pin1PreflightFailure::Transport),
            CertificateReadFailure::Transport
        );
        assert_eq!(
            open_preflight_failure(Pin1PreflightFailure::Bridge),
            CertificateReadFailure::Bridge
        );
    }

    // The session CAN was proven at connect, so a later PACE refusal on
    // the qualified path is a transport anomaly, never a CAN outcome: the
    // PIN2 and qualified-sign vocabularies carry no PACE-rejected code.
    #[test]
    fn folds_channel_failures_onto_the_pin2_vocabulary() {
        assert_eq!(
            pin2_channel_failure(SecureChannelFailure::CardUnavailable),
            Pin2PreflightFailure::CardUnavailable
        );
        assert_eq!(
            pin2_channel_failure(SecureChannelFailure::PaceRejected),
            Pin2PreflightFailure::Transport
        );
        assert_eq!(
            pin2_channel_failure(SecureChannelFailure::Transport),
            Pin2PreflightFailure::Transport
        );
        assert_eq!(
            pin2_channel_failure(SecureChannelFailure::Bridge),
            Pin2PreflightFailure::Bridge
        );
    }

    #[test]
    fn folds_channel_failures_onto_the_qualified_vocabulary() {
        assert_eq!(
            qualified_channel_failure(SecureChannelFailure::CardUnavailable),
            QualifiedSignFailure::CardUnavailable
        );
        assert_eq!(
            qualified_channel_failure(SecureChannelFailure::PaceRejected),
            QualifiedSignFailure::Transport
        );
        assert_eq!(
            qualified_channel_failure(SecureChannelFailure::Transport),
            QualifiedSignFailure::Transport
        );
        assert_eq!(
            qualified_channel_failure(SecureChannelFailure::Bridge),
            QualifiedSignFailure::Bridge
        );
    }

    #[test]
    fn extracts_portrait_via_emrtd() {
        let dg2 = vec![
            0x75, 0x1A, // DG2 tag + len
            0x00, 0x01, 0x02, // Biometric header
            0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 0x08, // SOF0 marker
            0x01, 0x90, // Height 400
            0x01, 0x2C, // Width 300
            0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, 0xFF, 0xD9,
        ];
        let portrait = refineid_emrtd::parse_card_face_image(&dg2).expect("portrait extracted");
        assert_eq!(portrait.format(), refineid_emrtd::ImageFormat::Jpeg);
        assert_eq!(portrait.width(), 300);
        assert_eq!(portrait.height(), 400);
        assert_eq!(&portrait.image_bytes()[..3], &[0xFF, 0xD8, 0xFF]);
    }
}
