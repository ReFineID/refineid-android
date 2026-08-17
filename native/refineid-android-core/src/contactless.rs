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

use refineid_apdu::{CardTransport, TransportOutcome};
use refineid_pace::{Can, PaceError, SmTransport, UnvalidatedCan, run_pace_with_can};
use refineid_pkcs15::{Pkcs15Error, Pkcs15Ops};

use crate::authentication_signer::{
    AuthenticationSignFailure, AuthenticationSignature, AuthenticationSigningAlgorithm,
    AuthenticationSigningInput, authenticate_and_sign,
};
use crate::card_certificate::{
    CardCertificate, CertificateReadFailure, map_pkcs15_error, read_authentication_certificate,
};
use crate::card_transport::{AndroidCardTransport, SingleBlockExchange};
use crate::pin1_status::{Pin1Preflight, Pin1PreflightFailure, probe_pin1_preflight};

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

#[cfg(test)]
mod tests {
    use refineid_apdu::{StatusWord, TransportOutcome};
    use refineid_pace::PaceError;

    use super::{SecureChannelFailure, map_pace_error, open_preflight_failure, reconstruct_can};
    use crate::card_certificate::CertificateReadFailure;
    use crate::pin1_status::Pin1PreflightFailure;

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
}
