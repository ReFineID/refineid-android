//! Typed public-certificate reads and public-key classification.

use refineid_apdu::TransportOutcome;
use refineid_pkcs15::{CertSlot, Pkcs15Error, Pkcs15Ops};
use refineid_x509::{EcCurve, PublicKey};

use crate::card_transport::{AndroidCardTransport, AndroidTransportError, SingleBlockExchange};

const RSA_2048_BITS: usize = 2_048;
const RSA_3072_BITS: usize = 3_072;

/// Supported key profile carried by a card certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardKeyProfile {
    Rsa2048,
    Rsa3072,
    EcdsaP256,
    EcdsaP384,
}

/// Validated public certificate bytes and their reconstructed key profile.
pub(crate) struct CardCertificate {
    pub(crate) profile: CardKeyProfile,
    pub(crate) der: Vec<u8>,
}

/// Safe failure classes crossing the native boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertificateReadFailure {
    CardUnavailable,
    Rejected,
    Transport,
    InvalidCertificate,
    Bridge,
}

/// Read EF.4331 and reconstruct its public key before returning its DER.
pub(crate) fn read_authentication_certificate<Exchange: SingleBlockExchange>(
    transport: &mut AndroidCardTransport<Exchange>,
) -> Result<CardCertificate, CertificateReadFailure> {
    read_card_certificate(transport, CertSlot::Authentication)
}

/// Read EF.4332 and reconstruct its public key before returning its DER.
pub(crate) fn read_qualified_certificate<Exchange: SingleBlockExchange>(
    transport: &mut AndroidCardTransport<Exchange>,
) -> Result<CardCertificate, CertificateReadFailure> {
    read_card_certificate(transport, CertSlot::Signature)
}

fn read_card_certificate<Exchange: SingleBlockExchange>(
    transport: &mut AndroidCardTransport<Exchange>,
    slot: CertSlot,
) -> Result<CardCertificate, CertificateReadFailure> {
    let certificate = transport.read_certificate(slot).map_err(map_pkcs15_error)?;
    let der = certificate.as_bytes().to_vec();
    let public_key = PublicKey::from_certificate(certificate)
        .map_err(|_| CertificateReadFailure::InvalidCertificate)?;
    let profile = classify_public_key(&public_key)?;
    Ok(CardCertificate { profile, der })
}

fn classify_public_key(public_key: &PublicKey) -> Result<CardKeyProfile, CertificateReadFailure> {
    match public_key {
        PublicKey::Rsa(rsa) => match rsa.modulus().bit_length() {
            RSA_2048_BITS => Ok(CardKeyProfile::Rsa2048),
            RSA_3072_BITS => Ok(CardKeyProfile::Rsa3072),
            _ => Err(CertificateReadFailure::InvalidCertificate),
        },
        PublicKey::Ecdsa(ec) => match ec.curve() {
            EcCurve::P256 => Ok(CardKeyProfile::EcdsaP256),
            EcCurve::P384 => Ok(CardKeyProfile::EcdsaP384),
        },
    }
}

fn map_pkcs15_error(error: Pkcs15Error<AndroidTransportError>) -> CertificateReadFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            CertificateReadFailure::CardUnavailable
        }
        Pkcs15Error::Status(_) => CertificateReadFailure::Rejected,
        Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => CertificateReadFailure::Transport,
        Pkcs15Error::Empty | Pkcs15Error::TooLarge | Pkcs15Error::InvalidData(_) => {
            CertificateReadFailure::InvalidCertificate
        }
        Pkcs15Error::Outcome(TransportOutcome::Response(_))
        | Pkcs15Error::Aid(_)
        | Pkcs15Error::Command(_) => CertificateReadFailure::Bridge,
    }
}

#[cfg(test)]
mod tests {
    use refineid_apdu::{ResponseApdu, StatusWord, TransportOutcome};
    use refineid_pkcs15::Pkcs15Error;

    use super::{CertificateReadFailure, map_pkcs15_error};
    use crate::card_transport::AndroidTransportError;

    #[test]
    fn maps_card_and_transport_failures_without_details() {
        let [success_sw1, success_sw2] = StatusWord::Success.as_u16().to_be_bytes();
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Outcome(TransportOutcome::NoCard)),
            CertificateReadFailure::CardUnavailable
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Status(StatusWord::FileNotFound)),
            CertificateReadFailure::Rejected
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Transport(AndroidTransportError::Backend)),
            CertificateReadFailure::Transport
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::InvalidData("synthetic certificate")),
            CertificateReadFailure::InvalidCertificate
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Outcome(TransportOutcome::Response(
                ResponseApdu {
                    body: Vec::new(),
                    sw1: success_sw1,
                    sw2: success_sw2,
                }
            ))),
            CertificateReadFailure::Bridge
        );
    }
}
