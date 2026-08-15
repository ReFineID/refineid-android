//! Typed authentication-certificate read and public-key classification.

use refineid_apdu::TransportOutcome;
use refineid_pkcs15::{CertSlot, Pkcs15Error, Pkcs15Ops};
use refineid_x509::{EcCurve, PublicKey};

use crate::card_transport::{AndroidCardTransport, AndroidTransportError, SingleBlockExchange};

const RSA_2048_BITS: usize = 2_048;
const RSA_3072_BITS: usize = 3_072;

/// Supported key profile carried by the authentication certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticationKeyProfile {
    Rsa2048,
    Rsa3072,
    EcdsaP256,
    EcdsaP384,
}

/// Validated public certificate bytes and their reconstructed key profile.
pub(crate) struct AuthenticationCertificate {
    pub(crate) profile: AuthenticationKeyProfile,
    pub(crate) der: Vec<u8>,
}

/// Safe failure classes crossing the native boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticationCertificateReadFailure {
    CardUnavailable,
    Rejected,
    Transport,
    InvalidCertificate,
    Bridge,
}

/// Read EF.4331 and reconstruct its public key before returning its DER.
pub(crate) fn read_authentication_certificate<Exchange: SingleBlockExchange>(
    transport: &mut AndroidCardTransport<Exchange>,
) -> Result<AuthenticationCertificate, AuthenticationCertificateReadFailure> {
    let certificate = transport
        .read_certificate(CertSlot::Authentication)
        .map_err(map_pkcs15_error)?;
    let der = certificate.as_bytes().to_vec();
    let public_key = PublicKey::from_certificate(certificate)
        .map_err(|_| AuthenticationCertificateReadFailure::InvalidCertificate)?;
    let profile = classify_public_key(&public_key)?;
    Ok(AuthenticationCertificate { profile, der })
}

fn classify_public_key(
    public_key: &PublicKey,
) -> Result<AuthenticationKeyProfile, AuthenticationCertificateReadFailure> {
    match public_key {
        PublicKey::Rsa(rsa) => match rsa.modulus().bit_length() {
            RSA_2048_BITS => Ok(AuthenticationKeyProfile::Rsa2048),
            RSA_3072_BITS => Ok(AuthenticationKeyProfile::Rsa3072),
            _ => Err(AuthenticationCertificateReadFailure::InvalidCertificate),
        },
        PublicKey::Ecdsa(ec) => match ec.curve() {
            EcCurve::P256 => Ok(AuthenticationKeyProfile::EcdsaP256),
            EcCurve::P384 => Ok(AuthenticationKeyProfile::EcdsaP384),
        },
    }
}

fn map_pkcs15_error(
    error: Pkcs15Error<AndroidTransportError>,
) -> AuthenticationCertificateReadFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            AuthenticationCertificateReadFailure::CardUnavailable
        }
        Pkcs15Error::Status(_) => AuthenticationCertificateReadFailure::Rejected,
        Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => AuthenticationCertificateReadFailure::Transport,
        Pkcs15Error::Empty | Pkcs15Error::TooLarge | Pkcs15Error::InvalidData(_) => {
            AuthenticationCertificateReadFailure::InvalidCertificate
        }
        Pkcs15Error::Outcome(TransportOutcome::Response(_))
        | Pkcs15Error::Aid(_)
        | Pkcs15Error::Command(_) => AuthenticationCertificateReadFailure::Bridge,
    }
}

#[cfg(test)]
mod tests {
    use refineid_apdu::{ResponseApdu, StatusWord, TransportOutcome};
    use refineid_pkcs15::Pkcs15Error;

    use super::{AuthenticationCertificateReadFailure, map_pkcs15_error};
    use crate::card_transport::AndroidTransportError;

    #[test]
    fn maps_card_and_transport_failures_without_details() {
        let [success_sw1, success_sw2] = StatusWord::Success.as_u16().to_be_bytes();
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Outcome(TransportOutcome::NoCard)),
            AuthenticationCertificateReadFailure::CardUnavailable
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Status(StatusWord::FileNotFound)),
            AuthenticationCertificateReadFailure::Rejected
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Transport(AndroidTransportError::Backend)),
            AuthenticationCertificateReadFailure::Transport
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::InvalidData("synthetic certificate")),
            AuthenticationCertificateReadFailure::InvalidCertificate
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Outcome(TransportOutcome::Response(
                ResponseApdu {
                    body: Vec::new(),
                    sw1: success_sw1,
                    sw2: success_sw2,
                }
            ))),
            AuthenticationCertificateReadFailure::Bridge
        );
    }
}
