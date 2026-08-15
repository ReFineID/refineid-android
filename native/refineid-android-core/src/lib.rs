//! Narrow JNI border between Android and the reviewed ReFineID core.
//!
//! ATR bytes return only a small typed status. Public authentication
//! certificate DER crosses back only after the core has bounded the read and
//! reconstructed its public key; credential bytes never cross this border.

mod authentication_certificate;
mod authentication_signer;
mod card_transport;
mod jni_card_exchange;
mod pin1_status;

use authentication_certificate::{
    AuthenticationCertificate, AuthenticationCertificateReadFailure, AuthenticationKeyProfile,
    read_authentication_certificate,
};
use authentication_signer::{
    AuthenticationSignFailure, AuthenticationSignature, AuthenticationSigningAlgorithm,
    authenticate_and_sign,
};
use card_transport::{AndroidCardTransport, CardExchangeLevel};
use jni::objects::{JByteArray, JClass, JObject};
use jni::sys::jint;
use jni::{Env, NativeMethod};
use jni_card_exchange::JniBlockExchange;
use pin1_status::{Pin1Preflight, Pin1PreflightFailure, Pin1State, probe_pin1_preflight};
use refineid_apdu::TransportOutcome;
use refineid_atr::{Atr, Convention};
use refineid_auth::PinReferenceScheme;
use refineid_pkcs15::{Pkcs15Error, Pkcs15Ops};

const ATR_INVALID: jint = 0;
const ATR_VALID_T0_DIRECT: jint = 1;
const ATR_VALID_T0_INVERSE: jint = 2;
const ATR_VALID_NON_T0_DIRECT: jint = 3;
const ATR_VALID_NON_T0_INVERSE: jint = 4;

const EXCHANGE_LEVEL_APDU: jint = 0;
const EXCHANGE_LEVEL_T0_TPDU: jint = 1;

const CARD_OPERATION_BRIDGE_ERROR: jint = 0;
const CARD_OPERATION_SUCCEEDED: jint = 1;
const CARD_OPERATION_CARD_UNAVAILABLE: jint = 2;
const CARD_OPERATION_REJECTED: jint = 3;
const CARD_OPERATION_TRANSPORT_ERROR: jint = 4;

const CERTIFICATE_BRIDGE_ERROR: u8 = 0;
const CERTIFICATE_SUCCEEDED: u8 = 1;
const CERTIFICATE_CARD_UNAVAILABLE: u8 = 2;
const CERTIFICATE_REJECTED: u8 = 3;
const CERTIFICATE_TRANSPORT_ERROR: u8 = 4;
const CERTIFICATE_INVALID: u8 = 5;

const PIN1_PREFLIGHT_BRIDGE_ERROR: u8 = 0;
const PIN1_PREFLIGHT_SUCCEEDED: u8 = 1;
const PIN1_PREFLIGHT_CARD_UNAVAILABLE: u8 = 2;
const PIN1_PREFLIGHT_TRANSPORT_ERROR: u8 = 3;

const AUTHENTICATION_SIGNATURE_BRIDGE_ERROR: u8 = 0;
const AUTHENTICATION_SIGNATURE_SUCCEEDED: u8 = 1;
const AUTHENTICATION_SIGNATURE_CARD_UNAVAILABLE: u8 = 2;
const AUTHENTICATION_SIGNATURE_TRANSPORT_ERROR: u8 = 3;
const AUTHENTICATION_SIGNATURE_INVALID_PIN: u8 = 4;
const AUTHENTICATION_SIGNATURE_SAFETY_REFUSED: u8 = 5;
const AUTHENTICATION_SIGNATURE_PIN_LOCKED: u8 = 6;
const AUTHENTICATION_SIGNATURE_WRONG_PIN: u8 = 7;
const AUTHENTICATION_SIGNATURE_VERIFICATION_REJECTED: u8 = 8;
const AUTHENTICATION_SIGNATURE_SIGNING_REJECTED: u8 = 9;

const AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256: u8 = 0;
const AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256: u8 = 1;
const AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256: u8 = 2;
const AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384: u8 = 3;

const PIN_REFERENCE_CITIZEN: u8 = 0;
const PIN_REFERENCE_ORGANIZATIONAL: u8 = 1;

const PIN1_STATE_VERIFIED: u8 = 0;
const PIN1_STATE_REMAINING: u8 = 1;
const PIN1_STATE_LOCKED: u8 = 2;
const PIN1_STATE_NO_INFORMATION: u8 = 3;
const PIN1_STATE_UNRECOGNISED: u8 = 4;

const POLICY_REFUSED: u8 = 0;
const POLICY_PERMITTED: u8 = 1;
const NO_RETRY_COUNT: u8 = u8::MAX;

const KEY_PROFILE_RSA_2048: u8 = 0;
const KEY_PROFILE_RSA_3072: u8 = 1;
const KEY_PROFILE_ECDSA_P256: u8 = 2;
const KEY_PROFILE_ECDSA_P384: u8 = 3;

const CERTIFICATE_REPLY_HEADER_LENGTH: usize = 2;
const PIN1_PREFLIGHT_REPLY_LENGTH: usize = 5;
const AUTHENTICATION_SIGNATURE_REPLY_HEADER_LENGTH: usize = 2;
const MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH: usize = 1_024 * 1_024;
const JAVA_ARRAY_CLEAR_CHUNK_LENGTH: usize = 64;

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn validate_atr_native(atr: [jbyte]) -> jint,
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn authenticate_and_sign_native(
        exchange_level: jint,
        algorithm: jint,
        pin: [jbyte],
        message: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn probe_pin1_status_native(
        exchange_level: jint,
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn read_authentication_certificate_native(
        exchange_level: jint,
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn select_pkcs15_application_native(
        exchange_level: jint,
        callback: JObject,
    ) -> jint,
};

fn validate_atr_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    atr: JByteArray<'local>,
) -> Result<jint, jni::errors::Error> {
    let mut bytes = env.convert_byte_array(&atr)?;
    let status = validate_atr_bytes(&bytes);
    bytes.fill(0);
    Ok(status)
}

fn validate_atr_bytes(bytes: &[u8]) -> jint {
    match Atr::new(bytes) {
        Ok(atr) => match (atr.supports_non_t0_protocol(), atr.convention()) {
            (false, Convention::Direct) => ATR_VALID_T0_DIRECT,
            (false, Convention::Inverse) => ATR_VALID_T0_INVERSE,
            (true, Convention::Direct) => ATR_VALID_NON_T0_DIRECT,
            (true, Convention::Inverse) => ATR_VALID_NON_T0_INVERSE,
        },
        Err(_) => ATR_INVALID,
    }
}

fn select_pkcs15_application_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    callback: JObject<'local>,
) -> Result<jint, jni::errors::Error> {
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        return Ok(CARD_OPERATION_BRIDGE_ERROR);
    };

    let exchange = JniBlockExchange::new(env, callback);
    let mut transport = AndroidCardTransport::new(exchange, level);
    let result = transport.select_pkcs15_application();
    let exchange = transport.into_exchange();
    if exchange.bridge_failed() {
        return Ok(CARD_OPERATION_BRIDGE_ERROR);
    }

    Ok(map_pkcs15_selection_result(result))
}

fn read_authentication_certificate_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        return env.byte_array_from_slice(&[CERTIFICATE_BRIDGE_ERROR]);
    };

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = AndroidCardTransport::new(exchange, level);
        let result = read_authentication_certificate(&mut transport);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![CERTIFICATE_BRIDGE_ERROR]
    } else {
        encode_authentication_certificate_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

fn probe_pin1_status_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        return env.byte_array_from_slice(&[PIN1_PREFLIGHT_BRIDGE_ERROR]);
    };

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = AndroidCardTransport::new(exchange, level);
        let result = probe_pin1_preflight(&mut transport);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![PIN1_PREFLIGHT_BRIDGE_ERROR]
    } else {
        encode_pin1_preflight_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

fn authenticate_and_sign_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    algorithm: jint,
    pin: JByteArray<'local>,
    message: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let mut pin_bytes = match env.convert_byte_array(&pin) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = clear_java_byte_array(env, &pin);
            return Err(error);
        }
    };
    if let Err(error) = clear_java_byte_array(env, &pin) {
        pin_bytes.fill(0);
        return Err(error);
    }

    let Some(level) = exchange_level_from_jint(exchange_level) else {
        pin_bytes.fill(0);
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    };
    let Some(algorithm) = authentication_algorithm_from_jint(algorithm) else {
        pin_bytes.fill(0);
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    };
    if message.len(env)? > MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH {
        pin_bytes.fill(0);
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    }

    let mut message_bytes = match env.convert_byte_array(&message) {
        Ok(bytes) => bytes,
        Err(error) => {
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = AndroidCardTransport::new(exchange, level);
        let result = authenticate_and_sign(&mut transport, algorithm, pin_bytes, &message_bytes);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };
    message_bytes.fill(0);

    let mut reply = if bridge_failed {
        vec![AUTHENTICATION_SIGNATURE_BRIDGE_ERROR]
    } else {
        encode_authentication_signature_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

fn clear_java_byte_array(env: &Env<'_>, array: &JByteArray<'_>) -> Result<(), jni::errors::Error> {
    const ZEROES: [i8; JAVA_ARRAY_CLEAR_CHUNK_LENGTH] = [0; JAVA_ARRAY_CLEAR_CHUNK_LENGTH];
    let length = array.len(env)?;
    let mut offset = 0usize;
    while offset < length {
        let chunk_length = (length - offset).min(JAVA_ARRAY_CLEAR_CHUNK_LENGTH);
        array.set_region(env, offset as jni::sys::jsize, &ZEROES[..chunk_length])?;
        offset += chunk_length;
    }
    Ok(())
}

fn one_byte_reply<'local>(
    env: &mut Env<'local>,
    tag: u8,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    env.byte_array_from_slice(&[tag])
}

fn exchange_level_from_jint(value: jint) -> Option<CardExchangeLevel> {
    match value {
        EXCHANGE_LEVEL_APDU => Some(CardExchangeLevel::Apdu),
        EXCHANGE_LEVEL_T0_TPDU => Some(CardExchangeLevel::T0Tpdu),
        _ => None,
    }
}

fn authentication_algorithm_from_jint(value: jint) -> Option<AuthenticationSigningAlgorithm> {
    match value {
        value if value == jint::from(AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256) => {
            Some(AuthenticationSigningAlgorithm::RsaPkcs1Sha256)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256) => {
            Some(AuthenticationSigningAlgorithm::RsaPssSha256)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256) => {
            Some(AuthenticationSigningAlgorithm::EcdsaP384Sha256)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384) => {
            Some(AuthenticationSigningAlgorithm::EcdsaP384Sha384)
        }
        _ => None,
    }
}

fn map_pkcs15_selection_result(
    result: Result<(), Pkcs15Error<card_transport::AndroidTransportError>>,
) -> jint {
    match result {
        Ok(()) => CARD_OPERATION_SUCCEEDED,
        Err(Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved)) => {
            CARD_OPERATION_CARD_UNAVAILABLE
        }
        Err(Pkcs15Error::Status(_)) => CARD_OPERATION_REJECTED,
        Err(Pkcs15Error::Transport(_))
        | Err(Pkcs15Error::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        )) => CARD_OPERATION_TRANSPORT_ERROR,
        Err(Pkcs15Error::Outcome(TransportOutcome::Response(_)))
        | Err(Pkcs15Error::Aid(_))
        | Err(Pkcs15Error::Command(_))
        | Err(Pkcs15Error::Empty)
        | Err(Pkcs15Error::TooLarge)
        | Err(Pkcs15Error::InvalidData(_)) => CARD_OPERATION_BRIDGE_ERROR,
    }
}

fn encode_authentication_certificate_reply(
    result: Result<AuthenticationCertificate, AuthenticationCertificateReadFailure>,
) -> Vec<u8> {
    match result {
        Ok(mut certificate) => {
            let mut reply =
                Vec::with_capacity(CERTIFICATE_REPLY_HEADER_LENGTH + certificate.der.len());
            reply.push(CERTIFICATE_SUCCEEDED);
            reply.push(match certificate.profile {
                AuthenticationKeyProfile::Rsa2048 => KEY_PROFILE_RSA_2048,
                AuthenticationKeyProfile::Rsa3072 => KEY_PROFILE_RSA_3072,
                AuthenticationKeyProfile::EcdsaP256 => KEY_PROFILE_ECDSA_P256,
                AuthenticationKeyProfile::EcdsaP384 => KEY_PROFILE_ECDSA_P384,
            });
            reply.append(&mut certificate.der);
            reply
        }
        Err(failure) => vec![match failure {
            AuthenticationCertificateReadFailure::CardUnavailable => CERTIFICATE_CARD_UNAVAILABLE,
            AuthenticationCertificateReadFailure::Rejected => CERTIFICATE_REJECTED,
            AuthenticationCertificateReadFailure::Transport => CERTIFICATE_TRANSPORT_ERROR,
            AuthenticationCertificateReadFailure::InvalidCertificate => CERTIFICATE_INVALID,
            AuthenticationCertificateReadFailure::Bridge => CERTIFICATE_BRIDGE_ERROR,
        }],
    }
}

fn encode_pin1_preflight_reply(result: Result<Pin1Preflight, Pin1PreflightFailure>) -> Vec<u8> {
    match result {
        Ok(preflight) => {
            let (state, retries) = match preflight.state {
                Pin1State::Verified => (PIN1_STATE_VERIFIED, NO_RETRY_COUNT),
                Pin1State::Remaining(retries) => (PIN1_STATE_REMAINING, retries),
                Pin1State::Locked => (PIN1_STATE_LOCKED, NO_RETRY_COUNT),
                Pin1State::NoInformation => (PIN1_STATE_NO_INFORMATION, NO_RETRY_COUNT),
                Pin1State::Unrecognised => (PIN1_STATE_UNRECOGNISED, NO_RETRY_COUNT),
            };
            let reply: [u8; PIN1_PREFLIGHT_REPLY_LENGTH] = [
                PIN1_PREFLIGHT_SUCCEEDED,
                match preflight.scheme {
                    PinReferenceScheme::Citizen => PIN_REFERENCE_CITIZEN,
                    PinReferenceScheme::Organizational => PIN_REFERENCE_ORGANIZATIONAL,
                },
                state,
                retries,
                if preflight.consumer_authentication_permitted {
                    POLICY_PERMITTED
                } else {
                    POLICY_REFUSED
                },
            ];
            reply.to_vec()
        }
        Err(failure) => vec![match failure {
            Pin1PreflightFailure::CardUnavailable => PIN1_PREFLIGHT_CARD_UNAVAILABLE,
            Pin1PreflightFailure::Transport => PIN1_PREFLIGHT_TRANSPORT_ERROR,
            Pin1PreflightFailure::Bridge => PIN1_PREFLIGHT_BRIDGE_ERROR,
        }],
    }
}

fn encode_authentication_signature_reply(
    result: Result<AuthenticationSignature, AuthenticationSignFailure>,
) -> Vec<u8> {
    match result {
        Ok(mut signature) => {
            let mut reply = Vec::with_capacity(
                AUTHENTICATION_SIGNATURE_REPLY_HEADER_LENGTH + signature.bytes.len(),
            );
            reply.push(AUTHENTICATION_SIGNATURE_SUCCEEDED);
            reply.push(match signature.algorithm {
                AuthenticationSigningAlgorithm::RsaPkcs1Sha256 => {
                    AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256
                }
                AuthenticationSigningAlgorithm::RsaPssSha256 => {
                    AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256
                }
                AuthenticationSigningAlgorithm::EcdsaP384Sha256 => {
                    AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256
                }
                AuthenticationSigningAlgorithm::EcdsaP384Sha384 => {
                    AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384
                }
            });
            reply.append(&mut signature.bytes);
            reply
        }
        Err(failure) => vec![match failure {
            AuthenticationSignFailure::InvalidPin => AUTHENTICATION_SIGNATURE_INVALID_PIN,
            AuthenticationSignFailure::SafetyRefused => AUTHENTICATION_SIGNATURE_SAFETY_REFUSED,
            AuthenticationSignFailure::PinLocked => AUTHENTICATION_SIGNATURE_PIN_LOCKED,
            AuthenticationSignFailure::WrongPin => AUTHENTICATION_SIGNATURE_WRONG_PIN,
            AuthenticationSignFailure::VerificationRejected => {
                AUTHENTICATION_SIGNATURE_VERIFICATION_REJECTED
            }
            AuthenticationSignFailure::SigningRejected => AUTHENTICATION_SIGNATURE_SIGNING_REJECTED,
            AuthenticationSignFailure::CardUnavailable => AUTHENTICATION_SIGNATURE_CARD_UNAVAILABLE,
            AuthenticationSignFailure::Transport => AUTHENTICATION_SIGNATURE_TRANSPORT_ERROR,
            AuthenticationSignFailure::Bridge => AUTHENTICATION_SIGNATURE_BRIDGE_ERROR,
        }],
    }
}

#[cfg(test)]
mod tests {
    use refineid_apdu::TransportOutcome;
    use refineid_atr::{Convention, MINIMAL_DIRECT_ATR};
    use refineid_auth::PinReferenceScheme;
    use refineid_pkcs15::Pkcs15Error;
    use refineid_sign::ECDSA_P384_SIG_BYTES;

    use super::{
        ATR_INVALID, ATR_VALID_NON_T0_DIRECT, ATR_VALID_T0_DIRECT, ATR_VALID_T0_INVERSE,
        AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384, AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256,
        AUTHENTICATION_SIGNATURE_CARD_UNAVAILABLE, AUTHENTICATION_SIGNATURE_REPLY_HEADER_LENGTH,
        AUTHENTICATION_SIGNATURE_SUCCEEDED, CARD_OPERATION_CARD_UNAVAILABLE,
        CARD_OPERATION_REJECTED, CARD_OPERATION_SUCCEEDED, CARD_OPERATION_TRANSPORT_ERROR,
        CERTIFICATE_CARD_UNAVAILABLE, CERTIFICATE_INVALID, CERTIFICATE_REPLY_HEADER_LENGTH,
        CERTIFICATE_SUCCEEDED, EXCHANGE_LEVEL_APDU, EXCHANGE_LEVEL_T0_TPDU, KEY_PROFILE_RSA_2048,
        NO_RETRY_COUNT, PIN_REFERENCE_CITIZEN, PIN1_PREFLIGHT_BRIDGE_ERROR,
        PIN1_PREFLIGHT_CARD_UNAVAILABLE, PIN1_PREFLIGHT_REPLY_LENGTH, PIN1_PREFLIGHT_SUCCEEDED,
        PIN1_STATE_REMAINING, POLICY_PERMITTED, authentication_algorithm_from_jint,
        encode_authentication_certificate_reply, encode_authentication_signature_reply,
        encode_pin1_preflight_reply, exchange_level_from_jint, map_pkcs15_selection_result,
        validate_atr_bytes,
    };
    use crate::authentication_certificate::{
        AuthenticationCertificate, AuthenticationCertificateReadFailure, AuthenticationKeyProfile,
    };
    use crate::authentication_signer::{
        AuthenticationSignFailure, AuthenticationSignature, AuthenticationSigningAlgorithm,
    };
    use crate::card_transport::{AndroidTransportError, CardExchangeLevel};
    use crate::pin1_status::{Pin1Preflight, Pin1PreflightFailure, Pin1State};

    const AUTHENTICATION_SIGNATURE_TAG_OFFSET: usize = 0;
    const AUTHENTICATION_SIGNATURE_ALGORITHM_OFFSET: usize = 1;
    const ATR_CONVENTION_OFFSET: usize = 0;
    const UNSUPPORTED_EXCHANGE_LEVEL: i32 = 2;
    const AUTHENTICATION_ALGORITHM_BELOW_RANGE: i32 = -1;
    const AUTHENTICATION_ALGORITHM_ABOVE_RANGE: i32 = 4;
    const SYNTHETIC_REJECTED_STATUS_WORD: u16 = 0x6a82;
    const SYNTHETIC_DER_SEQUENCE_TAG: u8 = 0x30;
    const SYNTHETIC_DER_EMPTY_LENGTH: u8 = 0x00;
    const SYNTHETIC_PIN_RETRY_COUNT: u8 = 3;
    const PIN1_PREFLIGHT_RETRY_COUNT_OFFSET: usize = 3;

    #[test]
    fn accepts_minimal_direct_atr() {
        assert_eq!(validate_atr_bytes(&MINIMAL_DIRECT_ATR), ATR_VALID_T0_DIRECT);
    }

    #[test]
    fn accepts_minimal_inverse_atr() {
        let mut atr = MINIMAL_DIRECT_ATR;
        atr[ATR_CONVENTION_OFFSET] = Convention::Inverse.as_ts();

        assert_eq!(validate_atr_bytes(&atr), ATR_VALID_T0_INVERSE);
    }

    #[test]
    fn classifies_a_non_t0_protocol() {
        const T0_WITH_TD1: u8 = 1 << 7;
        const TD1_T1: u8 = 1;
        let tck = T0_WITH_TD1 ^ TD1_T1;
        let atr = [Convention::Direct.as_ts(), T0_WITH_TD1, TD1_T1, tck];

        assert_eq!(validate_atr_bytes(&atr), ATR_VALID_NON_T0_DIRECT);
    }

    #[test]
    fn rejects_truncated_atr() {
        assert_eq!(validate_atr_bytes(&[]), ATR_INVALID);
    }

    #[test]
    fn accepts_only_stable_exchange_level_codes() {
        assert_eq!(
            exchange_level_from_jint(EXCHANGE_LEVEL_APDU),
            Some(CardExchangeLevel::Apdu)
        );
        assert_eq!(
            exchange_level_from_jint(EXCHANGE_LEVEL_T0_TPDU),
            Some(CardExchangeLevel::T0Tpdu)
        );
        assert_eq!(exchange_level_from_jint(UNSUPPORTED_EXCHANGE_LEVEL), None);
    }

    #[test]
    fn accepts_only_stable_authentication_algorithm_codes() {
        assert_eq!(
            authentication_algorithm_from_jint(i32::from(
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256,
            )),
            Some(AuthenticationSigningAlgorithm::RsaPkcs1Sha256)
        );
        assert_eq!(
            authentication_algorithm_from_jint(AUTHENTICATION_ALGORITHM_BELOW_RANGE),
            None
        );
        assert_eq!(
            authentication_algorithm_from_jint(AUTHENTICATION_ALGORITHM_ABOVE_RANGE),
            None
        );
    }

    #[test]
    fn maps_pkcs15_selection_outcomes_without_exposing_details() {
        assert_eq!(
            map_pkcs15_selection_result(Ok(())),
            CARD_OPERATION_SUCCEEDED
        );
        assert_eq!(
            map_pkcs15_selection_result(Err(Pkcs15Error::Outcome(TransportOutcome::NoCard))),
            CARD_OPERATION_CARD_UNAVAILABLE
        );
        assert_eq!(
            map_pkcs15_selection_result(Err(Pkcs15Error::Outcome(
                TransportOutcome::ProtocolDesync
            ))),
            CARD_OPERATION_TRANSPORT_ERROR
        );
        assert_eq!(
            map_pkcs15_selection_result(Err(Pkcs15Error::Transport(
                AndroidTransportError::Backend
            ))),
            CARD_OPERATION_TRANSPORT_ERROR
        );
        assert_eq!(
            map_pkcs15_selection_result(Err(Pkcs15Error::Status(
                refineid_apdu::StatusWord::Other(SYNTHETIC_REJECTED_STATUS_WORD)
            ))),
            CARD_OPERATION_REJECTED
        );
    }

    #[test]
    fn encodes_certificate_success_and_typed_failures() {
        const SYNTHETIC_DER: &[u8] = &[SYNTHETIC_DER_SEQUENCE_TAG, SYNTHETIC_DER_EMPTY_LENGTH];
        let success = encode_authentication_certificate_reply(Ok(AuthenticationCertificate {
            profile: AuthenticationKeyProfile::Rsa2048,
            der: SYNTHETIC_DER.to_vec(),
        }));
        assert_eq!(
            success,
            [
                &[CERTIFICATE_SUCCEEDED, KEY_PROFILE_RSA_2048],
                SYNTHETIC_DER,
            ]
            .concat()
        );
        assert_eq!(
            success.len(),
            CERTIFICATE_REPLY_HEADER_LENGTH + SYNTHETIC_DER.len()
        );
        assert_eq!(
            encode_authentication_certificate_reply(Err(
                AuthenticationCertificateReadFailure::CardUnavailable
            )),
            vec![CERTIFICATE_CARD_UNAVAILABLE]
        );
        assert_eq!(
            encode_authentication_certificate_reply(Err(
                AuthenticationCertificateReadFailure::InvalidCertificate
            )),
            vec![CERTIFICATE_INVALID]
        );
    }

    #[test]
    fn encodes_pin1_preflight_without_raw_card_values() {
        let success = encode_pin1_preflight_reply(Ok(Pin1Preflight {
            scheme: PinReferenceScheme::Citizen,
            state: Pin1State::Remaining(SYNTHETIC_PIN_RETRY_COUNT),
            consumer_authentication_permitted: true,
        }));
        assert_eq!(
            success,
            vec![
                PIN1_PREFLIGHT_SUCCEEDED,
                PIN_REFERENCE_CITIZEN,
                PIN1_STATE_REMAINING,
                SYNTHETIC_PIN_RETRY_COUNT,
                POLICY_PERMITTED,
            ]
        );
        assert_eq!(success.len(), PIN1_PREFLIGHT_REPLY_LENGTH);
        assert_ne!(success[PIN1_PREFLIGHT_RETRY_COUNT_OFFSET], NO_RETRY_COUNT);
        assert_eq!(
            encode_pin1_preflight_reply(Err(Pin1PreflightFailure::CardUnavailable)),
            vec![PIN1_PREFLIGHT_CARD_UNAVAILABLE]
        );
        assert_eq!(
            encode_pin1_preflight_reply(Err(Pin1PreflightFailure::Bridge)),
            vec![PIN1_PREFLIGHT_BRIDGE_ERROR]
        );
    }

    #[test]
    fn encodes_signature_success_and_coarse_failure() {
        const SYNTHETIC_SIGNATURE_FILL: u8 = 0xA5;
        const SYNTHETIC_SIGNATURE: [u8; ECDSA_P384_SIG_BYTES] =
            [SYNTHETIC_SIGNATURE_FILL; ECDSA_P384_SIG_BYTES];
        let success = encode_authentication_signature_reply(Ok(AuthenticationSignature {
            algorithm: AuthenticationSigningAlgorithm::EcdsaP384Sha384,
            bytes: SYNTHETIC_SIGNATURE.to_vec(),
        }));
        assert_eq!(
            success[AUTHENTICATION_SIGNATURE_TAG_OFFSET],
            AUTHENTICATION_SIGNATURE_SUCCEEDED
        );
        assert_eq!(
            success[AUTHENTICATION_SIGNATURE_ALGORITHM_OFFSET],
            AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384
        );
        assert_eq!(
            &success[AUTHENTICATION_SIGNATURE_REPLY_HEADER_LENGTH..],
            &SYNTHETIC_SIGNATURE
        );
        assert_eq!(
            encode_authentication_signature_reply(Err(AuthenticationSignFailure::CardUnavailable,)),
            vec![AUTHENTICATION_SIGNATURE_CARD_UNAVAILABLE]
        );
    }
}
