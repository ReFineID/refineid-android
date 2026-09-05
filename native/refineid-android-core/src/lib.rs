//! Narrow JNI border between Android and the reviewed ReFineID core.
//!
//! ATR bytes return only a small typed status. Public authentication and
//! qualified-signature certificates cross back only after the core has bounded
//! each DER read and reconstructed its public key; credential bytes never cross
//! this border.

mod authentication_signer;
mod card_access;
mod card_certificate;
mod card_transport;
mod contactless;
mod jni_card_exchange;
mod pin1_status;
mod pin2_status;
mod qualified_signer;

use authentication_signer::{
    AuthenticationSignFailure, AuthenticationSignature, AuthenticationSigningAlgorithm,
    AuthenticationSigningInput, authenticate_and_sign,
};
use card_access::{CardAccessProbeFailure, CardAccessSummary, probe_card_access};
use card_certificate::{
    CardCertificate, CardKeyProfile, CertificateReadFailure, read_authentication_certificate,
    read_qualified_certificate,
};
use card_transport::{AndroidCardTransport, CardExchangeLevel};
use contactless::{
    contactless_authenticate_and_sign, contactless_authenticate_and_sign_on_session,
    contactless_close, contactless_connect, contactless_open, contactless_probe_pin2,
    contactless_qualified_sign, contactless_read_qualified_certificate,
};
use jni::objects::{JByteArray, JClass, JObject};
use jni::sys::jint;
use jni::{Env, NativeMethod};
use jni_card_exchange::JniBlockExchange;
use pin1_status::{Pin1Preflight, Pin1PreflightFailure, Pin1State, probe_pin1_preflight};
use pin2_status::{Pin2Preflight, Pin2PreflightFailure, Pin2State, probe_pin2_preflight};
use qualified_signer::{
    MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH, QualifiedSignFailure, QualifiedSignature,
    QualifiedSigningAlgorithm, QualifiedSigningInput, qualified_sign,
};
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

/// The held contactless session was dropped. Closing is best-effort and
/// touches no card, so the only outcome is success.
const CONTACTLESS_SESSION_CLOSED: jint = 0;

const CERTIFICATE_BRIDGE_ERROR: u8 = 0;
const CERTIFICATE_SUCCEEDED: u8 = 1;
const CERTIFICATE_CARD_UNAVAILABLE: u8 = 2;
const CERTIFICATE_REJECTED: u8 = 3;
const CERTIFICATE_TRANSPORT_ERROR: u8 = 4;
const CERTIFICATE_INVALID: u8 = 5;
const CERTIFICATE_PACE_REJECTED: u8 = 6;

const CARD_ACCESS_BRIDGE_ERROR: u8 = 0;
const CARD_ACCESS_SUCCEEDED: u8 = 1;
const CARD_ACCESS_CARD_UNAVAILABLE: u8 = 2;
const CARD_ACCESS_REJECTED: u8 = 3;
const CARD_ACCESS_TRANSPORT_ERROR: u8 = 4;
const CARD_ACCESS_INVALID: u8 = 5;

const PUBLISHED_PROFILE_ABSENT: u8 = 0;
const PUBLISHED_PROFILE_PRESENT: u8 = 1;

const PIN1_PREFLIGHT_BRIDGE_ERROR: u8 = 0;
const PIN1_PREFLIGHT_SUCCEEDED: u8 = 1;
const PIN1_PREFLIGHT_CARD_UNAVAILABLE: u8 = 2;
const PIN1_PREFLIGHT_TRANSPORT_ERROR: u8 = 3;

const PIN2_PREFLIGHT_BRIDGE_ERROR: u8 = 0;
const PIN2_PREFLIGHT_SUCCEEDED: u8 = 1;
const PIN2_PREFLIGHT_CARD_UNAVAILABLE: u8 = 2;
const PIN2_PREFLIGHT_TRANSPORT_ERROR: u8 = 3;

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
const AUTHENTICATION_SIGNATURE_PACE_REJECTED: u8 = 10;

const AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256: u8 = 0;
const AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256: u8 = 1;
const AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256: u8 = 2;
const AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384: u8 = 3;
const AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA256: u8 = 4;
const AUTHENTICATION_PREHASHED_RSA_PSS_SHA256: u8 = 5;
const AUTHENTICATION_PREHASHED_ECDSA_P384_SHA256: u8 = 6;
const AUTHENTICATION_PREHASHED_ECDSA_P384_SHA384: u8 = 7;
const AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA384: u8 = 8;
const AUTHENTICATION_ALGORITHM_RSA_PSS_SHA384: u8 = 9;
const AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA512: u8 = 10;
const AUTHENTICATION_ALGORITHM_RSA_PSS_SHA512: u8 = 11;
const AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA384: u8 = 12;
const AUTHENTICATION_PREHASHED_RSA_PSS_SHA384: u8 = 13;
const AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA512: u8 = 14;
const AUTHENTICATION_PREHASHED_RSA_PSS_SHA512: u8 = 15;

const QUALIFIED_SIGNATURE_BRIDGE_ERROR: u8 = 0;
const QUALIFIED_SIGNATURE_SUCCEEDED: u8 = 1;
const QUALIFIED_SIGNATURE_CARD_UNAVAILABLE: u8 = 2;
const QUALIFIED_SIGNATURE_TRANSPORT_ERROR: u8 = 3;
const QUALIFIED_SIGNATURE_INVALID_PIN: u8 = 4;
const QUALIFIED_SIGNATURE_SAFETY_REFUSED: u8 = 5;
const QUALIFIED_SIGNATURE_PIN_LOCKED: u8 = 6;
const QUALIFIED_SIGNATURE_WRONG_PIN: u8 = 7;
const QUALIFIED_SIGNATURE_VERIFICATION_REJECTED: u8 = 8;
const QUALIFIED_SIGNATURE_CERTIFICATE_REJECTED: u8 = 9;
const QUALIFIED_SIGNATURE_INVALID_CERTIFICATE: u8 = 10;
const QUALIFIED_SIGNATURE_CERTIFICATE_MISMATCH: u8 = 11;
const QUALIFIED_SIGNATURE_KEY_PROFILE_MISMATCH: u8 = 12;
const QUALIFIED_SIGNATURE_SIGNING_REJECTED: u8 = 13;

const QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384: u8 = 0;
const QUALIFIED_ALGORITHM_ECDSA_P384_SHA384: u8 = 1;
const QUALIFIED_PREHASHED_RSA_PKCS1_SHA384: u8 = 2;
const QUALIFIED_PREHASHED_ECDSA_P384_SHA384: u8 = 3;
const SHA384_DIGEST_LENGTH: usize = 48;

const PIN_REFERENCE_CITIZEN: u8 = 0;
const PIN_REFERENCE_ORGANIZATIONAL: u8 = 1;

const PIN1_STATE_VERIFIED: u8 = 0;
const PIN1_STATE_REMAINING: u8 = 1;
const PIN1_STATE_LOCKED: u8 = 2;
const PIN1_STATE_NO_INFORMATION: u8 = 3;
const PIN1_STATE_UNRECOGNISED: u8 = 4;

const PIN2_STATE_VERIFIED: u8 = 0;
const PIN2_STATE_REMAINING: u8 = 1;
const PIN2_STATE_LOCKED: u8 = 2;
const PIN2_STATE_NO_INFORMATION: u8 = 3;
const PIN2_STATE_UNRECOGNISED: u8 = 4;

const POLICY_REFUSED: u8 = 0;
const POLICY_PERMITTED: u8 = 1;
const NO_RETRY_COUNT: u8 = u8::MAX;

const KEY_PROFILE_RSA_2048: u8 = 0;
const KEY_PROFILE_RSA_3072: u8 = 1;
const KEY_PROFILE_ECDSA_P256: u8 = 2;
const KEY_PROFILE_ECDSA_P384: u8 = 3;

const CERTIFICATE_REPLY_HEADER_LENGTH: usize = 2;
const CARD_ACCESS_REPLY_LENGTH: usize = 3;
const CONTACTLESS_OPEN_HEADER_LENGTH: usize = 2;
const PIN1_PREFLIGHT_REPLY_LENGTH: usize = 5;
const PIN1_PREFLIGHT_REPLY_LENGTH_BYTE: u8 = PIN1_PREFLIGHT_REPLY_LENGTH as u8;
const PIN2_PREFLIGHT_REPLY_LENGTH: usize = 5;
const AUTHENTICATION_SIGNATURE_REPLY_HEADER_LENGTH: usize = 2;
const QUALIFIED_SIGNATURE_REPLY_HEADER_LENGTH: usize = 2;
const MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH: usize = 1_024 * 1_024;
const MAXIMUM_EXPECTED_CERTIFICATE_LENGTH: usize = 16 * 1_024;
const JAVA_ARRAY_CLEAR_CHUNK_LENGTH: usize = 64;

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn validate_atr_native(atr: [jbyte]) -> jint,
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeQualifiedCore",
    static extern fn read_qualified_certificate_native(
        exchange_level: jint,
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn authenticate_and_sign_native(
        exchange_level: jint,
        request: jint,
        pin: [jbyte],
        message: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeQualifiedCore",
    static extern fn qualified_sign_native(
        exchange_level: jint,
        algorithm: jint,
        pin: [jbyte],
        content: [jbyte],
        expected_certificate: [jbyte],
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
    java_type = "fi.refineid.android.core.NativeQualifiedCore",
    static extern fn probe_pin2_status_native(
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

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn read_card_face_photo_native() -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn read_card_document_number_native() -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeVerification",
    static extern fn read_card_verification_native() -> jint,
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeVerification",
    static extern fn add_csca_anchor_native(anchor_der: [jbyte]) -> jint,
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeVerification",
    static extern fn clear_csca_anchors_native() -> jint,
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessCore",
    static extern fn probe_card_access_native(
        exchange_level: jint,
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessCore",
    static extern fn contactless_open_native(
        can: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessCore",
    static extern fn contactless_authenticate_and_sign_native(
        can: [jbyte],
        request: jint,
        pin: [jbyte],
        message: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessCore",
    static extern fn contactless_read_qualified_certificate_native(
        can: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessCore",
    static extern fn contactless_probe_pin2_native(
        can: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessCore",
    static extern fn contactless_qualified_sign_native(
        can: [jbyte],
        algorithm: jint,
        pin: [jbyte],
        content: [jbyte],
        expected_certificate: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessSession",
    static extern fn contactless_connect_native(
        can: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessSession",
    static extern fn contactless_authenticate_and_sign_on_session_native(
        request: jint,
        pin: [jbyte],
        message: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessSession",
    static extern fn contactless_close_native() -> jint,
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
        encode_certificate_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

fn read_qualified_certificate_native<'local>(
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
        let result = read_qualified_certificate(&mut transport);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![CERTIFICATE_BRIDGE_ERROR]
    } else {
        encode_certificate_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

fn probe_card_access_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        return env.byte_array_from_slice(&[CARD_ACCESS_BRIDGE_ERROR]);
    };

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = AndroidCardTransport::new(exchange, level);
        let result = probe_card_access(&mut transport);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![CARD_ACCESS_BRIDGE_ERROR]
    } else {
        encode_card_access_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

fn contactless_open_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    can: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let can_bytes = take_secret_bytes(env, &can)?;

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
        let (result, exchange) = contactless_open(transport, can_bytes);
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![CERTIFICATE_BRIDGE_ERROR]
    } else {
        encode_contactless_open_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

/// The persistent-session opener. Identical to `contactless_open_native`
/// except it runs `contactless_connect`, which retains the live
/// secure-messaging session on full success so the sign that follows can
/// skip PACE.
fn contactless_connect_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    can: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let can_bytes = take_secret_bytes(env, &can)?;

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
        let (result, exchange) = contactless_connect(transport, can_bytes);
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![CERTIFICATE_BRIDGE_ERROR]
    } else {
        encode_contactless_open_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

/// The authentication signature on the session a prior `contactless_connect`
/// left open. It carries no CAN: the channel is rebuilt from the held
/// session and PACE is skipped. Otherwise it mirrors
/// `contactless_authenticate_and_sign_native` byte for byte.
fn contactless_authenticate_and_sign_on_session_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    request: jint,
    pin: JByteArray<'local>,
    message: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let mut pin_bytes = take_secret_bytes(env, &pin)?;

    let Some((algorithm, input_mode)) = authentication_request_from_jint(request) else {
        pin_bytes.fill(0);
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    };
    let message_length = match message.len(env) {
        Ok(length) => length,
        Err(error) => {
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    if message_length > MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH {
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
        let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
        let input = match input_mode {
            AuthenticationSigningInputMode::Message => {
                AuthenticationSigningInput::Message(&message_bytes)
            }
            AuthenticationSigningInputMode::Prehashed => {
                AuthenticationSigningInput::Prehashed(&message_bytes)
            }
        };
        let (result, exchange) =
            contactless_authenticate_and_sign_on_session(transport, algorithm, pin_bytes, input);
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

/// Drop the held contactless session and its keys. No card interaction: the
/// card's half dies with the field, so closing is a local clear that always
/// reports success.
fn contactless_close_native<'local>(
    _env: &mut Env<'local>,
    _class: JClass<'local>,
) -> Result<jint, jni::errors::Error> {
    contactless::set_last_read_face_photo(None);
    contactless::set_last_read_document_number(None);
    contactless_close();
    Ok(CONTACTLESS_SESSION_CLOSED)
}

fn read_card_face_photo_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let photo = contactless::get_last_read_face_photo();
    match photo {
        Some(bytes) => env.byte_array_from_slice(&bytes),
        None => env.new_byte_array(0),
    }
}

fn read_card_document_number_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let document_number = contactless::get_last_read_document_number();
    match document_number {
        Some(text) => env.byte_array_from_slice(text.as_bytes()),
        None => env.new_byte_array(0),
    }
}

fn read_card_verification_native<'local>(
    _env: &mut Env<'local>,
    _class: JClass<'local>,
) -> Result<jint, jni::errors::Error> {
    Ok(contactless::get_last_read_verification())
}

/// Installed count is returned so the platform can assert its anchor
/// assets actually arrived.
fn add_csca_anchor_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    anchor_der: JByteArray<'local>,
) -> Result<jint, jni::errors::Error> {
    let bytes = env.convert_byte_array(&anchor_der)?;
    contactless::add_csca_anchor(bytes);
    Ok(1)
}

fn clear_csca_anchors_native<'local>(
    _env: &mut Env<'local>,
    _class: JClass<'local>,
) -> Result<jint, jni::errors::Error> {
    contactless::clear_csca_anchors();
    Ok(0)
}

fn contactless_authenticate_and_sign_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    can: JByteArray<'local>,
    request: jint,
    pin: JByteArray<'local>,
    message: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let mut can_bytes = take_secret_bytes(env, &can)?;
    let mut pin_bytes = match take_secret_bytes(env, &pin) {
        Ok(bytes) => bytes,
        Err(error) => {
            can_bytes.fill(0);
            return Err(error);
        }
    };

    let Some((algorithm, input_mode)) = authentication_request_from_jint(request) else {
        can_bytes.fill(0);
        pin_bytes.fill(0);
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    };
    let message_length = match message.len(env) {
        Ok(length) => length,
        Err(error) => {
            can_bytes.fill(0);
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    if message_length > MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH {
        can_bytes.fill(0);
        pin_bytes.fill(0);
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    }
    let mut message_bytes = match env.convert_byte_array(&message) {
        Ok(bytes) => bytes,
        Err(error) => {
            can_bytes.fill(0);
            pin_bytes.fill(0);
            return Err(error);
        }
    };

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
        let input = match input_mode {
            AuthenticationSigningInputMode::Message => {
                AuthenticationSigningInput::Message(&message_bytes)
            }
            AuthenticationSigningInputMode::Prehashed => {
                AuthenticationSigningInput::Prehashed(&message_bytes)
            }
        };
        let (result, exchange) =
            contactless_authenticate_and_sign(transport, can_bytes, algorithm, pin_bytes, input);
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

fn contactless_read_qualified_certificate_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    can: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let can_bytes = take_secret_bytes(env, &can)?;

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
        let (result, exchange) = contactless_read_qualified_certificate(transport, can_bytes);
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![CERTIFICATE_BRIDGE_ERROR]
    } else {
        encode_certificate_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

fn contactless_probe_pin2_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    can: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let can_bytes = take_secret_bytes(env, &can)?;

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
        let (result, exchange) = contactless_probe_pin2(transport, can_bytes);
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![PIN2_PREFLIGHT_BRIDGE_ERROR]
    } else {
        encode_pin2_preflight_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

#[allow(
    clippy::too_many_arguments,
    reason = "the static JNI ABI carries the CAN and five explicit request fields plus its environment, class, and callback"
)]
fn contactless_qualified_sign_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    can: JByteArray<'local>,
    algorithm: jint,
    pin: JByteArray<'local>,
    content: JByteArray<'local>,
    expected_certificate: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let mut can_bytes = take_secret_bytes(env, &can)?;
    let mut pin_bytes = match take_secret_bytes(env, &pin) {
        Ok(bytes) => bytes,
        Err(error) => {
            can_bytes.fill(0);
            return Err(error);
        }
    };

    let Some((algorithm, input_mode)) = qualified_request_from_jint(algorithm) else {
        can_bytes.fill(0);
        pin_bytes.fill(0);
        return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
    };
    let content_length = match content.len(env) {
        Ok(length) => length,
        Err(error) => {
            can_bytes.fill(0);
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    match input_mode {
        QualifiedSigningInputMode::Message => {
            if content_length > MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH {
                can_bytes.fill(0);
                pin_bytes.fill(0);
                return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
            }
        }
        QualifiedSigningInputMode::Prehashed => {
            if content_length != SHA384_DIGEST_LENGTH {
                can_bytes.fill(0);
                pin_bytes.fill(0);
                return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
            }
        }
    }
    let certificate_length = match expected_certificate.len(env) {
        Ok(length) => length,
        Err(error) => {
            can_bytes.fill(0);
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    if certificate_length == 0 || certificate_length > MAXIMUM_EXPECTED_CERTIFICATE_LENGTH {
        can_bytes.fill(0);
        pin_bytes.fill(0);
        return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
    }

    let mut content_bytes = match env.convert_byte_array(&content) {
        Ok(bytes) => bytes,
        Err(error) => {
            can_bytes.fill(0);
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    let mut certificate_bytes = match env.convert_byte_array(&expected_certificate) {
        Ok(bytes) => bytes,
        Err(error) => {
            can_bytes.fill(0);
            pin_bytes.fill(0);
            content_bytes.fill(0);
            return Err(error);
        }
    };

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
        let input = match input_mode {
            QualifiedSigningInputMode::Message => QualifiedSigningInput::Message(&content_bytes),
            QualifiedSigningInputMode::Prehashed => {
                QualifiedSigningInput::Prehashed(&content_bytes)
            }
        };
        let (result, exchange) = contactless_qualified_sign(
            transport,
            can_bytes,
            algorithm,
            pin_bytes,
            input,
            &certificate_bytes,
        );
        (result, exchange.bridge_failed())
    };
    content_bytes.fill(0);
    certificate_bytes.fill(0);

    let mut reply = if bridge_failed {
        vec![QUALIFIED_SIGNATURE_BRIDGE_ERROR]
    } else {
        encode_qualified_signature_reply(result)
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

fn probe_pin2_status_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        return env.byte_array_from_slice(&[PIN2_PREFLIGHT_BRIDGE_ERROR]);
    };

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = AndroidCardTransport::new(exchange, level);
        let result = probe_pin2_preflight(&mut transport);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![PIN2_PREFLIGHT_BRIDGE_ERROR]
    } else {
        encode_pin2_preflight_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

fn authenticate_and_sign_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    request: jint,
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
    let Some((algorithm, input_mode)) = authentication_request_from_jint(request) else {
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
        let input = match input_mode {
            AuthenticationSigningInputMode::Message => {
                AuthenticationSigningInput::Message(&message_bytes)
            }
            AuthenticationSigningInputMode::Prehashed => {
                AuthenticationSigningInput::Prehashed(&message_bytes)
            }
        };
        let result = authenticate_and_sign(&mut transport, algorithm, pin_bytes, input);
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

#[allow(
    clippy::too_many_arguments,
    reason = "the static JNI ABI carries five explicit request fields plus its environment, class, and callback"
)]
fn qualified_sign_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    algorithm: jint,
    pin: JByteArray<'local>,
    content: JByteArray<'local>,
    expected_certificate: JByteArray<'local>,
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
        return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
    };
    let Some((algorithm, input_mode)) = qualified_request_from_jint(algorithm) else {
        pin_bytes.fill(0);
        return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
    };
    let content_length = match content.len(env) {
        Ok(length) => length,
        Err(error) => {
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    match input_mode {
        QualifiedSigningInputMode::Message => {
            if content_length > MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH {
                pin_bytes.fill(0);
                return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
            }
        }
        QualifiedSigningInputMode::Prehashed => {
            if content_length != SHA384_DIGEST_LENGTH {
                pin_bytes.fill(0);
                return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
            }
        }
    }
    let certificate_length = match expected_certificate.len(env) {
        Ok(length) => length,
        Err(error) => {
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    if certificate_length == 0 || certificate_length > MAXIMUM_EXPECTED_CERTIFICATE_LENGTH {
        pin_bytes.fill(0);
        return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
    }

    let mut content_bytes = match env.convert_byte_array(&content) {
        Ok(bytes) => bytes,
        Err(error) => {
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    let mut certificate_bytes = match env.convert_byte_array(&expected_certificate) {
        Ok(bytes) => bytes,
        Err(error) => {
            pin_bytes.fill(0);
            content_bytes.fill(0);
            return Err(error);
        }
    };
    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = AndroidCardTransport::new(exchange, level);
        let input = match input_mode {
            QualifiedSigningInputMode::Message => QualifiedSigningInput::Message(&content_bytes),
            QualifiedSigningInputMode::Prehashed => {
                QualifiedSigningInput::Prehashed(&content_bytes)
            }
        };
        let result = qualified_sign(
            &mut transport,
            algorithm,
            pin_bytes,
            input,
            &certificate_bytes,
        );
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };
    content_bytes.fill(0);
    certificate_bytes.fill(0);

    let mut reply = if bridge_failed {
        vec![QUALIFIED_SIGNATURE_BRIDGE_ERROR]
    } else {
        encode_qualified_signature_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

/// Copy a caller-owned secret array, clearing the Java copy immediately.
/// The returned bytes are the only remaining copy and must be zeroized
/// by the caller on every path.
fn take_secret_bytes(
    env: &mut Env<'_>,
    array: &JByteArray<'_>,
) -> Result<Vec<u8>, jni::errors::Error> {
    let mut bytes = match env.convert_byte_array(array) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = clear_java_byte_array(env, array);
            return Err(error);
        }
    };
    if let Err(error) = clear_java_byte_array(env, array) {
        bytes.fill(0);
        return Err(error);
    }
    Ok(bytes)
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
        value if value == jint::from(AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA384) => {
            Some(AuthenticationSigningAlgorithm::RsaPkcs1Sha384)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_RSA_PSS_SHA384) => {
            Some(AuthenticationSigningAlgorithm::RsaPssSha384)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA512) => {
            Some(AuthenticationSigningAlgorithm::RsaPkcs1Sha512)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_RSA_PSS_SHA512) => {
            Some(AuthenticationSigningAlgorithm::RsaPssSha512)
        }
        _ => None,
    }
}

fn qualified_algorithm_from_jint(value: jint) -> Option<QualifiedSigningAlgorithm> {
    match value {
        value if value == jint::from(QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384) => {
            Some(QualifiedSigningAlgorithm::RsaPkcs1Sha384)
        }
        value if value == jint::from(QUALIFIED_ALGORITHM_ECDSA_P384_SHA384) => {
            Some(QualifiedSigningAlgorithm::EcdsaP384Sha384)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QualifiedSigningInputMode {
    Message,
    Prehashed,
}

fn qualified_request_from_jint(
    value: jint,
) -> Option<(QualifiedSigningAlgorithm, QualifiedSigningInputMode)> {
    if let Some(algorithm) = qualified_algorithm_from_jint(value) {
        return Some((algorithm, QualifiedSigningInputMode::Message));
    }
    match value {
        value if value == jint::from(QUALIFIED_PREHASHED_RSA_PKCS1_SHA384) => Some((
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            QualifiedSigningInputMode::Prehashed,
        )),
        value if value == jint::from(QUALIFIED_PREHASHED_ECDSA_P384_SHA384) => Some((
            QualifiedSigningAlgorithm::EcdsaP384Sha384,
            QualifiedSigningInputMode::Prehashed,
        )),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticationSigningInputMode {
    Message,
    Prehashed,
}

fn authentication_request_from_jint(
    value: jint,
) -> Option<(
    AuthenticationSigningAlgorithm,
    AuthenticationSigningInputMode,
)> {
    if let Some(algorithm) = authentication_algorithm_from_jint(value) {
        return Some((algorithm, AuthenticationSigningInputMode::Message));
    }
    match value {
        value if value == jint::from(AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA256) => Some((
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_RSA_PSS_SHA256) => Some((
            AuthenticationSigningAlgorithm::RsaPssSha256,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_ECDSA_P384_SHA256) => Some((
            AuthenticationSigningAlgorithm::EcdsaP384Sha256,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_ECDSA_P384_SHA384) => Some((
            AuthenticationSigningAlgorithm::EcdsaP384Sha384,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA384) => Some((
            AuthenticationSigningAlgorithm::RsaPkcs1Sha384,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_RSA_PSS_SHA384) => Some((
            AuthenticationSigningAlgorithm::RsaPssSha384,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA512) => Some((
            AuthenticationSigningAlgorithm::RsaPkcs1Sha512,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_RSA_PSS_SHA512) => Some((
            AuthenticationSigningAlgorithm::RsaPssSha512,
            AuthenticationSigningInputMode::Prehashed,
        )),
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

fn encode_certificate_reply(result: Result<CardCertificate, CertificateReadFailure>) -> Vec<u8> {
    match result {
        Ok(mut certificate) => {
            let mut reply =
                Vec::with_capacity(CERTIFICATE_REPLY_HEADER_LENGTH + certificate.der.len());
            reply.push(CERTIFICATE_SUCCEEDED);
            reply.push(match certificate.profile {
                CardKeyProfile::Rsa2048 => KEY_PROFILE_RSA_2048,
                CardKeyProfile::Rsa3072 => KEY_PROFILE_RSA_3072,
                CardKeyProfile::EcdsaP256 => KEY_PROFILE_ECDSA_P256,
                CardKeyProfile::EcdsaP384 => KEY_PROFILE_ECDSA_P384,
            });
            reply.append(&mut certificate.der);
            reply
        }
        Err(failure) => vec![match failure {
            CertificateReadFailure::CardUnavailable => CERTIFICATE_CARD_UNAVAILABLE,
            CertificateReadFailure::Rejected => CERTIFICATE_REJECTED,
            CertificateReadFailure::Transport => CERTIFICATE_TRANSPORT_ERROR,
            CertificateReadFailure::InvalidCertificate => CERTIFICATE_INVALID,
            CertificateReadFailure::PaceRejected => CERTIFICATE_PACE_REJECTED,
            CertificateReadFailure::Bridge => CERTIFICATE_BRIDGE_ERROR,
        }],
    }
}

/// The contactless open reply nests the two established vocabularies:
/// `[CERTIFICATE_SUCCEEDED, preflight-reply length, preflight reply,
/// certificate reply]` on success, or one certificate-vocabulary failure
/// byte. Kotlin splits the wrapper and reuses both strict sub-decoders.
fn encode_contactless_open_reply(
    result: Result<(CardCertificate, Pin1Preflight), CertificateReadFailure>,
) -> Vec<u8> {
    match result {
        Ok((certificate, preflight)) => {
            let mut preflight_reply = encode_pin1_preflight_reply(Ok(preflight));
            let mut certificate_reply = encode_certificate_reply(Ok(certificate));
            let mut reply = Vec::with_capacity(
                CONTACTLESS_OPEN_HEADER_LENGTH + preflight_reply.len() + certificate_reply.len(),
            );
            reply.push(CERTIFICATE_SUCCEEDED);
            reply.push(PIN1_PREFLIGHT_REPLY_LENGTH_BYTE);
            reply.append(&mut preflight_reply);
            reply.append(&mut certificate_reply);
            reply
        }
        Err(failure) => encode_certificate_reply(Err(failure)),
    }
}

fn encode_card_access_reply(result: Result<CardAccessSummary, CardAccessProbeFailure>) -> Vec<u8> {
    match result {
        Ok(summary) => {
            let reply: [u8; CARD_ACCESS_REPLY_LENGTH] = [
                CARD_ACCESS_SUCCEEDED,
                if summary.supports_published_profile {
                    PUBLISHED_PROFILE_PRESENT
                } else {
                    PUBLISHED_PROFILE_ABSENT
                },
                summary.pace_entry_count,
            ];
            reply.to_vec()
        }
        Err(failure) => vec![match failure {
            CardAccessProbeFailure::CardUnavailable => CARD_ACCESS_CARD_UNAVAILABLE,
            CardAccessProbeFailure::Rejected => CARD_ACCESS_REJECTED,
            CardAccessProbeFailure::Transport => CARD_ACCESS_TRANSPORT_ERROR,
            CardAccessProbeFailure::Invalid => CARD_ACCESS_INVALID,
            CardAccessProbeFailure::Bridge => CARD_ACCESS_BRIDGE_ERROR,
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

fn encode_pin2_preflight_reply(result: Result<Pin2Preflight, Pin2PreflightFailure>) -> Vec<u8> {
    match result {
        Ok(preflight) => {
            let (state, retries) = match preflight.state {
                Pin2State::Verified => (PIN2_STATE_VERIFIED, NO_RETRY_COUNT),
                Pin2State::Remaining(retries) => (PIN2_STATE_REMAINING, retries),
                Pin2State::Locked => (PIN2_STATE_LOCKED, NO_RETRY_COUNT),
                Pin2State::NoInformation => (PIN2_STATE_NO_INFORMATION, NO_RETRY_COUNT),
                Pin2State::Unrecognised => (PIN2_STATE_UNRECOGNISED, NO_RETRY_COUNT),
            };
            let reply: [u8; PIN2_PREFLIGHT_REPLY_LENGTH] = [
                PIN2_PREFLIGHT_SUCCEEDED,
                match preflight.scheme {
                    PinReferenceScheme::Citizen => PIN_REFERENCE_CITIZEN,
                    PinReferenceScheme::Organizational => PIN_REFERENCE_ORGANIZATIONAL,
                },
                state,
                retries,
                if preflight.qualified_signature_permitted {
                    POLICY_PERMITTED
                } else {
                    POLICY_REFUSED
                },
            ];
            reply.to_vec()
        }
        Err(failure) => vec![match failure {
            Pin2PreflightFailure::CardUnavailable => PIN2_PREFLIGHT_CARD_UNAVAILABLE,
            Pin2PreflightFailure::Transport => PIN2_PREFLIGHT_TRANSPORT_ERROR,
            Pin2PreflightFailure::Bridge => PIN2_PREFLIGHT_BRIDGE_ERROR,
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
                AuthenticationSigningAlgorithm::RsaPkcs1Sha384 => {
                    AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA384
                }
                AuthenticationSigningAlgorithm::RsaPssSha384 => {
                    AUTHENTICATION_ALGORITHM_RSA_PSS_SHA384
                }
                AuthenticationSigningAlgorithm::RsaPkcs1Sha512 => {
                    AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA512
                }
                AuthenticationSigningAlgorithm::RsaPssSha512 => {
                    AUTHENTICATION_ALGORITHM_RSA_PSS_SHA512
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
            AuthenticationSignFailure::PaceRejected => AUTHENTICATION_SIGNATURE_PACE_REJECTED,
            AuthenticationSignFailure::Bridge => AUTHENTICATION_SIGNATURE_BRIDGE_ERROR,
        }],
    }
}

fn encode_qualified_signature_reply(
    result: Result<QualifiedSignature, QualifiedSignFailure>,
) -> Vec<u8> {
    match result {
        Ok(mut signature) => {
            let mut reply =
                Vec::with_capacity(QUALIFIED_SIGNATURE_REPLY_HEADER_LENGTH + signature.bytes.len());
            reply.push(QUALIFIED_SIGNATURE_SUCCEEDED);
            reply.push(match signature.algorithm {
                QualifiedSigningAlgorithm::RsaPkcs1Sha384 => QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384,
                QualifiedSigningAlgorithm::EcdsaP384Sha384 => QUALIFIED_ALGORITHM_ECDSA_P384_SHA384,
            });
            reply.append(&mut signature.bytes);
            reply
        }
        Err(failure) => vec![match failure {
            QualifiedSignFailure::InvalidPin => QUALIFIED_SIGNATURE_INVALID_PIN,
            QualifiedSignFailure::SafetyRefused => QUALIFIED_SIGNATURE_SAFETY_REFUSED,
            QualifiedSignFailure::PinLocked => QUALIFIED_SIGNATURE_PIN_LOCKED,
            QualifiedSignFailure::WrongPin => QUALIFIED_SIGNATURE_WRONG_PIN,
            QualifiedSignFailure::VerificationRejected => QUALIFIED_SIGNATURE_VERIFICATION_REJECTED,
            QualifiedSignFailure::CertificateRejected => QUALIFIED_SIGNATURE_CERTIFICATE_REJECTED,
            QualifiedSignFailure::InvalidCertificate => QUALIFIED_SIGNATURE_INVALID_CERTIFICATE,
            QualifiedSignFailure::CertificateMismatch => QUALIFIED_SIGNATURE_CERTIFICATE_MISMATCH,
            QualifiedSignFailure::KeyProfileMismatch => QUALIFIED_SIGNATURE_KEY_PROFILE_MISMATCH,
            QualifiedSignFailure::SigningRejected => QUALIFIED_SIGNATURE_SIGNING_REJECTED,
            QualifiedSignFailure::CardUnavailable => QUALIFIED_SIGNATURE_CARD_UNAVAILABLE,
            QualifiedSignFailure::Transport => QUALIFIED_SIGNATURE_TRANSPORT_ERROR,
            QualifiedSignFailure::Bridge => QUALIFIED_SIGNATURE_BRIDGE_ERROR,
        }],
    }
}

#[cfg(test)]
mod tests {
    use refineid_apdu::TransportOutcome;
    use refineid_atr::{Convention, MINIMAL_DIRECT_ATR};
    use refineid_auth::PinReferenceScheme;
    use refineid_pkcs15::Pkcs15Error;
    use refineid_sign::{ECDSA_P384_SIG_BYTES, RSA_3072_SIG_BYTES};

    use super::{
        ATR_INVALID, ATR_VALID_NON_T0_DIRECT, ATR_VALID_T0_DIRECT, ATR_VALID_T0_INVERSE,
        AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256, AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384,
        AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256, AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA384,
        AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA512, AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256,
        AUTHENTICATION_ALGORITHM_RSA_PSS_SHA384, AUTHENTICATION_ALGORITHM_RSA_PSS_SHA512,
        AUTHENTICATION_PREHASHED_ECDSA_P384_SHA256, AUTHENTICATION_PREHASHED_ECDSA_P384_SHA384,
        AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA256, AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA384,
        AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA512, AUTHENTICATION_PREHASHED_RSA_PSS_SHA256,
        AUTHENTICATION_PREHASHED_RSA_PSS_SHA384, AUTHENTICATION_PREHASHED_RSA_PSS_SHA512,
        AUTHENTICATION_SIGNATURE_CARD_UNAVAILABLE, AUTHENTICATION_SIGNATURE_PACE_REJECTED,
        AUTHENTICATION_SIGNATURE_REPLY_HEADER_LENGTH, AUTHENTICATION_SIGNATURE_SUCCEEDED,
        CARD_ACCESS_BRIDGE_ERROR, CARD_ACCESS_CARD_UNAVAILABLE, CARD_ACCESS_INVALID,
        CARD_ACCESS_REJECTED, CARD_ACCESS_REPLY_LENGTH, CARD_ACCESS_SUCCEEDED,
        CARD_ACCESS_TRANSPORT_ERROR, CARD_OPERATION_CARD_UNAVAILABLE, CARD_OPERATION_REJECTED,
        CARD_OPERATION_SUCCEEDED, CARD_OPERATION_TRANSPORT_ERROR, CERTIFICATE_CARD_UNAVAILABLE,
        CERTIFICATE_INVALID, CERTIFICATE_PACE_REJECTED, CERTIFICATE_REPLY_HEADER_LENGTH,
        CERTIFICATE_SUCCEEDED, EXCHANGE_LEVEL_APDU, EXCHANGE_LEVEL_T0_TPDU, KEY_PROFILE_RSA_2048,
        NO_RETRY_COUNT, PIN_REFERENCE_CITIZEN, PIN1_PREFLIGHT_BRIDGE_ERROR,
        PIN1_PREFLIGHT_CARD_UNAVAILABLE, PIN1_PREFLIGHT_REPLY_LENGTH,
        PIN1_PREFLIGHT_REPLY_LENGTH_BYTE, PIN1_PREFLIGHT_SUCCEEDED, PIN1_STATE_REMAINING,
        PIN2_PREFLIGHT_BRIDGE_ERROR, PIN2_PREFLIGHT_CARD_UNAVAILABLE, PIN2_PREFLIGHT_REPLY_LENGTH,
        PIN2_PREFLIGHT_SUCCEEDED, PIN2_STATE_REMAINING, POLICY_PERMITTED, PUBLISHED_PROFILE_ABSENT,
        PUBLISHED_PROFILE_PRESENT, QUALIFIED_ALGORITHM_ECDSA_P384_SHA384,
        QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384, QUALIFIED_PREHASHED_ECDSA_P384_SHA384,
        QUALIFIED_PREHASHED_RSA_PKCS1_SHA384, QUALIFIED_SIGNATURE_CARD_UNAVAILABLE,
        QUALIFIED_SIGNATURE_REPLY_HEADER_LENGTH, QUALIFIED_SIGNATURE_SUCCEEDED,
        authentication_algorithm_from_jint, authentication_request_from_jint,
        encode_authentication_signature_reply, encode_card_access_reply, encode_certificate_reply,
        encode_contactless_open_reply, encode_pin1_preflight_reply, encode_pin2_preflight_reply,
        encode_qualified_signature_reply, exchange_level_from_jint, map_pkcs15_selection_result,
        qualified_algorithm_from_jint, qualified_request_from_jint, validate_atr_bytes,
    };
    use crate::authentication_signer::{
        AuthenticationSignFailure, AuthenticationSignature, AuthenticationSigningAlgorithm,
    };
    use crate::card_access::{CardAccessProbeFailure, CardAccessSummary};
    use crate::card_certificate::{CardCertificate, CardKeyProfile, CertificateReadFailure};
    use crate::card_transport::{AndroidTransportError, CardExchangeLevel};
    use crate::pin1_status::{Pin1Preflight, Pin1PreflightFailure, Pin1State};
    use crate::pin2_status::{Pin2Preflight, Pin2PreflightFailure, Pin2State};
    use crate::qualified_signer::{
        QualifiedSignFailure, QualifiedSignature, QualifiedSigningAlgorithm,
    };

    const AUTHENTICATION_SIGNATURE_TAG_OFFSET: usize = 0;
    const AUTHENTICATION_SIGNATURE_ALGORITHM_OFFSET: usize = 1;
    const QUALIFIED_SIGNATURE_TAG_OFFSET: usize = 0;
    const QUALIFIED_SIGNATURE_ALGORITHM_OFFSET: usize = 1;
    const ATR_CONVENTION_OFFSET: usize = 0;
    const UNSUPPORTED_EXCHANGE_LEVEL: i32 = 2;
    const AUTHENTICATION_ALGORITHM_BELOW_RANGE: i32 = -1;
    const AUTHENTICATION_ALGORITHM_NON_MESSAGE_CODE: i32 =
        AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA256 as i32;
    const AUTHENTICATION_REQUEST_BELOW_RANGE: i32 = -1;
    const AUTHENTICATION_REQUEST_ABOVE_RANGE: i32 =
        AUTHENTICATION_PREHASHED_RSA_PSS_SHA512 as i32 + 1;
    const QUALIFIED_ALGORITHM_BELOW_RANGE: i32 = -1;
    const QUALIFIED_ALGORITHM_ABOVE_RANGE: i32 = 2;
    const QUALIFIED_REQUEST_ABOVE_RANGE: i32 = QUALIFIED_PREHASHED_ECDSA_P384_SHA384 as i32 + 1;
    const SYNTHETIC_REJECTED_STATUS_WORD: u16 = 0x6a82;
    const SYNTHETIC_DER_SEQUENCE_TAG: u8 = 0x30;
    const SYNTHETIC_DER_EMPTY_LENGTH: u8 = 0x00;
    const SYNTHETIC_PIN_RETRY_COUNT: u8 = 3;
    const PIN1_PREFLIGHT_RETRY_COUNT_OFFSET: usize = 3;
    const PIN2_PREFLIGHT_RETRY_COUNT_OFFSET: usize = 3;

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
        for (wire_value, algorithm) in [
            (
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256,
                AuthenticationSigningAlgorithm::RsaPssSha256,
            ),
            (
                AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256,
                AuthenticationSigningAlgorithm::EcdsaP384Sha256,
            ),
            (
                AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384,
                AuthenticationSigningAlgorithm::EcdsaP384Sha384,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA384,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha384,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PSS_SHA384,
                AuthenticationSigningAlgorithm::RsaPssSha384,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA512,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha512,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PSS_SHA512,
                AuthenticationSigningAlgorithm::RsaPssSha512,
            ),
        ] {
            assert_eq!(
                authentication_algorithm_from_jint(i32::from(wire_value)),
                Some(algorithm)
            );
        }
        assert_eq!(
            authentication_algorithm_from_jint(AUTHENTICATION_ALGORITHM_BELOW_RANGE),
            None
        );
        assert_eq!(
            authentication_algorithm_from_jint(AUTHENTICATION_ALGORITHM_NON_MESSAGE_CODE),
            None
        );
    }

    #[test]
    fn accepts_only_stable_qualified_algorithm_codes() {
        assert_eq!(
            qualified_algorithm_from_jint(i32::from(QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384)),
            Some(QualifiedSigningAlgorithm::RsaPkcs1Sha384)
        );
        assert_eq!(
            qualified_algorithm_from_jint(QUALIFIED_ALGORITHM_BELOW_RANGE),
            None
        );
        assert_eq!(
            qualified_algorithm_from_jint(QUALIFIED_ALGORITHM_ABOVE_RANGE),
            None
        );
    }

    #[test]
    fn accepts_only_stable_qualified_request_codes() {
        assert_eq!(
            qualified_request_from_jint(i32::from(QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384)),
            Some((
                QualifiedSigningAlgorithm::RsaPkcs1Sha384,
                super::QualifiedSigningInputMode::Message
            ))
        );
        assert_eq!(
            qualified_request_from_jint(i32::from(QUALIFIED_ALGORITHM_ECDSA_P384_SHA384)),
            Some((
                QualifiedSigningAlgorithm::EcdsaP384Sha384,
                super::QualifiedSigningInputMode::Message
            ))
        );
        assert_eq!(
            qualified_request_from_jint(i32::from(QUALIFIED_PREHASHED_RSA_PKCS1_SHA384)),
            Some((
                QualifiedSigningAlgorithm::RsaPkcs1Sha384,
                super::QualifiedSigningInputMode::Prehashed
            ))
        );
        assert_eq!(
            qualified_request_from_jint(i32::from(QUALIFIED_PREHASHED_ECDSA_P384_SHA384)),
            Some((
                QualifiedSigningAlgorithm::EcdsaP384Sha384,
                super::QualifiedSigningInputMode::Prehashed
            ))
        );
        assert_eq!(
            qualified_request_from_jint(QUALIFIED_ALGORITHM_BELOW_RANGE),
            None
        );
        assert_eq!(
            qualified_request_from_jint(QUALIFIED_REQUEST_ABOVE_RANGE),
            None
        );
    }

    #[test]
    fn accepts_only_stable_authentication_request_codes() {
        for (wire_value, algorithm) in [
            (
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256,
                AuthenticationSigningAlgorithm::RsaPssSha256,
            ),
            (
                AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256,
                AuthenticationSigningAlgorithm::EcdsaP384Sha256,
            ),
            (
                AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384,
                AuthenticationSigningAlgorithm::EcdsaP384Sha384,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA384,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha384,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PSS_SHA384,
                AuthenticationSigningAlgorithm::RsaPssSha384,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA512,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha512,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PSS_SHA512,
                AuthenticationSigningAlgorithm::RsaPssSha512,
            ),
        ] {
            assert_eq!(
                authentication_request_from_jint(i32::from(wire_value)),
                Some((algorithm, super::AuthenticationSigningInputMode::Message))
            );
        }
        for (wire_value, algorithm) in [
            (
                AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA256,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            ),
            (
                AUTHENTICATION_PREHASHED_RSA_PSS_SHA256,
                AuthenticationSigningAlgorithm::RsaPssSha256,
            ),
            (
                AUTHENTICATION_PREHASHED_ECDSA_P384_SHA256,
                AuthenticationSigningAlgorithm::EcdsaP384Sha256,
            ),
            (
                AUTHENTICATION_PREHASHED_ECDSA_P384_SHA384,
                AuthenticationSigningAlgorithm::EcdsaP384Sha384,
            ),
            (
                AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA384,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha384,
            ),
            (
                AUTHENTICATION_PREHASHED_RSA_PSS_SHA384,
                AuthenticationSigningAlgorithm::RsaPssSha384,
            ),
            (
                AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA512,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha512,
            ),
            (
                AUTHENTICATION_PREHASHED_RSA_PSS_SHA512,
                AuthenticationSigningAlgorithm::RsaPssSha512,
            ),
        ] {
            assert_eq!(
                authentication_request_from_jint(i32::from(wire_value)),
                Some((algorithm, super::AuthenticationSigningInputMode::Prehashed))
            );
        }
        assert_eq!(
            authentication_request_from_jint(AUTHENTICATION_REQUEST_BELOW_RANGE),
            None
        );
        assert_eq!(
            authentication_request_from_jint(AUTHENTICATION_REQUEST_ABOVE_RANGE),
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
        let success = encode_certificate_reply(Ok(CardCertificate {
            profile: CardKeyProfile::Rsa2048,
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
            encode_certificate_reply(Err(CertificateReadFailure::CardUnavailable)),
            vec![CERTIFICATE_CARD_UNAVAILABLE]
        );
        assert_eq!(
            encode_certificate_reply(Err(CertificateReadFailure::InvalidCertificate)),
            vec![CERTIFICATE_INVALID]
        );
    }

    #[test]
    fn encodes_card_access_summary_and_typed_failures() {
        const SYNTHETIC_PACE_ENTRY_COUNT: u8 = 2;
        let published = encode_card_access_reply(Ok(CardAccessSummary {
            supports_published_profile: true,
            pace_entry_count: SYNTHETIC_PACE_ENTRY_COUNT,
        }));
        assert_eq!(
            published,
            vec![
                CARD_ACCESS_SUCCEEDED,
                PUBLISHED_PROFILE_PRESENT,
                SYNTHETIC_PACE_ENTRY_COUNT,
            ]
        );
        assert_eq!(published.len(), CARD_ACCESS_REPLY_LENGTH);
        assert_eq!(
            encode_card_access_reply(Ok(CardAccessSummary {
                supports_published_profile: false,
                pace_entry_count: 1,
            })),
            vec![CARD_ACCESS_SUCCEEDED, PUBLISHED_PROFILE_ABSENT, 1]
        );
        assert_eq!(
            encode_card_access_reply(Err(CardAccessProbeFailure::CardUnavailable)),
            vec![CARD_ACCESS_CARD_UNAVAILABLE]
        );
        assert_eq!(
            encode_card_access_reply(Err(CardAccessProbeFailure::Rejected)),
            vec![CARD_ACCESS_REJECTED]
        );
        assert_eq!(
            encode_card_access_reply(Err(CardAccessProbeFailure::Transport)),
            vec![CARD_ACCESS_TRANSPORT_ERROR]
        );
        assert_eq!(
            encode_card_access_reply(Err(CardAccessProbeFailure::Invalid)),
            vec![CARD_ACCESS_INVALID]
        );
        assert_eq!(
            encode_card_access_reply(Err(CardAccessProbeFailure::Bridge)),
            vec![CARD_ACCESS_BRIDGE_ERROR]
        );
    }

    #[test]
    fn encodes_contactless_open_as_nested_established_replies() {
        const SYNTHETIC_DER: &[u8] = &[SYNTHETIC_DER_SEQUENCE_TAG, SYNTHETIC_DER_EMPTY_LENGTH];
        let success = encode_contactless_open_reply(Ok((
            CardCertificate {
                profile: CardKeyProfile::Rsa2048,
                der: SYNTHETIC_DER.to_vec(),
            },
            Pin1Preflight {
                scheme: PinReferenceScheme::Citizen,
                state: Pin1State::Remaining(SYNTHETIC_PIN_RETRY_COUNT),
                consumer_authentication_permitted: true,
            },
        )));
        assert_eq!(
            success,
            [
                &[
                    CERTIFICATE_SUCCEEDED,
                    PIN1_PREFLIGHT_REPLY_LENGTH_BYTE,
                    PIN1_PREFLIGHT_SUCCEEDED,
                    PIN_REFERENCE_CITIZEN,
                    PIN1_STATE_REMAINING,
                    SYNTHETIC_PIN_RETRY_COUNT,
                    POLICY_PERMITTED,
                    CERTIFICATE_SUCCEEDED,
                    KEY_PROFILE_RSA_2048,
                ],
                SYNTHETIC_DER,
            ]
            .concat()
        );
        assert_eq!(
            encode_contactless_open_reply(Err(CertificateReadFailure::PaceRejected)),
            vec![CERTIFICATE_PACE_REJECTED]
        );
        assert_eq!(
            encode_contactless_open_reply(Err(CertificateReadFailure::CardUnavailable)),
            vec![CERTIFICATE_CARD_UNAVAILABLE]
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
    fn encodes_pin2_preflight_without_raw_card_values() {
        let success = encode_pin2_preflight_reply(Ok(Pin2Preflight {
            scheme: PinReferenceScheme::Citizen,
            state: Pin2State::Remaining(SYNTHETIC_PIN_RETRY_COUNT),
            qualified_signature_permitted: true,
        }));
        assert_eq!(
            success,
            vec![
                PIN2_PREFLIGHT_SUCCEEDED,
                PIN_REFERENCE_CITIZEN,
                PIN2_STATE_REMAINING,
                SYNTHETIC_PIN_RETRY_COUNT,
                POLICY_PERMITTED,
            ]
        );
        assert_eq!(success.len(), PIN2_PREFLIGHT_REPLY_LENGTH);
        assert_ne!(success[PIN2_PREFLIGHT_RETRY_COUNT_OFFSET], NO_RETRY_COUNT);
        assert_eq!(
            encode_pin2_preflight_reply(Err(Pin2PreflightFailure::CardUnavailable)),
            vec![PIN2_PREFLIGHT_CARD_UNAVAILABLE]
        );
        assert_eq!(
            encode_pin2_preflight_reply(Err(Pin2PreflightFailure::Bridge)),
            vec![PIN2_PREFLIGHT_BRIDGE_ERROR]
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
        assert_eq!(
            encode_authentication_signature_reply(Err(AuthenticationSignFailure::PaceRejected)),
            vec![AUTHENTICATION_SIGNATURE_PACE_REJECTED]
        );
    }

    #[test]
    fn encodes_qualified_signature_success_and_coarse_failure() {
        const SYNTHETIC_QUALIFIED_SIGNATURE_FILL: u8 = 0xC3;
        const SYNTHETIC_QUALIFIED_SIGNATURE: [u8; RSA_3072_SIG_BYTES] =
            [SYNTHETIC_QUALIFIED_SIGNATURE_FILL; RSA_3072_SIG_BYTES];
        let success = encode_qualified_signature_reply(Ok(QualifiedSignature {
            algorithm: QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            bytes: SYNTHETIC_QUALIFIED_SIGNATURE.to_vec(),
        }));
        assert_eq!(
            success[QUALIFIED_SIGNATURE_TAG_OFFSET],
            QUALIFIED_SIGNATURE_SUCCEEDED
        );
        assert_eq!(
            success[QUALIFIED_SIGNATURE_ALGORITHM_OFFSET],
            QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384
        );
        assert_eq!(
            &success[QUALIFIED_SIGNATURE_REPLY_HEADER_LENGTH..],
            &SYNTHETIC_QUALIFIED_SIGNATURE
        );
        assert_eq!(
            encode_qualified_signature_reply(Err(QualifiedSignFailure::CardUnavailable)),
            vec![QUALIFIED_SIGNATURE_CARD_UNAVAILABLE]
        );
    }
}
