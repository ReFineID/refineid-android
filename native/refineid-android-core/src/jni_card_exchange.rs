//! Synchronous JNI callback adapter for one Android-owned CCID session.
//!
//! The callback ABI returns a tagged byte array. Tag zero carries one card
//! response; every other tag is a typed transport state and carries no bytes.
//! Java arrays are cleared before their local references are released.

use jni::objects::{JByteArray, JObject, JValue};
use jni::strings::JNIStr;
use jni::{Env, jni_sig, jni_str};

use crate::card_transport::{SingleBlockExchange, SingleExchangeOutcome};

const REPLY_RESPONSE: u8 = 0;
const REPLY_NO_CARD: u8 = 1;
const REPLY_TIMEOUT_UNKNOWN_STATE: u8 = 2;
const REPLY_CARD_RESET: u8 = 3;
const REPLY_PROTOCOL_DESYNC: u8 = 4;
const REPLY_READER_REMOVED: u8 = 5;
const REPLY_BACKEND_FAILURE: u8 = 6;

const TAG_OFFSET: usize = 0;
const TAG_LENGTH: usize = 1;
const STATUS_WORD_LENGTH: usize = 2;
const MAXIMUM_RESPONSE_LENGTH: usize = 65_538;
const MAXIMUM_REPLY_LENGTH: usize = TAG_LENGTH + MAXIMUM_RESPONSE_LENGTH;

/// JNI-backed implementation of the narrow single-block callback.
pub(crate) struct JniBlockExchange<'env, 'local> {
    env: &'env mut Env<'local>,
    callback: JObject<'local>,
    bridge_failed: bool,
}

impl<'env, 'local> JniBlockExchange<'env, 'local> {
    /// Bind a callback object for the duration of one synchronous native call.
    pub(crate) const fn new(env: &'env mut Env<'local>, callback: JObject<'local>) -> Self {
        Self {
            env,
            callback,
            bridge_failed: false,
        }
    }

    /// Whether a JNI allocation, lookup, invocation, or conversion failed.
    pub(crate) const fn bridge_failed(&self) -> bool {
        self.bridge_failed
    }

    fn exchange(&mut self, method: &JNIStr, block: &[u8]) -> SingleExchangeOutcome {
        match self.invoke(method, block) {
            Ok(reply) => parse_reply(reply),
            Err(()) => {
                self.bridge_failed = true;
                SingleExchangeOutcome::BackendFailure
            }
        }
    }

    fn invoke(&mut self, method: &JNIStr, block: &[u8]) -> Result<Vec<u8>, ()> {
        let input = self.env.byte_array_from_slice(block).map_err(|_| ())?;
        let call = self.env.call_method(
            &self.callback,
            method,
            jni_sig!(([jbyte]) -> [jbyte]),
            &[JValue::Object(input.as_ref())],
        );

        let input_cleared = clear_java_array(self.env, &input);
        self.env.delete_local_ref(input);
        input_cleared?;

        let reply_object = call.map_err(|_| ())?.l().map_err(|_| ())?;
        let reply_array = JByteArray::cast_local(self.env, reply_object).map_err(|_| ())?;
        let converted = self.env.convert_byte_array(&reply_array).map_err(|_| ());
        let reply_cleared = clear_java_array(self.env, &reply_array);
        self.env.delete_local_ref(reply_array);
        reply_cleared?;
        converted
    }
}

impl SingleBlockExchange for JniBlockExchange<'_, '_> {
    fn exchange_public(&mut self, block: &[u8]) -> SingleExchangeOutcome {
        self.exchange(jni_str!("exchangePublic"), block)
    }

    fn exchange_credential(&mut self, block: &[u8]) -> SingleExchangeOutcome {
        self.exchange(jni_str!("exchangeCredential"), block)
    }
}

fn clear_java_array(env: &Env<'_>, array: &JByteArray<'_>) -> Result<(), ()> {
    let length = array.len(env).map_err(|_| ())?;
    let zeros = vec![0_i8; length];
    array.set_region(env, 0, &zeros).map_err(|_| ())
}

fn parse_reply(mut reply: Vec<u8>) -> SingleExchangeOutcome {
    if reply.is_empty() || reply.len() > MAXIMUM_REPLY_LENGTH {
        reply.fill(0);
        return SingleExchangeOutcome::ProtocolDesync;
    }

    let tag = reply[TAG_OFFSET];
    if tag == REPLY_RESPONSE {
        if reply.len() < TAG_LENGTH + STATUS_WORD_LENGTH {
            reply.fill(0);
            return SingleExchangeOutcome::ProtocolDesync;
        }
        let response = reply.split_off(TAG_LENGTH);
        reply.fill(0);
        return SingleExchangeOutcome::Response(response);
    }

    if reply.len() != TAG_LENGTH {
        reply.fill(0);
        return SingleExchangeOutcome::ProtocolDesync;
    }
    reply.fill(0);
    match tag {
        REPLY_NO_CARD => SingleExchangeOutcome::NoCard,
        REPLY_TIMEOUT_UNKNOWN_STATE => SingleExchangeOutcome::TimeoutUnknownState,
        REPLY_CARD_RESET => SingleExchangeOutcome::CardReset,
        REPLY_PROTOCOL_DESYNC => SingleExchangeOutcome::ProtocolDesync,
        REPLY_READER_REMOVED => SingleExchangeOutcome::ReaderRemoved,
        REPLY_BACKEND_FAILURE => SingleExchangeOutcome::BackendFailure,
        _ => SingleExchangeOutcome::ProtocolDesync,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAXIMUM_REPLY_LENGTH, REPLY_BACKEND_FAILURE, REPLY_CARD_RESET, REPLY_NO_CARD,
        REPLY_PROTOCOL_DESYNC, REPLY_READER_REMOVED, REPLY_RESPONSE, REPLY_TIMEOUT_UNKNOWN_STATE,
        parse_reply,
    };
    use crate::card_transport::SingleExchangeOutcome;

    const ISO_SUCCESS_FIRST: u8 = 0x90;
    const ISO_SUCCESS_SECOND: u8 = 0x00;
    const UNKNOWN_REPLY_TAG: u8 = 0x7f;
    const UNEXPECTED_FAULT_PAYLOAD: u8 = 0x00;
    const TRUNCATED_RESPONSE: &[u8] = &[REPLY_RESPONSE, ISO_SUCCESS_FIRST];
    const SYNTHETIC_RESPONSE: &[u8] = &[ISO_SUCCESS_FIRST, ISO_SUCCESS_SECOND];

    #[test]
    fn parses_response_and_every_typed_fault() {
        assert!(matches!(
            parse_reply([&[REPLY_RESPONSE], SYNTHETIC_RESPONSE].concat()),
            SingleExchangeOutcome::Response(bytes) if bytes == SYNTHETIC_RESPONSE
        ));
        assert!(matches!(
            parse_reply(vec![REPLY_NO_CARD]),
            SingleExchangeOutcome::NoCard
        ));
        assert!(matches!(
            parse_reply(vec![REPLY_TIMEOUT_UNKNOWN_STATE]),
            SingleExchangeOutcome::TimeoutUnknownState
        ));
        assert!(matches!(
            parse_reply(vec![REPLY_CARD_RESET]),
            SingleExchangeOutcome::CardReset
        ));
        assert!(matches!(
            parse_reply(vec![REPLY_PROTOCOL_DESYNC]),
            SingleExchangeOutcome::ProtocolDesync
        ));
        assert!(matches!(
            parse_reply(vec![REPLY_READER_REMOVED]),
            SingleExchangeOutcome::ReaderRemoved
        ));
        assert!(matches!(
            parse_reply(vec![REPLY_BACKEND_FAILURE]),
            SingleExchangeOutcome::BackendFailure
        ));
    }

    #[test]
    fn rejects_empty_short_unknown_and_payload_bearing_fault_replies() {
        for reply in [
            vec![],
            vec![REPLY_RESPONSE],
            TRUNCATED_RESPONSE.to_vec(),
            vec![UNKNOWN_REPLY_TAG],
            vec![REPLY_NO_CARD, UNEXPECTED_FAULT_PAYLOAD],
        ] {
            assert!(matches!(
                parse_reply(reply),
                SingleExchangeOutcome::ProtocolDesync
            ));
        }
    }

    #[test]
    fn rejects_reply_above_the_bound() {
        assert!(matches!(
            parse_reply(vec![REPLY_RESPONSE; MAXIMUM_REPLY_LENGTH + 1]),
            SingleExchangeOutcome::ProtocolDesync
        ));
    }
}
