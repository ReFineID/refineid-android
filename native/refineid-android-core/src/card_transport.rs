//! Logical APDU transport over one Android-owned CCID block session.
//!
//! Kotlin moves one validated CCID transfer block. This module retains the
//! ISO 7816 behavior: T=0 case conversion, bounded response continuation,
//! one typed public wrong-Le correction, and a non-replayable credential path.

use refineid_apdu::iso7816::GetResponse;
use refineid_apdu::{
    ApduClass, CardTransport, CommandApdu, CredentialCommand, ResponseApdu, TransportErrorExt,
    TransportErrorKind, TransportOutcome,
};

const SW1_BYTES_AVAILABLE: u8 = 0x61;
const SW1_WRONG_LE: u8 = 0x6C;
const STATUS_WORD_LENGTH: usize = 2;
const CHAIN_BODY_MAXIMUM: usize = 1 << 16;
const HEADER_AND_LC_LENGTH: usize = 5;
const TRAILING_LE_LENGTH: usize = 1;

/// Exchange format declared by the admitted CCID functional descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardExchangeLevel {
    /// Reader accepts complete command APDUs.
    Apdu,
    /// Reader accepts ISO 7816-3 T=0 command TPDUs.
    T0Tpdu,
}

/// Result of exactly one Kotlin-owned CCID block exchange.
pub(crate) enum SingleExchangeOutcome {
    /// Raw card response including trailing SW1 and SW2.
    Response(Vec<u8>),
    /// Slot was empty.
    NoCard,
    /// Transfer timed out with uncertain card state.
    TimeoutUnknownState,
    /// Card reset during the exchange.
    CardReset,
    /// CCID or session framing was lost.
    ProtocolDesync,
    /// Reader or session disappeared.
    ReaderRemoved,
    /// Android backend failure without a more specific mapping.
    BackendFailure,
}

impl core::fmt::Debug for SingleExchangeOutcome {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Response(bytes) => formatter
                .debug_struct("Response")
                .field("length", &bytes.len())
                .finish(),
            Self::NoCard => formatter.write_str("NoCard"),
            Self::TimeoutUnknownState => formatter.write_str("TimeoutUnknownState"),
            Self::CardReset => formatter.write_str("CardReset"),
            Self::ProtocolDesync => formatter.write_str("ProtocolDesync"),
            Self::ReaderRemoved => formatter.write_str("ReaderRemoved"),
            Self::BackendFailure => formatter.write_str("BackendFailure"),
        }
    }
}

/// Distinct byte-moving entry points implemented by the JNI callback object.
pub(crate) trait SingleBlockExchange {
    /// Move one replay-safe block.
    fn exchange_public(&mut self, block: &[u8]) -> SingleExchangeOutcome;

    /// Move one credential-bearing block exactly once.
    fn exchange_credential(&mut self, block: &[u8]) -> SingleExchangeOutcome;
}

/// Adapter-local failures not already represented by [`TransportOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AndroidTransportError {
    /// Android reported a backend failure.
    Backend,
    /// A response continuation exceeded the ISO 7816 bound.
    ChainTooLong,
    /// A card repeatedly announced more data without returning any.
    ChainStalled,
}

impl core::fmt::Display for AndroidTransportError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Backend => formatter.write_str("Android card transport backend failed"),
            Self::ChainTooLong => formatter.write_str("card response chain exceeded 64 KiB"),
            Self::ChainStalled => formatter.write_str("card response chain made no progress"),
        }
    }
}

impl TransportErrorExt for AndroidTransportError {
    fn kind(&self) -> TransportErrorKind {
        match self {
            Self::Backend => TransportErrorKind::Backend,
            Self::ChainTooLong | Self::ChainStalled => TransportErrorKind::ProtocolDesync,
        }
    }
}

enum ParsedExchange {
    Response(ResponseApdu),
    Fault(TransportOutcome),
}

/// A `refineid-core` transport backed by a synchronous Android block mover.
pub(crate) struct AndroidCardTransport<Exchange> {
    exchange: Exchange,
    level: CardExchangeLevel,
}

impl<Exchange> AndroidCardTransport<Exchange> {
    /// Bind one exchange callback to the descriptor-proven exchange level.
    pub(crate) const fn new(exchange: Exchange, level: CardExchangeLevel) -> Self {
        Self { exchange, level }
    }

    /// Return the byte-moving adapter after a bounded card operation.
    pub(crate) fn into_exchange(self) -> Exchange {
        self.exchange
    }
}

impl<Exchange: SingleBlockExchange> AndroidCardTransport<Exchange> {
    fn send_public_wire(&mut self, wire: &[u8]) -> Result<ParsedExchange, AndroidTransportError> {
        let block = lower_for_exchange_level(self.level, wire);
        parse_single_exchange(self.exchange.exchange_public(block))
    }

    fn send_credential_wire(
        &mut self,
        wire: &[u8],
    ) -> Result<ParsedExchange, AndroidTransportError> {
        let block = lower_for_exchange_level(self.level, wire);
        parse_single_exchange(self.exchange.exchange_credential(block))
    }

    fn settle_response_chain(
        &mut self,
        first_body: Vec<u8>,
        first_le: u8,
    ) -> Result<TransportOutcome, AndroidTransportError> {
        let mut combined = first_body;
        let mut next_le = first_le;
        loop {
            let get_response = GetResponse {
                class: ApduClass::Plain,
                le: next_le,
            }
            .into_apdu();
            let response = match self.send_public_wire(get_response.as_bytes())? {
                ParsedExchange::Fault(fault) => return Ok(fault),
                ParsedExchange::Response(response) => response,
            };
            let progressed = !response.body.is_empty();
            let Some(combined_length) = combined.len().checked_add(response.body.len()) else {
                return Err(AndroidTransportError::ChainTooLong);
            };
            if combined_length > CHAIN_BODY_MAXIMUM {
                return Err(AndroidTransportError::ChainTooLong);
            }
            combined.extend_from_slice(&response.body);
            if response.sw1 != SW1_BYTES_AVAILABLE {
                return Ok(TransportOutcome::Response(ResponseApdu {
                    body: combined,
                    sw1: response.sw1,
                    sw2: response.sw2,
                }));
            }
            if !progressed {
                return Err(AndroidTransportError::ChainStalled);
            }
            next_le = response.sw2;
        }
    }

    fn finish_response(
        &mut self,
        response: ResponseApdu,
    ) -> Result<TransportOutcome, AndroidTransportError> {
        if response.sw1 == SW1_BYTES_AVAILABLE {
            self.settle_response_chain(response.body, response.sw2)
        } else {
            Ok(TransportOutcome::Response(response))
        }
    }
}

impl<Exchange: SingleBlockExchange> CardTransport for AndroidCardTransport<Exchange> {
    type Error = AndroidTransportError;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let mut corrected: Option<CommandApdu> = None;
        loop {
            let selected = corrected.as_ref().unwrap_or(command);
            let response = match self.send_public_wire(selected.as_bytes())? {
                ParsedExchange::Fault(fault) => return Ok(fault),
                ParsedExchange::Response(response) => response,
            };
            if response.sw1 == SW1_WRONG_LE
                && let Some(next) = selected.corrected_wrong_le(response.sw2)
            {
                corrected = Some(next);
                continue;
            }
            return self.finish_response(response);
        }
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        command.expose_wire(|wire| {
            let response = match self.send_credential_wire(wire)? {
                ParsedExchange::Fault(fault) => return Ok(fault),
                ParsedExchange::Response(response) => response,
            };
            self.finish_response(response)
        })
    }
}

fn lower_for_exchange_level(level: CardExchangeLevel, wire: &[u8]) -> &[u8] {
    if level != CardExchangeLevel::T0Tpdu {
        return wire;
    }
    short_case_4_prefix(wire).unwrap_or(wire)
}

/// T=0 sends a short case-4 APDU as its case-3 prefix; response data follows
/// through the card's ordinary `61xx`/GET RESPONSE exchange.
fn short_case_4_prefix(wire: &[u8]) -> Option<&[u8]> {
    let lc = usize::from(*wire.get(4)?);
    if lc == 0 {
        return None;
    }
    let expected_length = HEADER_AND_LC_LENGTH
        .checked_add(lc)?
        .checked_add(TRAILING_LE_LENGTH)?;
    if wire.len() != expected_length {
        return None;
    }
    wire.get(..wire.len().checked_sub(TRAILING_LE_LENGTH)?)
}

fn parse_single_exchange(
    outcome: SingleExchangeOutcome,
) -> Result<ParsedExchange, AndroidTransportError> {
    match outcome {
        SingleExchangeOutcome::Response(mut bytes) => {
            if bytes.len() < STATUS_WORD_LENGTH {
                return Ok(ParsedExchange::Fault(TransportOutcome::ProtocolDesync));
            }
            let status_offset = bytes.len() - STATUS_WORD_LENGTH;
            let status = bytes.split_off(status_offset);
            let [sw1, sw2] = status.as_slice() else {
                return Ok(ParsedExchange::Fault(TransportOutcome::ProtocolDesync));
            };
            Ok(ParsedExchange::Response(ResponseApdu {
                body: bytes,
                sw1: *sw1,
                sw2: *sw2,
            }))
        }
        SingleExchangeOutcome::NoCard => Ok(ParsedExchange::Fault(TransportOutcome::NoCard)),
        SingleExchangeOutcome::TimeoutUnknownState => {
            Ok(ParsedExchange::Fault(TransportOutcome::TimeoutUnknownState))
        }
        SingleExchangeOutcome::CardReset => Ok(ParsedExchange::Fault(TransportOutcome::CardReset)),
        SingleExchangeOutcome::ProtocolDesync => {
            Ok(ParsedExchange::Fault(TransportOutcome::ProtocolDesync))
        }
        SingleExchangeOutcome::ReaderRemoved => {
            Ok(ParsedExchange::Fault(TransportOutcome::ReaderRemoved))
        }
        SingleExchangeOutcome::BackendFailure => Err(AndroidTransportError::Backend),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use refineid_apdu::iso7816::GetResponse;
    use refineid_apdu::{
        ApduClass, CardTransport as _, CommandApdu, CommandDataError, CommandHeader,
        CredentialBodyError, CredentialCommand, TransportOutcome,
    };

    use super::{
        AndroidCardTransport, AndroidTransportError, CardExchangeLevel, SW1_WRONG_LE,
        SingleBlockExchange, SingleExchangeOutcome,
    };

    const SYNTHETIC_INSTRUCTION: u8 = 0xE2;
    const SYNTHETIC_PARAMETER_ONE: u8 = 0x11;
    const SYNTHETIC_PARAMETER_TWO: u8 = 0x22;
    const SYNTHETIC_DATA_ONE: u8 = 0xA1;
    const SYNTHETIC_DATA_TWO: u8 = 0xA2;
    const SYNTHETIC_LE: u8 = 0x08;
    const CORRECTED_LE: u8 = 0x10;
    const SW1_SUCCESS: u8 = 0x90;
    const SW2_SUCCESS: u8 = 0x00;
    const SW1_BYTES_AVAILABLE: u8 = 0x61;
    const VERIFY_INSTRUCTION: u8 = 0x20;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ExpectedPath {
        Public,
        Credential,
    }

    struct ScriptStep {
        path: ExpectedPath,
        expected: Vec<u8>,
        outcome: SingleExchangeOutcome,
    }

    struct ScriptedExchange {
        steps: VecDeque<ScriptStep>,
        violation: Option<&'static str>,
        public_count: usize,
        credential_count: usize,
    }

    impl ScriptedExchange {
        fn new(steps: Vec<ScriptStep>) -> Self {
            Self {
                steps: steps.into(),
                violation: None,
                public_count: 0,
                credential_count: 0,
            }
        }

        fn take(&mut self, path: ExpectedPath, block: &[u8]) -> SingleExchangeOutcome {
            let Some(step) = self.steps.pop_front() else {
                self.violation = Some("unexpected exchange");
                return SingleExchangeOutcome::BackendFailure;
            };
            if step.path != path {
                self.violation = Some("wrong exchange path");
                return SingleExchangeOutcome::BackendFailure;
            }
            if step.expected.as_slice() != block {
                self.violation = Some("unexpected transfer block");
                return SingleExchangeOutcome::BackendFailure;
            }
            step.outcome
        }
    }

    impl SingleBlockExchange for ScriptedExchange {
        fn exchange_public(&mut self, block: &[u8]) -> SingleExchangeOutcome {
            self.public_count += 1;
            self.take(ExpectedPath::Public, block)
        }

        fn exchange_credential(&mut self, block: &[u8]) -> SingleExchangeOutcome {
            self.credential_count += 1;
            self.take(ExpectedPath::Credential, block)
        }
    }

    fn header() -> CommandHeader {
        CommandHeader {
            class: ApduClass::Plain,
            instruction: SYNTHETIC_INSTRUCTION,
            p1: SYNTHETIC_PARAMETER_ONE,
            p2: SYNTHETIC_PARAMETER_TWO,
        }
    }

    fn response(body: &[u8], sw1: u8, sw2: u8) -> SingleExchangeOutcome {
        let mut bytes = body.to_vec();
        bytes.extend_from_slice(&[sw1, sw2]);
        SingleExchangeOutcome::Response(bytes)
    }

    fn assert_script_complete(transport: &AndroidCardTransport<ScriptedExchange>) {
        assert_eq!(transport.exchange.violation, None);
        assert!(transport.exchange.steps.is_empty());
    }

    #[test]
    fn apdu_level_passes_short_case_4_unchanged() -> Result<(), CommandDataError> {
        let command = CommandApdu::case_4(header(), &[SYNTHETIC_DATA_ONE], SYNTHETIC_LE)?;
        let expected = command.as_bytes().to_vec();
        let exchange = ScriptedExchange::new(vec![ScriptStep {
            path: ExpectedPath::Public,
            expected,
            outcome: response(&[], SW1_SUCCESS, SW2_SUCCESS),
        }]);
        let mut transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);

        let outcome = transport.transmit(&command);

        assert!(matches!(
            outcome,
            Ok(TransportOutcome::Response(answer)) if answer.is_ok()
        ));
        assert_script_complete(&transport);
        Ok(())
    }

    #[test]
    fn t0_lowers_short_case_4_and_settles_response() -> Result<(), CommandDataError> {
        let command = CommandApdu::case_4(
            header(),
            &[SYNTHETIC_DATA_ONE, SYNTHETIC_DATA_TWO],
            SYNTHETIC_LE,
        )?;
        let mut prefix = command.as_bytes().to_vec();
        let _removed_le = prefix.pop();
        let get_response = GetResponse {
            class: ApduClass::Plain,
            le: 2,
        }
        .into_apdu();
        let exchange = ScriptedExchange::new(vec![
            ScriptStep {
                path: ExpectedPath::Public,
                expected: prefix,
                outcome: response(&[SYNTHETIC_DATA_ONE], SW1_BYTES_AVAILABLE, 2),
            },
            ScriptStep {
                path: ExpectedPath::Public,
                expected: get_response.as_bytes().to_vec(),
                outcome: response(
                    &[SYNTHETIC_DATA_TWO, SYNTHETIC_LE],
                    SW1_SUCCESS,
                    SW2_SUCCESS,
                ),
            },
        ]);
        let mut transport = AndroidCardTransport::new(exchange, CardExchangeLevel::T0Tpdu);

        let outcome = transport.transmit(&command);

        assert!(matches!(
            outcome,
            Ok(TransportOutcome::Response(answer))
                if answer.is_ok()
                    && answer.body
                        == vec![SYNTHETIC_DATA_ONE, SYNTHETIC_DATA_TWO, SYNTHETIC_LE]
        ));
        assert_eq!(transport.exchange.public_count, 2);
        assert_script_complete(&transport);
        Ok(())
    }

    #[test]
    fn applies_one_builder_authorized_wrong_le_correction() {
        let command = GetResponse {
            class: ApduClass::Plain,
            le: 0,
        }
        .into_apdu();
        let corrected = GetResponse {
            class: ApduClass::Plain,
            le: CORRECTED_LE,
        }
        .into_apdu();
        let exchange = ScriptedExchange::new(vec![
            ScriptStep {
                path: ExpectedPath::Public,
                expected: command.as_bytes().to_vec(),
                outcome: response(&[], SW1_WRONG_LE, CORRECTED_LE),
            },
            ScriptStep {
                path: ExpectedPath::Public,
                expected: corrected.as_bytes().to_vec(),
                outcome: response(&[SYNTHETIC_DATA_ONE], SW1_SUCCESS, SW2_SUCCESS),
            },
        ]);
        let mut transport = AndroidCardTransport::new(exchange, CardExchangeLevel::T0Tpdu);

        let outcome = transport.transmit(&command);

        assert!(matches!(
            outcome,
            Ok(TransportOutcome::Response(answer))
                if answer.is_ok() && answer.body == vec![SYNTHETIC_DATA_ONE]
        ));
        assert_eq!(transport.exchange.public_count, 2);
        assert_script_complete(&transport);
    }

    #[test]
    fn leaves_unapproved_wrong_le_terminal() {
        let command = CommandApdu::case_2(header(), SYNTHETIC_LE);
        let exchange = ScriptedExchange::new(vec![ScriptStep {
            path: ExpectedPath::Public,
            expected: command.as_bytes().to_vec(),
            outcome: response(&[], SW1_WRONG_LE, CORRECTED_LE),
        }]);
        let mut transport = AndroidCardTransport::new(exchange, CardExchangeLevel::T0Tpdu);

        let outcome = transport.transmit(&command);

        assert!(matches!(
            outcome,
            Ok(TransportOutcome::Response(answer))
                if answer.sw1 == SW1_WRONG_LE && answer.sw2 == CORRECTED_LE
        ));
        assert_eq!(transport.exchange.public_count, 1);
        assert_script_complete(&transport);
    }

    #[test]
    fn credential_case_4_is_sent_once_then_continued_publicly() -> Result<(), CredentialBodyError> {
        let credential = CredentialCommand::from_protected_parts(
            CommandHeader {
                class: ApduClass::SecureMessaging,
                instruction: VERIFY_INSTRUCTION,
                p1: SYNTHETIC_PARAMETER_ONE,
                p2: SYNTHETIC_PARAMETER_TWO,
            },
            &[SYNTHETIC_DATA_ONE, SYNTHETIC_DATA_TWO],
            0,
        )?;
        let expected_credential = vec![
            ApduClass::SecureMessaging.as_byte(),
            VERIFY_INSTRUCTION,
            SYNTHETIC_PARAMETER_ONE,
            SYNTHETIC_PARAMETER_TWO,
            2,
            SYNTHETIC_DATA_ONE,
            SYNTHETIC_DATA_TWO,
        ];
        let get_response = GetResponse {
            class: ApduClass::Plain,
            le: 1,
        }
        .into_apdu();
        let exchange = ScriptedExchange::new(vec![
            ScriptStep {
                path: ExpectedPath::Credential,
                expected: expected_credential,
                outcome: response(&[], SW1_BYTES_AVAILABLE, 1),
            },
            ScriptStep {
                path: ExpectedPath::Public,
                expected: get_response.as_bytes().to_vec(),
                outcome: response(&[SYNTHETIC_DATA_ONE], SW1_SUCCESS, SW2_SUCCESS),
            },
        ]);
        let mut transport = AndroidCardTransport::new(exchange, CardExchangeLevel::T0Tpdu);

        let outcome = transport.transmit_credential(credential);

        assert!(matches!(
            outcome,
            Ok(TransportOutcome::Response(answer))
                if answer.is_ok() && answer.body == vec![SYNTHETIC_DATA_ONE]
        ));
        assert_eq!(transport.exchange.credential_count, 1);
        assert_eq!(transport.exchange.public_count, 1);
        assert_script_complete(&transport);
        Ok(())
    }

    #[test]
    fn credential_wrong_le_is_terminal_without_replay() -> Result<(), CredentialBodyError> {
        let credential = CredentialCommand::from_protected_parts(
            CommandHeader {
                class: ApduClass::SecureMessaging,
                instruction: VERIFY_INSTRUCTION,
                p1: SYNTHETIC_PARAMETER_ONE,
                p2: SYNTHETIC_PARAMETER_TWO,
            },
            &[SYNTHETIC_DATA_ONE],
            0,
        )?;
        let expected = vec![
            ApduClass::SecureMessaging.as_byte(),
            VERIFY_INSTRUCTION,
            SYNTHETIC_PARAMETER_ONE,
            SYNTHETIC_PARAMETER_TWO,
            1,
            SYNTHETIC_DATA_ONE,
        ];
        let exchange = ScriptedExchange::new(vec![ScriptStep {
            path: ExpectedPath::Credential,
            expected,
            outcome: response(&[], SW1_WRONG_LE, CORRECTED_LE),
        }]);
        let mut transport = AndroidCardTransport::new(exchange, CardExchangeLevel::T0Tpdu);

        let outcome = transport.transmit_credential(credential);

        assert!(matches!(
            outcome,
            Ok(TransportOutcome::Response(answer))
                if answer.sw1 == SW1_WRONG_LE && answer.sw2 == CORRECTED_LE
        ));
        assert_eq!(transport.exchange.credential_count, 1);
        assert_eq!(transport.exchange.public_count, 0);
        assert_script_complete(&transport);
        Ok(())
    }

    #[test]
    fn malformed_short_response_is_protocol_desync() {
        let command = CommandApdu::case_1(header());
        let exchange = ScriptedExchange::new(vec![ScriptStep {
            path: ExpectedPath::Public,
            expected: command.as_bytes().to_vec(),
            outcome: SingleExchangeOutcome::Response(vec![SW1_SUCCESS]),
        }]);
        let mut transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);

        let outcome = transport.transmit(&command);

        assert!(matches!(outcome, Ok(TransportOutcome::ProtocolDesync)));
        assert_script_complete(&transport);
    }

    #[test]
    fn response_chain_requires_progress() {
        let command = CommandApdu::case_1(header());
        let get_response = GetResponse {
            class: ApduClass::Plain,
            le: 1,
        }
        .into_apdu();
        let exchange = ScriptedExchange::new(vec![
            ScriptStep {
                path: ExpectedPath::Public,
                expected: command.as_bytes().to_vec(),
                outcome: response(&[], SW1_BYTES_AVAILABLE, 1),
            },
            ScriptStep {
                path: ExpectedPath::Public,
                expected: get_response.as_bytes().to_vec(),
                outcome: response(&[], SW1_BYTES_AVAILABLE, 1),
            },
        ]);
        let mut transport = AndroidCardTransport::new(exchange, CardExchangeLevel::T0Tpdu);

        let outcome = transport.transmit(&command);

        assert_eq!(outcome, Err(AndroidTransportError::ChainStalled));
        assert_script_complete(&transport);
    }

    #[test]
    fn transport_fault_is_preserved() {
        let command = CommandApdu::case_1(header());
        let exchange = ScriptedExchange::new(vec![ScriptStep {
            path: ExpectedPath::Public,
            expected: command.as_bytes().to_vec(),
            outcome: SingleExchangeOutcome::ReaderRemoved,
        }]);
        let mut transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);

        let outcome = transport.transmit(&command);

        assert!(matches!(outcome, Ok(TransportOutcome::ReaderRemoved)));
        assert_script_complete(&transport);
    }
}
