// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `EF.CardAccess` recognition for the contactless border.
//!
//! `EF.CardAccess` (file identifier `011C`) sits directly under the MF
//! and is readable without PACE or secure messaging -- that is its
//! purpose: a terminal cannot run PACE until the card has advertised
//! which protocol variants and domain parameters it supports
//! (ICAO 9303-11 section 9.2, BSI TR-03110-3 appendix A.1.1.4).
//!
//! This module reads and parses that public file so Android can report
//! whether a discovered contactless card advertises the FINEID S4-2
//! published PACE profile. It establishes no secure channel and sends
//! no credential; PACE itself is a later slice.

use refineid_apdu::{FileId, TransportOutcome};
use refineid_ber::{BerTlv, BerTlvIter, Integer, Oid, Sequence, Set};
use refineid_pkcs15::{Pkcs15Error, Pkcs15Ops};

use crate::card_transport::{AndroidCardTransport, AndroidTransportError, SingleBlockExchange};

/// File identifier of `EF.CardAccess` under the MF
/// (ICAO 9303-11 section 9.2.11).
const EF_CARD_ACCESS_FID: FileId = FileId::from_u16(0x011C);

/// `PACEInfo` version mandated for the v2 protocol family
/// (BSI TR-03110-3 appendix A.1.1.1).
const PACE_VERSION_2: u32 = 2;

/// FINEID's published `parameterId` for brainpoolP384r1: `0x10` by
/// empirical agreement with the shipped readers (FINEID S4-2).
const FINEID_BRAINPOOL_P384_PARAMETER_ID: u32 = 0x10;

/// A PACE protocol variant this implementation recognizes, identified
/// by its `protocol` OID (BSI TR-03110-3 appendix A.1.1.1,
/// `0.4.0.127.0.7.2.2.4.{2,6}.{n}`).
///
/// The set is closed: [`PaceProtocol::from_oid`] returns `None` for any
/// other OID and the parser never retains unrecognized protocol bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaceProtocol {
    /// `id-PACE-ECDH-GM-AES-CBC-CMAC-128`.
    EcdhGmAesCbcCmac128,
    /// `id-PACE-ECDH-GM-AES-CBC-CMAC-192`.
    EcdhGmAesCbcCmac192,
    /// `id-PACE-ECDH-GM-AES-CBC-CMAC-256` (the FINEID S4-2 published
    /// variant).
    EcdhGmAesCbcCmac256,
    /// `id-PACE-ECDH-CAM-AES-CBC-CMAC-128`.
    EcdhCamAesCbcCmac128,
    /// `id-PACE-ECDH-CAM-AES-CBC-CMAC-256`.
    EcdhCamAesCbcCmac256,
}

impl PaceProtocol {
    /// Recognize a PACE protocol from its OID value bytes (no tag, no
    /// length). `None` for any OID outside the supported set.
    ///
    /// The mapping arc is 2 for ECDH-GM and 6 for ECDH-CAM; 4 is
    /// ECDH-IM, which is not supported (BSI TR-03110-3 appendix
    /// A.1.1.1). A production FINEID card advertises both GM-256 and
    /// CAM-256.
    fn from_oid(oid: &[u8]) -> Option<Self> {
        match oid {
            [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02] => {
                Some(Self::EcdhGmAesCbcCmac128)
            }
            [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x03] => {
                Some(Self::EcdhGmAesCbcCmac192)
            }
            [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04] => {
                Some(Self::EcdhGmAesCbcCmac256)
            }
            [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x02] => {
                Some(Self::EcdhCamAesCbcCmac128)
            }
            [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x04] => {
                Some(Self::EcdhCamAesCbcCmac256)
            }
            _ => None,
        }
    }
}

/// One `PACEInfo` entry: `PACEInfo ::= SEQUENCE { protocol OID,
/// version INTEGER, parameterId INTEGER OPTIONAL }` (ICAO 9303-11
/// section 9.2, BSI TR-03110-3 appendix A.1.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PaceSecurityInfo {
    /// The recognized PACE protocol variant.
    protocol: PaceProtocol,
    /// Protocol version; `2` for the v2 family.
    version: u32,
    /// `parameterId` referencing the curve or group; `None` when the
    /// OPTIONAL field is omitted.
    parameter_id: Option<u32>,
}

impl PaceSecurityInfo {
    /// Whether this entry is the FINEID S4-2 published profile:
    /// PACE-ECDH-GM with AES-CBC-CMAC-256, protocol version 2, on
    /// brainpoolP384r1 (FINEID `parameterId` `0x10`).
    fn is_published_profile(&self) -> bool {
        self.protocol == PaceProtocol::EcdhGmAesCbcCmac256
            && self.version == PACE_VERSION_2
            && self.parameter_id == Some(FINEID_BRAINPOOL_P384_PARAMETER_ID)
    }

    /// Decode one `SecurityInfo` SEQUENCE body. An OID outside the
    /// recognized PACE set is [`CardAccessParseError::UnsupportedProtocol`],
    /// which the caller skips without retaining a byte; spec-legal
    /// siblings such as `ChipAuthenticationInfo` share the SET
    /// (ICAO 9303-11 section 9.2).
    fn parse(body: &[u8]) -> Result<Self, CardAccessParseError> {
        let mut fields = BerTlvIter::new(body);
        let oid = fields
            .next()
            .ok_or(CardAccessParseError::IncompletePaceInfo)?
            .map_err(|_| CardAccessParseError::MalformedSecurityInfo)?
            .expect::<Oid>()
            .map_err(|_| CardAccessParseError::MalformedSecurityInfo)?;
        let protocol =
            PaceProtocol::from_oid(oid.value()).ok_or(CardAccessParseError::UnsupportedProtocol)?;
        let version = fields
            .next()
            .ok_or(CardAccessParseError::IncompletePaceInfo)?
            .map_err(|_| CardAccessParseError::MalformedSecurityInfo)?
            .expect::<Integer>()
            .map_err(|_| CardAccessParseError::MalformedSecurityInfo)?;
        let parameter_id = fields
            .next()
            .and_then(Result::ok)
            .and_then(|any| any.expect::<Integer>().ok())
            .map(|tlv| u32_from_be(tlv.value()));
        Ok(Self {
            protocol,
            version: u32_from_be(version.value()),
            parameter_id,
        })
    }
}

/// Why an `EF.CardAccess` blob failed to decode as a
/// `SET OF SecurityInfo` per ICAO 9303-11 section 9.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardAccessParseError {
    /// The outer TLV is neither a SET nor a SEQUENCE, or is itself
    /// malformed BER.
    NotSetOrSequence,
    /// A well-formed leading TLV is followed by undeclared trailing
    /// bytes; a valid file is a single outer TLV that fills the file.
    TrailingBytes,
    /// A `SecurityInfo` entry was malformed BER.
    MalformedSecurityInfo,
    /// A required `PACEInfo` field (`protocol` OID or `version`) was
    /// absent.
    IncompletePaceInfo,
    /// No entry advertised a recognized PACE protocol; the card offers
    /// nothing this implementation can run.
    UnsupportedProtocol,
}

/// Every recognized `PACEInfo` entry from a card's `EF.CardAccess`.
#[derive(Debug, Clone)]
struct CardAccess {
    /// Recognized entries in the order they appear in the SET.
    security_infos: Vec<PaceSecurityInfo>,
}

impl CardAccess {
    /// Validating constructor: parse raw `EF.CardAccess` bytes. This is
    /// the trust boundary; construction and validation are one step.
    ///
    /// The spec says SET OF, but some cards write SEQUENCE OF; both are
    /// accepted because the child value bytes are identical. The outer
    /// TLV must consume the whole input, entries with unrecognized
    /// protocol OIDs are skipped without retention, and a file with no
    /// recognized entry fails loudly instead of parsing empty.
    fn parse(der: &[u8]) -> Result<Self, CardAccessParseError> {
        let (outer_size, outer_value) = if let Ok(outer) = BerTlv::<Set>::parse(der) {
            (outer.size(), outer.value())
        } else {
            let outer = BerTlv::<Sequence>::parse(der)
                .map_err(|_| CardAccessParseError::NotSetOrSequence)?;
            (outer.size(), outer.value())
        };
        if outer_size != der.len() {
            return Err(CardAccessParseError::TrailingBytes);
        }
        let mut security_infos = Vec::new();
        for entry in BerTlvIter::new(outer_value) {
            let entry = entry
                .map_err(|_| CardAccessParseError::MalformedSecurityInfo)?
                .expect::<Sequence>()
                .map_err(|_| CardAccessParseError::MalformedSecurityInfo)?;
            match PaceSecurityInfo::parse(entry.value()) {
                Ok(info) => security_infos.push(info),
                Err(CardAccessParseError::UnsupportedProtocol) => {}
                Err(error) => return Err(error),
            }
        }
        if security_infos.is_empty() {
            return Err(CardAccessParseError::UnsupportedProtocol);
        }
        Ok(Self { security_infos })
    }

    /// The typed summary that crosses JNI; no OID or entry bytes leave
    /// the native side.
    fn summary(&self) -> CardAccessSummary {
        CardAccessSummary {
            supports_published_profile: self
                .security_infos
                .iter()
                .any(PaceSecurityInfo::is_published_profile),
            pace_entry_count: u8::try_from(self.security_infos.len()).unwrap_or(u8::MAX),
        }
    }
}

/// Coarse typed outcome of one contactless `EF.CardAccess` probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CardAccessSummary {
    /// Whether any entry is the FINEID S4-2 published PACE profile.
    pub(crate) supports_published_profile: bool,
    /// Number of recognized `PACEInfo` entries, saturated at 255.
    pub(crate) pace_entry_count: u8,
}

/// Failure vocabulary for the contactless card-access probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardAccessProbeFailure {
    /// Card left the field or was never present.
    CardUnavailable,
    /// The card rejected a select or read with a status word.
    Rejected,
    /// The exchange failed or left the card state uncertain.
    Transport,
    /// The file was empty, oversized, malformed, or advertised no
    /// recognized PACE protocol.
    Invalid,
    /// Android-side bridge failure.
    Bridge,
}

/// Read and parse `EF.CardAccess` over a plain (pre-PACE) transport:
/// select the MF, select file `011C`, and read one bounded DER object.
pub(crate) fn probe_card_access<Exchange: SingleBlockExchange>(
    transport: &mut AndroidCardTransport<Exchange>,
) -> Result<CardAccessSummary, CardAccessProbeFailure> {
    transport.select_mf().map_err(map_pkcs15_error)?;
    transport
        .select_ef(EF_CARD_ACCESS_FID)
        .map_err(map_pkcs15_error)?;
    let bytes = transport
        .read_binary_der_object("EF.CardAccess")
        .map_err(map_pkcs15_error)?;
    let card_access = CardAccess::parse(&bytes).map_err(|_| CardAccessProbeFailure::Invalid)?;
    Ok(card_access.summary())
}

fn map_pkcs15_error(error: Pkcs15Error<AndroidTransportError>) -> CardAccessProbeFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            CardAccessProbeFailure::CardUnavailable
        }
        Pkcs15Error::Status(_) => CardAccessProbeFailure::Rejected,
        Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => CardAccessProbeFailure::Transport,
        Pkcs15Error::Empty | Pkcs15Error::TooLarge | Pkcs15Error::InvalidData(_) => {
            CardAccessProbeFailure::Invalid
        }
        Pkcs15Error::Outcome(TransportOutcome::Response(_))
        | Pkcs15Error::Aid(_)
        | Pkcs15Error::Command(_) => CardAccessProbeFailure::Bridge,
    }
}

/// Big-endian byte slice to `u32`, keeping the low 32 bits when the
/// input is wider. Versions and parameter identifiers are single-byte
/// in every registered profile.
fn u32_from_be(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |value, &byte| (value << u8::BITS) | u32::from(byte))
}

#[cfg(test)]
mod tests {
    use refineid_apdu::{StatusWord, TransportOutcome};
    use refineid_pkcs15::Pkcs15Error;

    use super::{
        CardAccess, CardAccessParseError, CardAccessProbeFailure, PaceProtocol, map_pkcs15_error,
    };
    use crate::card_transport::AndroidTransportError;

    // BER universal-class tag bytes for the synthetic fixtures below.
    const TAG_OID: u8 = 0x06;
    const TAG_INTEGER: u8 = 0x02;
    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_SET: u8 = 0x31;

    // OID value bytes for `id-PACE-ECDH-GM-AES-CBC-CMAC-256`
    // (0.4.0.127.0.7.2.2.4.2.4), bare value without tag or length.
    const OID_PACE_ECDH_GM_AES_CBC_CMAC_256: [u8; 10] =
        [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04];
    // `PACEInfo` version mandated for the v2 family.
    const PACE_VERSION: u8 = 2;
    // FINEID's published `parameterId` alias for brainpoolP384r1.
    const FINEID_PACE_PARAMETER_ID: u8 = 0x10;
    // OID value bytes for 1.2.3.4 -- deliberately outside the
    // recognized PACE set.
    const UNSUPPORTED_PROTOCOL_OID: [u8; 3] = [0x2A, 0x03, 0x04];

    /// A production FINEID card's `EF.CardAccess`, captured over a
    /// contactless PC/SC reader (2026-07-24, mono-internal fixture):
    /// two `PACEInfo` entries, GM-256 and CAM-256, both v2 on
    /// parameter `0x10`. The bytes are public protocol parameters;
    /// nothing card- or person-identifying is in them.
    const PRODUCTION_CARD_ACCESS: [u8; 42] = [
        0x31, 0x28, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02,
        0x04, 0x02, 0x01, 0x02, 0x02, 0x01, 0x10, 0x30, 0x12, 0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00,
        0x07, 0x02, 0x02, 0x04, 0x06, 0x04, 0x02, 0x01, 0x02, 0x02, 0x01, 0x10,
    ];

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![
            tag,
            u8::try_from(value.len()).expect("test TLV fits a short length"),
        ];
        bytes.extend_from_slice(value);
        bytes
    }

    fn supported_pace_security_info() -> Vec<u8> {
        let mut body = tlv(TAG_OID, &OID_PACE_ECDH_GM_AES_CBC_CMAC_256);
        body.extend_from_slice(&tlv(TAG_INTEGER, &[PACE_VERSION]));
        body.extend_from_slice(&tlv(TAG_INTEGER, &[FINEID_PACE_PARAMETER_ID]));
        tlv(TAG_SEQUENCE, &body)
    }

    fn synthetic_pace_security_infos_set() -> Vec<u8> {
        tlv(TAG_SET, &supported_pace_security_info())
    }

    #[test]
    fn parses_published_profile_pace_info() {
        let set = synthetic_pace_security_infos_set();

        let card_access = CardAccess::parse(&set).expect("synthetic file parses");

        assert_eq!(card_access.security_infos.len(), 1);
        let info = &card_access.security_infos[0];
        assert_eq!(info.protocol, PaceProtocol::EcdhGmAesCbcCmac256);
        assert_eq!(info.version, u32::from(PACE_VERSION));
        assert_eq!(info.parameter_id, Some(u32::from(FINEID_PACE_PARAMETER_ID)));
        let summary = card_access.summary();
        assert!(summary.supports_published_profile);
        assert_eq!(summary.pace_entry_count, 1);
    }

    #[test]
    fn parses_production_fineid_card_access_capture() {
        let card_access =
            CardAccess::parse(&PRODUCTION_CARD_ACCESS).expect("real EF.CardAccess parses");

        assert_eq!(card_access.security_infos.len(), 2);
        assert_eq!(
            card_access.security_infos[0].protocol,
            PaceProtocol::EcdhGmAesCbcCmac256
        );
        assert_eq!(
            card_access.security_infos[1].protocol,
            PaceProtocol::EcdhCamAesCbcCmac256
        );
        let summary = card_access.summary();
        assert!(summary.supports_published_profile);
        assert_eq!(summary.pace_entry_count, 2);
    }

    #[test]
    fn gm_256_without_published_parameter_is_recognized_but_not_published() {
        let mut body = tlv(TAG_OID, &OID_PACE_ECDH_GM_AES_CBC_CMAC_256);
        body.extend_from_slice(&tlv(TAG_INTEGER, &[PACE_VERSION]));
        let set = tlv(TAG_SET, &tlv(TAG_SEQUENCE, &body));

        let summary = CardAccess::parse(&set).expect("entry parses").summary();

        assert!(!summary.supports_published_profile);
        assert_eq!(summary.pace_entry_count, 1);
    }

    #[test]
    fn unsupported_protocol_oid_is_rejected_not_retained() {
        let info = tlv(TAG_SEQUENCE, &tlv(TAG_OID, &UNSUPPORTED_PROTOCOL_OID));
        let set = tlv(TAG_SET, &info);

        assert_eq!(
            CardAccess::parse(&set).expect_err("unsupported protocol OID is rejected"),
            CardAccessParseError::UnsupportedProtocol,
        );
    }

    #[test]
    fn unsupported_sibling_is_skipped_without_retention() {
        let unsupported = tlv(TAG_SEQUENCE, &tlv(TAG_OID, &UNSUPPORTED_PROTOCOL_OID));
        let mut set_body = supported_pace_security_info();
        set_body.extend_from_slice(&unsupported);
        let set = tlv(TAG_SET, &set_body);

        let card_access = CardAccess::parse(&set).expect("supported entry keeps the file usable");

        assert_eq!(card_access.security_infos.len(), 1);
    }

    #[test]
    fn rejects_trailing_bytes_past_outer_tlv() {
        const TRAILING_GARBAGE_SENTINEL: u8 = 0xAA;
        let mut set = synthetic_pace_security_infos_set();
        set.push(TRAILING_GARBAGE_SENTINEL);

        assert_eq!(
            CardAccess::parse(&set).expect_err("trailing garbage is rejected"),
            CardAccessParseError::TrailingBytes,
        );
    }

    #[test]
    fn rejects_truncated_and_non_set_input() {
        assert_eq!(
            CardAccess::parse(&[]).expect_err("empty input is rejected"),
            CardAccessParseError::NotSetOrSequence,
        );
        assert_eq!(
            CardAccess::parse(&[TAG_INTEGER, 1, PACE_VERSION])
                .expect_err("a non-container outer tag is rejected"),
            CardAccessParseError::NotSetOrSequence,
        );
        let mut truncated = synthetic_pace_security_infos_set();
        let _removed = truncated.pop();
        assert_eq!(
            CardAccess::parse(&truncated).expect_err("a truncated file is rejected"),
            CardAccessParseError::NotSetOrSequence,
        );
    }

    #[test]
    fn rejects_incomplete_pace_info() {
        let info = tlv(
            TAG_SEQUENCE,
            &tlv(TAG_OID, &OID_PACE_ECDH_GM_AES_CBC_CMAC_256),
        );
        let set = tlv(TAG_SET, &info);

        assert_eq!(
            CardAccess::parse(&set).expect_err("a version-less PACEInfo is rejected"),
            CardAccessParseError::IncompletePaceInfo,
        );
    }

    #[test]
    fn maps_pkcs15_errors_onto_probe_failures() {
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Outcome(TransportOutcome::NoCard)),
            CardAccessProbeFailure::CardUnavailable
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Status(StatusWord::FileNotFound)),
            CardAccessProbeFailure::Rejected
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Transport(AndroidTransportError::Backend)),
            CardAccessProbeFailure::Transport
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::InvalidData("synthetic card access")),
            CardAccessProbeFailure::Invalid
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Empty),
            CardAccessProbeFailure::Invalid
        );
    }
}
