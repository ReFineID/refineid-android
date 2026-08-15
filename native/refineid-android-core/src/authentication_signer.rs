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

//! One-shot PIN1 verification and authentication-key signing.
//!
//! The input message is hashed in this boundary, then the counter-safe PIN1
//! preflight, the single credential transmission, and the MSE/PSO signing
//! chain run without releasing the card transport. The entered PIN is
//! reconstructed into the public core's non-clonable role type and consumed
//! by exactly one credential command.

use refineid_apdu::{CardTransport, TransportOutcome};
use refineid_auth::{Pin1, PinOps, PinReferenceScheme, UnvalidatedSecret, VerifyOutcome};
use refineid_digest::{Sha256, Sha384};
use refineid_sign::{KeyRef, SignError, SignOps, SignScheme};

use crate::pin1_status::{Pin1PreflightFailure, Pin1State, map_auth_error, probe_pin1_preflight};

/// Browser-facing authentication-signature algorithms supported by the
/// reviewed card core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticationSigningAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256 and an RSA-3072 authentication key.
    RsaPkcs1Sha256,
    /// RSASSA-PSS with SHA-256 and an RSA-3072 authentication key.
    RsaPssSha256,
    /// ECDSA with SHA-256 and a P-384 authentication key.
    EcdsaP384Sha256,
    /// ECDSA with SHA-384 and a P-384 authentication key.
    EcdsaP384Sha384,
}

/// Locally shaped signature returned by the card.
pub(crate) struct AuthenticationSignature {
    /// Algorithm that produced the bytes.
    pub(crate) algorithm: AuthenticationSigningAlgorithm,
    /// RSA modulus-wide bytes or raw ECDSA `r || s`.
    pub(crate) bytes: Vec<u8>,
}

impl core::fmt::Debug for AuthenticationSignature {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticationSignature")
            .field("algorithm", &self.algorithm)
            .field("length", &self.bytes.len())
            .finish()
    }
}

impl Drop for AuthenticationSignature {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Coarse one-shot failures safe to encode across JNI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticationSignFailure {
    /// The submitted PIN1 did not satisfy its local digit predicate.
    InvalidPin,
    /// The live counter state did not permit a consumer authentication try.
    SafetyRefused,
    /// PIN1 is blocked or became exhausted on this attempt.
    PinLocked,
    /// The card rejected the submitted PIN1 without exhausting it.
    WrongPin,
    /// VERIFY returned a status outside the reviewed outcome vocabulary.
    VerificationRejected,
    /// The card rejected or malformed the signing chain.
    SigningRejected,
    /// Card or reader disappeared from the slot.
    CardUnavailable,
    /// Transport state became unusable or indeterminate.
    Transport,
    /// An impossible local shape reached the bridge.
    Bridge,
}

/// Present one fresh PIN1 exactly once and sign one owned request message.
///
/// FINEID S1 v4.2 sections 3.5, 3.6, 3.7.2.3, and 3.8 govern the sequence:
/// header-only VERIFY preflight, credential VERIFY, MSE:SET DST, PSO:HASH,
/// and PSO:COMPUTE DIGITAL SIGNATURE. No operation may interleave after the
/// hash has been loaded.
pub(crate) fn authenticate_and_sign<T>(
    transport: &mut T,
    algorithm: AuthenticationSigningAlgorithm,
    pin_bytes: Vec<u8>,
    message: &[u8],
) -> Result<AuthenticationSignature, AuthenticationSignFailure>
where
    T: CardTransport,
{
    let pin = Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(pin_bytes))
        .map_err(|_| AuthenticationSignFailure::InvalidPin)?;
    let preflight = probe_pin1_preflight(transport).map_err(map_preflight_failure)?;
    if !preflight.consumer_authentication_permitted {
        return Err(match preflight.state {
            Pin1State::Locked => AuthenticationSignFailure::PinLocked,
            Pin1State::Verified
            | Pin1State::Remaining(_)
            | Pin1State::NoInformation
            | Pin1State::Unrecognised => AuthenticationSignFailure::SafetyRefused,
        });
    }

    let outcome = transport
        .verify_pin1_with_scheme(preflight.scheme, pin)
        .map_err(|error| map_preflight_failure(map_auth_error(error)))?;
    match outcome {
        VerifyOutcome::Ok => {}
        VerifyOutcome::WrongPin { retries_left } if retries_left.is_exhausted() => {
            return Err(AuthenticationSignFailure::PinLocked);
        }
        VerifyOutcome::WrongPin { .. } => return Err(AuthenticationSignFailure::WrongPin),
        VerifyOutcome::Locked => return Err(AuthenticationSignFailure::PinLocked),
        VerifyOutcome::Other(_) => {
            return Err(AuthenticationSignFailure::VerificationRejected);
        }
    }

    let scheme = sign_scheme(preflight.scheme);
    let bytes = sign_message(transport, scheme, algorithm, message).map_err(map_sign_error)?;
    Ok(AuthenticationSignature { algorithm, bytes })
}

fn sign_scheme(scheme: PinReferenceScheme) -> SignScheme {
    match scheme {
        PinReferenceScheme::Citizen => SignScheme::Citizen,
        PinReferenceScheme::Organizational => SignScheme::Organizational,
    }
}

fn sign_message<T>(
    transport: &mut T,
    scheme: SignScheme,
    algorithm: AuthenticationSigningAlgorithm,
    message: &[u8],
) -> Result<Vec<u8>, SignError<T::Error>>
where
    T: CardTransport,
{
    match algorithm {
        AuthenticationSigningAlgorithm::RsaPkcs1Sha256 => transport
            .sign_prehashed_sha256_rsa(scheme, KeyRef::Auth, Sha256::of(message).into_bytes())
            .map(|signature| signature.into_bytes()),
        AuthenticationSigningAlgorithm::RsaPssSha256 => transport
            .sign_prehashed_sha256_rsa_pss(scheme, KeyRef::Auth, Sha256::of(message).into_bytes())
            .map(|signature| signature.into_bytes()),
        AuthenticationSigningAlgorithm::EcdsaP384Sha256 => transport
            .sign_prehashed_sha256_ecdsa(scheme, KeyRef::Auth, Sha256::of(message).into_bytes())
            .map(|signature| signature.into_bytes()),
        AuthenticationSigningAlgorithm::EcdsaP384Sha384 => transport
            .sign_prehashed_sha384_ecdsa(scheme, KeyRef::Auth, Sha384::of(message).into_bytes())
            .map(|signature| signature.into_bytes()),
    }
}

fn map_preflight_failure(failure: Pin1PreflightFailure) -> AuthenticationSignFailure {
    match failure {
        Pin1PreflightFailure::CardUnavailable => AuthenticationSignFailure::CardUnavailable,
        Pin1PreflightFailure::Transport => AuthenticationSignFailure::Transport,
        Pin1PreflightFailure::Bridge => AuthenticationSignFailure::Bridge,
    }
}

fn map_sign_error<E>(error: SignError<E>) -> AuthenticationSignFailure {
    match error {
        SignError::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            AuthenticationSignFailure::CardUnavailable
        }
        SignError::Transport(_)
        | SignError::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => AuthenticationSignFailure::Transport,
        SignError::Status(_, _) | SignError::UnexpectedSignatureLength { .. } => {
            AuthenticationSignFailure::SigningRejected
        }
        SignError::Outcome(TransportOutcome::Response(_)) | SignError::Command(_) => {
            AuthenticationSignFailure::Bridge
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use refineid_apdu::{
        CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
        TransportOutcome,
    };
    use refineid_sign::{ECDSA_P384_SIG_BYTES, RSA_3072_SIG_BYTES};

    use super::{AuthenticationSignFailure, AuthenticationSigningAlgorithm, authenticate_and_sign};

    const SAFE_RETRIES: u8 = 3;
    const LOW_RETRIES: u8 = 2;
    const PUBLIC_VERIFY_CALLS: usize = 2;
    const FULL_RSA_PUBLIC_CALLS: usize = 5;
    const VERIFY_INSTRUCTION: u8 = 0x20;
    const INSTRUCTION_OFFSET: usize = 1;
    const SYNTHETIC_PIN: &[u8] = b"1357";
    const SYNTHETIC_MESSAGE: &[u8] = b"authentication request";
    const SIGNATURE_FILL: u8 = 0xA5;

    struct ScriptedTransport {
        public_responses: VecDeque<TransportOutcome>,
        credential_response: TransportOutcome,
        public_calls: usize,
        credential_calls: usize,
    }

    impl ScriptedTransport {
        fn new(public_responses: Vec<TransportOutcome>, credential_status: StatusWord) -> Self {
            Self {
                public_responses: public_responses.into(),
                credential_response: response(credential_status, Vec::new()),
                public_calls: 0,
                credential_calls: 0,
            }
        }
    }

    impl CardTransport for ScriptedTransport {
        type Error = &'static str;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            self.public_calls += 1;
            if self.public_calls <= PUBLIC_VERIFY_CALLS {
                assert_eq!(
                    command.as_bytes().get(INSTRUCTION_OFFSET).copied(),
                    Some(VERIFY_INSTRUCTION)
                );
            }
            self.public_responses
                .pop_front()
                .ok_or("missing public response")
        }

        fn transmit_credential(
            &mut self,
            command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            self.credential_calls += 1;
            command.expose_wire(|wire| {
                assert_eq!(
                    wire.get(INSTRUCTION_OFFSET).copied(),
                    Some(VERIFY_INSTRUCTION)
                );
            });
            Ok(self.credential_response.clone())
        }
    }

    fn retries(value: u8) -> PinRetries {
        PinRetries::from_nibble(value).expect("synthetic retry count fits")
    }

    fn status(retry_count: u8) -> StatusWord {
        StatusWord::PinIncorrect {
            retries: retries(retry_count),
        }
    }

    fn response(status: StatusWord, body: Vec<u8>) -> TransportOutcome {
        let [sw1, sw2] = status.as_u16().to_be_bytes();
        TransportOutcome::Response(ResponseApdu { body, sw1, sw2 })
    }

    fn rsa_success_script() -> ScriptedTransport {
        let safe = response(status(SAFE_RETRIES), Vec::new());
        ScriptedTransport::new(
            vec![
                safe.clone(),
                safe,
                response(StatusWord::Success, Vec::new()),
                response(StatusWord::Success, Vec::new()),
                response(
                    StatusWord::Success,
                    vec![SIGNATURE_FILL; RSA_3072_SIG_BYTES],
                ),
            ],
            StatusWord::Success,
        )
    }

    #[test]
    fn one_submission_drives_one_verify_then_one_signature_chain() {
        let mut transport = rsa_success_script();

        let result = authenticate_and_sign(
            &mut transport,
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            SYNTHETIC_PIN.to_vec(),
            SYNTHETIC_MESSAGE,
        )
        .expect("scripted authentication signature succeeds");

        assert_eq!(result.bytes.len(), RSA_3072_SIG_BYTES);
        assert_eq!(transport.credential_calls, 1);
        assert_eq!(transport.public_calls, FULL_RSA_PUBLIC_CALLS);
        assert!(transport.public_responses.is_empty());
    }

    #[test]
    fn an_invalid_submission_never_touches_the_card() {
        let mut transport = rsa_success_script();

        let result = authenticate_and_sign(
            &mut transport,
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            Vec::new(),
            SYNTHETIC_MESSAGE,
        );

        assert!(matches!(result, Err(AuthenticationSignFailure::InvalidPin)));
        assert_eq!(transport.public_calls, 0);
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn the_retry_floor_refuses_before_the_credential_path() {
        let low = response(status(LOW_RETRIES), Vec::new());
        let mut transport = ScriptedTransport::new(vec![low.clone(), low], StatusWord::Success);

        let result = authenticate_and_sign(
            &mut transport,
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            SYNTHETIC_PIN.to_vec(),
            SYNTHETIC_MESSAGE,
        );

        assert!(matches!(
            result,
            Err(AuthenticationSignFailure::SafetyRefused)
        ));
        assert_eq!(transport.public_calls, PUBLIC_VERIFY_CALLS);
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn a_wrong_pin_stops_before_mse_and_is_never_replayed() {
        let safe = response(status(SAFE_RETRIES), Vec::new());
        let mut transport = ScriptedTransport::new(vec![safe.clone(), safe], status(LOW_RETRIES));

        let result = authenticate_and_sign(
            &mut transport,
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            SYNTHETIC_PIN.to_vec(),
            SYNTHETIC_MESSAGE,
        );

        assert!(matches!(result, Err(AuthenticationSignFailure::WrongPin)));
        assert_eq!(transport.public_calls, PUBLIC_VERIFY_CALLS);
        assert_eq!(transport.credential_calls, 1);
    }

    #[test]
    fn every_algorithm_has_a_fixed_signature_shape() {
        for (algorithm, signature_length) in [
            (
                AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
                RSA_3072_SIG_BYTES,
            ),
            (
                AuthenticationSigningAlgorithm::RsaPssSha256,
                RSA_3072_SIG_BYTES,
            ),
            (
                AuthenticationSigningAlgorithm::EcdsaP384Sha256,
                ECDSA_P384_SIG_BYTES,
            ),
            (
                AuthenticationSigningAlgorithm::EcdsaP384Sha384,
                ECDSA_P384_SIG_BYTES,
            ),
        ] {
            let safe = response(status(SAFE_RETRIES), Vec::new());
            let mut transport = ScriptedTransport::new(
                vec![
                    safe.clone(),
                    safe,
                    response(StatusWord::Success, Vec::new()),
                    response(StatusWord::Success, Vec::new()),
                    response(StatusWord::Success, vec![SIGNATURE_FILL; signature_length]),
                ],
                StatusWord::Success,
            );

            let result = authenticate_and_sign(
                &mut transport,
                algorithm,
                SYNTHETIC_PIN.to_vec(),
                SYNTHETIC_MESSAGE,
            )
            .expect("scripted algorithm succeeds");
            assert_eq!(result.algorithm, algorithm);
            assert_eq!(result.bytes.len(), signature_length);
            assert_eq!(transport.credential_calls, 1);
        }
    }
}
