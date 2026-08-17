package fi.refineid.android.nfc

import android.nfc.tech.IsoDep
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSignatureVerifier
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeAuthenticationSignFailure
import fi.refineid.android.core.NativeAuthenticationSignResult
import fi.refineid.android.core.NativeCardSessionMaterial
import fi.refineid.android.core.NativeContactlessCore
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.diagnostics.AppTrace
import java.io.IOException

/**
 * One holder-opened contactless card session, confined to the probe
 * worker thread. The session retains the resting tag handle, the CAN
 * for its lifetime only, and the cached public material; every card
 * operation reconnects ISO-DEP and re-runs PACE natively.
 */
internal class ContactlessSession(
    private var isoDep: IsoDep,
    private val can: ByteArray,
    private val material: NativeCardSessionMaterial,
) : AutoCloseable {
    private val ownerThread = Thread.currentThread()
    private var isClosed = false

    /**
     * Replace the tag handle after the stack re-polled the resting
     * card; the previous handle is dead once the field cycled.
     */
    fun adopt(freshIsoDep: IsoDep) {
        checkOwnerThread()
        check(!isClosed) {
            "contactless session is closed"
        }
        try {
            isoDep.close()
        } catch (_: IOException) {
            // The replaced handle is expected to be gone already.
        }
        isoDep = freshIsoDep
    }

    fun copyAuthenticationCertificate(): NativeAuthenticationCertificate {
        checkOwnerThread()
        check(!isClosed) {
            "contactless session is closed"
        }
        return material.copyAuthenticationCertificate()
    }

    fun authenticateAndSignInput(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
    ): AuthenticationSignResult {
        checkOwnerThread()
        check(!isClosed) {
            "contactless session is closed"
        }
        val certificate = material.requireAuthenticationCertificate()
        if (certificate.keyProfile != algorithm.keyProfile) {
            pin1.close()
            return AuthenticationSignResult.Failure(
                AuthenticationSignFailure.KEY_PROFILE_MISMATCH,
            )
        }
        try {
            if (!isoDep.isConnected) {
                isoDep.connect()
                isoDep.timeout = TRANSCEIVE_TIMEOUT_MILLISECONDS
            }
        } catch (_: IOException) {
            pin1.close()
            AppTrace.nfcSessionOpenFailed()
            return AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)
        }
        val nativeResult =
            NativeContactlessCore.authenticateAndSign(
                canCopy = can.copyOf(),
                algorithm = algorithm,
                inputMode = inputMode,
                pin1 = pin1,
                input = input,
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        try {
            isoDep.close()
        } catch (_: IOException) {
            // The tag may already be gone; the signing result stands.
        }
        AppTrace.nfcSessionClosed()
        return when (nativeResult) {
            is NativeAuthenticationSignResult.Success -> {
                val isVerified =
                    when (inputMode) {
                        AuthenticationSigningInputMode.MESSAGE -> {
                            AuthenticationSignatureVerifier.verify(
                                certificate = certificate,
                                message = input,
                                signature = nativeResult.signature,
                            )
                        }

                        AuthenticationSigningInputMode.PREHASHED -> {
                            AuthenticationSignatureVerifier.verifyPrehashed(
                                certificate = certificate,
                                digest = input,
                                signature = nativeResult.signature,
                            )
                        }
                    }
                AppTrace.authenticationSignatureVerificationCompleted(
                    inputMode = inputMode,
                    isVerified = isVerified,
                )
                if (isVerified) {
                    AuthenticationSignResult.Success(nativeResult.signature)
                } else {
                    nativeResult.signature.close()
                    AuthenticationSignResult.Failure(
                        AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED,
                    )
                }
            }

            is NativeAuthenticationSignResult.Failure -> {
                AuthenticationSignResult.Failure(nativeResult.kind.toContactlessFailure())
            }
        }
    }

    override fun close() {
        checkOwnerThread()
        if (isClosed) {
            return
        }
        isClosed = true
        can.fill(0)
        material.close()
        try {
            isoDep.close()
        } catch (_: IOException) {
            // Closing a lost tag is a no-op.
        }
    }

    override fun toString(): String = "ContactlessSession(closed=" + isClosed + ")"

    private fun checkOwnerThread() {
        check(Thread.currentThread() === ownerThread) {
            "contactless session used from a different thread"
        }
    }

    private companion object {
        /** Bound on one contactless exchange, PACE cryptography included. */
        const val TRANSCEIVE_TIMEOUT_MILLISECONDS = 4_000
    }
}

private fun NativeAuthenticationSignFailure.toContactlessFailure(): AuthenticationSignFailure =
    when (this) {
        NativeAuthenticationSignFailure.CARD_UNAVAILABLE -> {
            AuthenticationSignFailure.CARD_UNAVAILABLE
        }

        NativeAuthenticationSignFailure.TRANSPORT_ERROR -> {
            AuthenticationSignFailure.TRANSPORT_ERROR
        }

        NativeAuthenticationSignFailure.INVALID_PIN -> {
            AuthenticationSignFailure.INVALID_PIN
        }

        NativeAuthenticationSignFailure.SAFETY_REFUSED -> {
            AuthenticationSignFailure.SAFETY_REFUSED
        }

        NativeAuthenticationSignFailure.PIN_LOCKED -> {
            AuthenticationSignFailure.PIN_LOCKED
        }

        NativeAuthenticationSignFailure.WRONG_PIN -> {
            AuthenticationSignFailure.WRONG_PIN
        }

        NativeAuthenticationSignFailure.VERIFICATION_REJECTED -> {
            AuthenticationSignFailure.VERIFICATION_REJECTED
        }

        NativeAuthenticationSignFailure.SIGNING_REJECTED -> {
            AuthenticationSignFailure.SIGNING_REJECTED
        }

        // The session CAN was proven at connect; a later channel refusal
        // is a transport anomaly, not a holder-facing CAN outcome.
        NativeAuthenticationSignFailure.PACE_REJECTED -> {
            AuthenticationSignFailure.TRANSPORT_ERROR
        }

        NativeAuthenticationSignFailure.BRIDGE_ERROR -> {
            AuthenticationSignFailure.BRIDGE_ERROR
        }
    }
