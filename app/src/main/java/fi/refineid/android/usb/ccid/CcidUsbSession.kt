package fi.refineid.android.usb.ccid

import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import fi.refineid.android.core.AtrValidation
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSignatureVerifier
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeAuthenticationCertificateReadFailure
import fi.refineid.android.core.NativeAuthenticationCertificateReadResult
import fi.refineid.android.core.NativeAuthenticationKeyProfile
import fi.refineid.android.core.NativeAuthenticationSignFailure
import fi.refineid.android.core.NativeAuthenticationSignResult
import fi.refineid.android.core.NativeCardExchangeLevel
import fi.refineid.android.core.NativeCardOperationResult
import fi.refineid.android.core.NativeCardSessionMaterial
import fi.refineid.android.core.NativeCore
import fi.refineid.android.core.NativePin1PreflightFailure
import fi.refineid.android.core.NativePin1PreflightResult
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.diagnostics.AppTrace

internal sealed interface CcidSessionOpenResult {
    class Ready(
        val session: CcidUsbSession,
    ) : CcidSessionOpenResult {
        override fun toString(): String = "Ready"
    }

    data object NoCard : CcidSessionOpenResult

    data object CardError : CcidSessionOpenResult

    data object TransportError : CcidSessionOpenResult
}

/** One claimed CCID interface, confined to the worker thread that opened it. */
internal class CcidUsbSession(
    private val connection: UsbDeviceConnection,
    private val usbInterface: UsbInterface,
    descriptor: CcidFunctionalDescriptor,
    exchange: CcidCommandExchange,
    sequenceCounter: CcidSequenceCounter,
) : AutoCloseable {
    private val ownerThread = Thread.currentThread()
    private val exchangeLevel =
        when (descriptor.exchangeLevel) {
            CcidExchangeLevel.TPDU -> NativeCardExchangeLevel.T0_TPDU
            CcidExchangeLevel.SHORT_APDU,
            CcidExchangeLevel.SHORT_AND_EXTENDED_APDU,
            -> NativeCardExchangeLevel.APDU
        }
    private val nativeExchange =
        CcidNativeBlockExchange(
            CcidBlockTransport(
                exchange = exchange,
                maximumBlockLength = descriptor.maximumTransferBlockLength,
                sequenceCounter = sequenceCounter,
            ),
        )
    private var isClosed = false
    private val sessionMaterial = NativeCardSessionMaterial()

    fun selectPkcs15Application(): NativeCardOperationResult {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        return NativeCore.selectPkcs15Application(
            exchangeLevel = exchangeLevel,
            exchange = nativeExchange,
        )
    }

    fun cacheAuthenticationCertificate(): NativeAuthenticationCertificateReadResult {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        val result =
            NativeCore.readAuthenticationCertificate(
                exchangeLevel = exchangeLevel,
                exchange = nativeExchange,
            )
        if (result is NativeAuthenticationCertificateReadResult.Success) {
            sessionMaterial.cacheAuthenticationCertificate(result.certificate)
        }
        return result
    }

    fun cachePin1Preflight(): NativePin1PreflightResult {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        val result =
            NativeCore.probePin1Status(
                exchangeLevel = exchangeLevel,
                exchange = nativeExchange,
            )
        if (result is NativePin1PreflightResult.Success) {
            sessionMaterial.cachePin1Preflight(result.preflight)
        }
        return result
    }

    fun copyAuthenticationCertificate(): NativeAuthenticationCertificate {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        return sessionMaterial.copyAuthenticationCertificate()
    }

    fun authenticateAndSign(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        message: ByteArray,
    ): AuthenticationSignResult =
        authenticateAndSignInput(
            algorithm = algorithm,
            inputMode = AuthenticationSigningInputMode.MESSAGE,
            pin1 = pin1,
            input = message,
        )

    fun authenticateAndSignPrehashed(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        digest: ByteArray,
    ): AuthenticationSignResult =
        authenticateAndSignInput(
            algorithm = algorithm,
            inputMode = AuthenticationSigningInputMode.PREHASHED,
            pin1 = pin1,
            input = digest,
        )

    private fun authenticateAndSignInput(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
    ): AuthenticationSignResult {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        val certificate = sessionMaterial.requireAuthenticationCertificate()
        if (certificate.keyProfile != algorithm.keyProfile) {
            pin1.close()
            return AuthenticationSignResult.Failure(
                AuthenticationSignFailure.KEY_PROFILE_MISMATCH,
            )
        }

        return when (
            val result =
                when (inputMode) {
                    AuthenticationSigningInputMode.MESSAGE ->
                        NativeCore.authenticateAndSign(
                            exchangeLevel = exchangeLevel,
                            algorithm = algorithm,
                            pin1 = pin1,
                            message = input,
                            exchange = nativeExchange,
                        )
                    AuthenticationSigningInputMode.PREHASHED ->
                        NativeCore.authenticateAndSignPrehashed(
                            exchangeLevel = exchangeLevel,
                            algorithm = algorithm,
                            pin1 = pin1,
                            digest = input,
                            exchange = nativeExchange,
                        )
                }
        ) {
            is NativeAuthenticationSignResult.Success -> {
                val isVerified =
                    when (inputMode) {
                        AuthenticationSigningInputMode.MESSAGE ->
                            AuthenticationSignatureVerifier.verify(
                                certificate = certificate,
                                message = input,
                                signature = result.signature,
                            )
                        AuthenticationSigningInputMode.PREHASHED ->
                            AuthenticationSignatureVerifier.verifyPrehashed(
                                certificate = certificate,
                                digest = input,
                                signature = result.signature,
                            )
                    }
                AppTrace.authenticationSignatureVerificationCompleted(
                    inputMode = inputMode,
                    isVerified = isVerified,
                )
                if (isVerified) {
                    AuthenticationSignResult.Success(result.signature)
                } else {
                    result.signature.close()
                    AuthenticationSignResult.Failure(
                        AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED,
                    )
                }
            }
            is NativeAuthenticationSignResult.Failure ->
                AuthenticationSignResult.Failure(result.kind.toAuthenticationFailure())
        }
    }

    fun authenticateAndSignWithDiagnosticAlgorithm(
        pin1: Pin1Submission,
        message: ByteArray,
    ): AuthenticationSignResult {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        val algorithm =
            when (sessionMaterial.requireAuthenticationCertificate().keyProfile) {
                NativeAuthenticationKeyProfile.RSA_3072 ->
                    AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256
                NativeAuthenticationKeyProfile.ECDSA_P384 ->
                    AuthenticationSigningAlgorithm.ECDSA_P384_SHA256
                NativeAuthenticationKeyProfile.RSA_2048,
                NativeAuthenticationKeyProfile.ECDSA_P256,
                -> null
            }
        if (algorithm == null) {
            pin1.close()
            return AuthenticationSignResult.Failure(
                AuthenticationSignFailure.KEY_PROFILE_MISMATCH,
            )
        }
        return authenticateAndSign(
            algorithm = algorithm,
            pin1 = pin1,
            message = message,
        )
    }

    override fun close() {
        checkOwnerThread()
        if (isClosed) {
            return
        }
        isClosed = true
        sessionMaterial.close()

        val interfaceReleased =
            try {
                connection.releaseInterface(usbInterface)
            } catch (_: SecurityException) {
                false
            }
        try {
            connection.close()
        } finally {
            AppTrace.ccidSessionClosed(interfaceReleased)
        }
    }

    override fun toString(): String = "CcidUsbSession(closed=" + isClosed + ")"

    private fun checkOwnerThread() {
        check(Thread.currentThread() === ownerThread) {
            "CCID session used from a different thread"
        }
    }
}

private fun NativeAuthenticationSignFailure.toAuthenticationFailure(): AuthenticationSignFailure =
    when (this) {
        NativeAuthenticationSignFailure.CARD_UNAVAILABLE ->
            AuthenticationSignFailure.CARD_UNAVAILABLE
        NativeAuthenticationSignFailure.TRANSPORT_ERROR ->
            AuthenticationSignFailure.TRANSPORT_ERROR
        NativeAuthenticationSignFailure.INVALID_PIN -> AuthenticationSignFailure.INVALID_PIN
        NativeAuthenticationSignFailure.SAFETY_REFUSED -> AuthenticationSignFailure.SAFETY_REFUSED
        NativeAuthenticationSignFailure.PIN_LOCKED -> AuthenticationSignFailure.PIN_LOCKED
        NativeAuthenticationSignFailure.WRONG_PIN -> AuthenticationSignFailure.WRONG_PIN
        NativeAuthenticationSignFailure.VERIFICATION_REJECTED ->
            AuthenticationSignFailure.VERIFICATION_REJECTED
        NativeAuthenticationSignFailure.SIGNING_REJECTED ->
            AuthenticationSignFailure.SIGNING_REJECTED
        NativeAuthenticationSignFailure.BRIDGE_ERROR -> AuthenticationSignFailure.BRIDGE_ERROR
    }

internal class CcidUsbSessionOpener(
    private val usbManager: UsbManager,
    private val validateAtr: (ByteArray) -> AtrValidation,
) {
    fun open(device: UsbDevice): CcidSessionOpenResult {
        val endpoints =
            CcidUsbEndpointFinder.find(device)
                ?: run {
                    AppTrace.ccidEndpointsMissing()
                    return CcidSessionOpenResult.TransportError
                }
        val connection =
            usbManager.openDevice(device)
                ?: run {
                    AppTrace.ccidOpenFailed()
                    return CcidSessionOpenResult.TransportError
                }

        return connection.openClaimed(endpoints)
    }

    private fun UsbDeviceConnection.openClaimed(
        endpoints: CcidUsbEndpoints,
    ): CcidSessionOpenResult {
        var ownsConnection = true
        var isClaimed = false
        return try {
            val descriptor =
                CcidFunctionalDescriptor.parse(
                    rawDescriptors = rawDescriptors,
                    interfaceNumber = endpoints.usbInterface.id,
                    alternateSetting = endpoints.usbInterface.alternateSetting,
                )
            AppTrace.ccidDescriptorAccepted(
                level = descriptor.exchangeLevel,
                maximumMessageLength = descriptor.maximumMessageLength,
            )

            isClaimed = claimInterface(endpoints.usbInterface, true)
            if (!isClaimed) {
                AppTrace.ccidClaimFailed()
                CcidSessionOpenResult.TransportError
            } else {
                val sequenceCounter = CcidSequenceCounter()
                val exchange =
                    CcidCommandExchange(
                        bulkIo = AndroidCcidBulkIo(this, endpoints),
                        maximumMessageLength = descriptor.maximumMessageLength,
                    )
                val activation =
                    CcidCardActivator(
                        validateAtr = validateAtr,
                        sequenceCounter = sequenceCounter,
                    ).activate(
                        exchange = exchange,
                        exchangeLevel = descriptor.exchangeLevel,
                    )
                when (activation) {
                    CcidActivationResult.READY -> {
                        val session =
                            CcidUsbSession(
                                connection = this,
                                usbInterface = endpoints.usbInterface,
                                descriptor = descriptor,
                                exchange = exchange,
                                sequenceCounter = sequenceCounter,
                            )
                        ownsConnection = false
                        isClaimed = false
                        prepareSession(session)
                    }
                    CcidActivationResult.NO_CARD -> CcidSessionOpenResult.NoCard
                    CcidActivationResult.CARD_ERROR -> CcidSessionOpenResult.CardError
                    CcidActivationResult.TRANSPORT_ERROR ->
                        CcidSessionOpenResult.TransportError
                }
            }
        } catch (error: CcidDescriptorException) {
            AppTrace.ccidDescriptorRejected(error.kind)
            CcidSessionOpenResult.TransportError
        } catch (_: SecurityException) {
            AppTrace.ccidSecurityFailure()
            CcidSessionOpenResult.TransportError
        } finally {
            if (isClaimed) {
                try {
                    releaseInterface(endpoints.usbInterface)
                } catch (_: SecurityException) {
                    // The connection is closed below regardless.
                }
            }
            if (ownsConnection) {
                close()
            }
        }
    }

    private fun prepareSession(session: CcidUsbSession): CcidSessionOpenResult {
        var retainSession = false
        return try {
            when (session.selectPkcs15Application()) {
                NativeCardOperationResult.SUCCEEDED -> {
                    when (val result = session.cacheAuthenticationCertificate()) {
                        is NativeAuthenticationCertificateReadResult.Success ->
                            when (val preflight = session.cachePin1Preflight()) {
                                is NativePin1PreflightResult.Success -> {
                                    retainSession = true
                                    CcidSessionOpenResult.Ready(session)
                                }
                                is NativePin1PreflightResult.Failure ->
                                    when (preflight.kind) {
                                        NativePin1PreflightFailure.CARD_UNAVAILABLE ->
                                            CcidSessionOpenResult.NoCard
                                        NativePin1PreflightFailure.TRANSPORT_ERROR,
                                        NativePin1PreflightFailure.BRIDGE_ERROR,
                                        -> CcidSessionOpenResult.TransportError
                                    }
                            }
                        is NativeAuthenticationCertificateReadResult.Failure ->
                            when (result.kind) {
                                NativeAuthenticationCertificateReadFailure.CARD_UNAVAILABLE ->
                                    CcidSessionOpenResult.NoCard
                                NativeAuthenticationCertificateReadFailure.REJECTED,
                                NativeAuthenticationCertificateReadFailure.INVALID_CERTIFICATE,
                                -> CcidSessionOpenResult.CardError
                                NativeAuthenticationCertificateReadFailure.TRANSPORT_ERROR,
                                NativeAuthenticationCertificateReadFailure.BRIDGE_ERROR,
                                -> CcidSessionOpenResult.TransportError
                            }
                    }
                }
                NativeCardOperationResult.CARD_UNAVAILABLE -> CcidSessionOpenResult.NoCard
                NativeCardOperationResult.REJECTED -> CcidSessionOpenResult.CardError
                NativeCardOperationResult.TRANSPORT_ERROR,
                NativeCardOperationResult.BRIDGE_ERROR,
                -> CcidSessionOpenResult.TransportError
            }
        } finally {
            if (!retainSession) {
                session.close()
            }
        }
    }
}
