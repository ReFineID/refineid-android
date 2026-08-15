package fi.refineid.android.core

import fi.refineid.android.diagnostics.AppTrace

internal enum class AtrValidation {
    VALID_T0_DIRECT,
    VALID_T0_INVERSE,
    VALID_NON_T0_DIRECT,
    VALID_NON_T0_INVERSE,
    INVALID,
    BRIDGE_ERROR,
}

internal enum class NativeCardExchangeLevel(
    val wireValue: Int,
) {
    APDU(0),
    T0_TPDU(1),
}

internal enum class NativeCardOperationResult {
    SUCCEEDED,
    CARD_UNAVAILABLE,
    REJECTED,
    TRANSPORT_ERROR,
    BRIDGE_ERROR,
}

internal enum class NativeAuthenticationKeyProfile {
    RSA_2048,
    RSA_3072,
    ECDSA_P256,
    ECDSA_P384,
}

internal class NativeAuthenticationCertificate(
    val keyProfile: NativeAuthenticationKeyProfile,
    private val ownedDer: ByteArray,
) : AutoCloseable {
    private var isClosed = false

    val derLength: Int
        get() = ownedDer.size

    fun copyDer(): ByteArray {
        check(!isClosed) {
            "authentication certificate is closed"
        }
        return ownedDer.copyOf()
    }

    fun copyOwned(): NativeAuthenticationCertificate =
        NativeAuthenticationCertificate(
            keyProfile = keyProfile,
            ownedDer = copyDer(),
        )

    override fun close() {
        if (!isClosed) {
            ownedDer.fill(0)
            isClosed = true
        }
    }

    override fun toString(): String =
        "NativeAuthenticationCertificate(profile=" + keyProfile +
            ", length=" + derLength +
            ", closed=" + isClosed + ")"
}

internal enum class NativeAuthenticationCertificateReadFailure {
    CARD_UNAVAILABLE,
    REJECTED,
    TRANSPORT_ERROR,
    INVALID_CERTIFICATE,
    BRIDGE_ERROR,
}

internal sealed interface NativeAuthenticationCertificateReadResult {
    class Success(
        val certificate: NativeAuthenticationCertificate,
    ) : NativeAuthenticationCertificateReadResult {
        override fun toString(): String = "Success(" + certificate + ")"
    }

    data class Failure(
        val kind: NativeAuthenticationCertificateReadFailure,
    ) : NativeAuthenticationCertificateReadResult
}

/** Synchronous byte-moving callback invoked only inside one native operation. */
internal interface NativeBlockExchange {
    fun exchangePublic(block: ByteArray): ByteArray

    fun exchangeCredential(block: ByteArray): ByteArray
}

internal object NativeCore {
    private const val LIBRARY_NAME = "refineid_android_core"
    private const val ATR_INVALID = 0
    private const val ATR_VALID_T0_DIRECT = 1
    private const val ATR_VALID_T0_INVERSE = 2
    private const val ATR_VALID_NON_T0_DIRECT = 3
    private const val ATR_VALID_NON_T0_INVERSE = 4
    private const val CARD_OPERATION_BRIDGE_ERROR = 0
    private const val CARD_OPERATION_SUCCEEDED = 1
    private const val CARD_OPERATION_CARD_UNAVAILABLE = 2
    private const val CARD_OPERATION_REJECTED = 3
    private const val CARD_OPERATION_TRANSPORT_ERROR = 4

    private val isLoaded =
        runCatching {
            System.loadLibrary(LIBRARY_NAME)
        }.also { result ->
            AppTrace.nativeLibraryLoadCompleted(isSuccessful = result.isSuccess)
        }.isSuccess

    fun validateAtr(atr: ByteArray): AtrValidation {
        val result =
            if (!isLoaded) {
                AtrValidation.BRIDGE_ERROR
            } else {
                try {
                    when (validateAtrNative(atr)) {
                        ATR_VALID_T0_DIRECT -> AtrValidation.VALID_T0_DIRECT
                        ATR_VALID_T0_INVERSE -> AtrValidation.VALID_T0_INVERSE
                        ATR_VALID_NON_T0_DIRECT -> AtrValidation.VALID_NON_T0_DIRECT
                        ATR_VALID_NON_T0_INVERSE -> AtrValidation.VALID_NON_T0_INVERSE
                        ATR_INVALID -> AtrValidation.INVALID
                        else -> AtrValidation.BRIDGE_ERROR
                    }
                } catch (_: LinkageError) {
                    AtrValidation.BRIDGE_ERROR
                }
            }
        AppTrace.nativeAtrValidationCompleted(result)
        return result
    }

    fun selectPkcs15Application(
        exchangeLevel: NativeCardExchangeLevel,
        exchange: NativeBlockExchange,
    ): NativeCardOperationResult {
        val startedAt = AppTrace.nativePkcs15SelectionStarted(exchangeLevel)
        val result =
            if (!isLoaded) {
                NativeCardOperationResult.BRIDGE_ERROR
            } else {
                try {
                    when (
                        selectPkcs15ApplicationNative(
                            exchangeLevel = exchangeLevel.wireValue,
                            callback = exchange,
                        )
                    ) {
                        CARD_OPERATION_SUCCEEDED -> {
                            NativeCardOperationResult.SUCCEEDED
                        }

                        CARD_OPERATION_CARD_UNAVAILABLE -> {
                            NativeCardOperationResult.CARD_UNAVAILABLE
                        }

                        CARD_OPERATION_REJECTED -> {
                            NativeCardOperationResult.REJECTED
                        }

                        CARD_OPERATION_TRANSPORT_ERROR -> {
                            NativeCardOperationResult.TRANSPORT_ERROR
                        }

                        CARD_OPERATION_BRIDGE_ERROR -> {
                            NativeCardOperationResult.BRIDGE_ERROR
                        }

                        else -> {
                            NativeCardOperationResult.BRIDGE_ERROR
                        }
                    }
                } catch (_: LinkageError) {
                    NativeCardOperationResult.BRIDGE_ERROR
                } catch (_: RuntimeException) {
                    NativeCardOperationResult.BRIDGE_ERROR
                }
            }
        AppTrace.nativePkcs15SelectionCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    fun readAuthenticationCertificate(
        exchangeLevel: NativeCardExchangeLevel,
        exchange: NativeBlockExchange,
    ): NativeAuthenticationCertificateReadResult {
        val startedAt = AppTrace.nativeAuthenticationCertificateReadStarted(exchangeLevel)
        val result =
            if (!isLoaded) {
                NativeAuthenticationCertificateReadResult.Failure(
                    NativeAuthenticationCertificateReadFailure.BRIDGE_ERROR,
                )
            } else {
                try {
                    NativeAuthenticationCertificateReply.decode(
                        readAuthenticationCertificateNative(
                            exchangeLevel = exchangeLevel.wireValue,
                            callback = exchange,
                        ),
                    )
                } catch (_: LinkageError) {
                    NativeAuthenticationCertificateReadResult.Failure(
                        NativeAuthenticationCertificateReadFailure.BRIDGE_ERROR,
                    )
                } catch (_: RuntimeException) {
                    NativeAuthenticationCertificateReadResult.Failure(
                        NativeAuthenticationCertificateReadFailure.BRIDGE_ERROR,
                    )
                }
            }
        AppTrace.nativeAuthenticationCertificateReadCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    fun probePin1Status(
        exchangeLevel: NativeCardExchangeLevel,
        exchange: NativeBlockExchange,
    ): NativePin1PreflightResult {
        val startedAt = AppTrace.nativePin1StatusProbeStarted(exchangeLevel)
        val result =
            if (!isLoaded) {
                NativePin1PreflightResult.Failure(NativePin1PreflightFailure.BRIDGE_ERROR)
            } else {
                try {
                    NativePin1PreflightReply.decode(
                        probePin1StatusNative(
                            exchangeLevel = exchangeLevel.wireValue,
                            callback = exchange,
                        ),
                    )
                } catch (_: LinkageError) {
                    NativePin1PreflightResult.Failure(NativePin1PreflightFailure.BRIDGE_ERROR)
                } catch (_: RuntimeException) {
                    NativePin1PreflightResult.Failure(NativePin1PreflightFailure.BRIDGE_ERROR)
                }
            }
        AppTrace.nativePin1StatusProbeCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    fun authenticateAndSign(
        exchangeLevel: NativeCardExchangeLevel,
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        message: ByteArray,
        exchange: NativeBlockExchange,
    ): NativeAuthenticationSignResult =
        authenticateAndSignInput(
            exchangeLevel = exchangeLevel,
            algorithm = algorithm,
            inputMode = AuthenticationSigningInputMode.MESSAGE,
            pin1 = pin1,
            input = message,
            exchange = exchange,
        )

    fun authenticateAndSignPrehashed(
        exchangeLevel: NativeCardExchangeLevel,
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        digest: ByteArray,
        exchange: NativeBlockExchange,
    ): NativeAuthenticationSignResult =
        authenticateAndSignInput(
            exchangeLevel = exchangeLevel,
            algorithm = algorithm,
            inputMode = AuthenticationSigningInputMode.PREHASHED,
            pin1 = pin1,
            input = digest,
            exchange = exchange,
        )

    private fun authenticateAndSignInput(
        exchangeLevel: NativeCardExchangeLevel,
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
        exchange: NativeBlockExchange,
    ): NativeAuthenticationSignResult {
        val startedAt =
            AppTrace.nativeAuthenticationSignStarted(
                algorithm = algorithm,
                inputMode = inputMode,
                inputLength = input.size,
            )
        val result =
            if (!algorithm.acceptsInputLength(inputMode, input.size)) {
                pin1.close()
                NativeAuthenticationSignResult.Failure(
                    NativeAuthenticationSignFailure.BRIDGE_ERROR,
                )
            } else {
                try {
                    pin1.consume { pinBytes ->
                        if (!isLoaded) {
                            NativeAuthenticationSignResult.Failure(
                                NativeAuthenticationSignFailure.BRIDGE_ERROR,
                            )
                        } else {
                            NativeAuthenticationSignReply.decode(
                                authenticateAndSignNative(
                                    exchangeLevel = exchangeLevel.wireValue,
                                    request = algorithm.requestWireValue(inputMode),
                                    pin = pinBytes,
                                    input = input,
                                    callback = exchange,
                                ),
                            )
                        }
                    }
                } catch (_: LinkageError) {
                    NativeAuthenticationSignResult.Failure(
                        NativeAuthenticationSignFailure.BRIDGE_ERROR,
                    )
                } catch (_: RuntimeException) {
                    NativeAuthenticationSignResult.Failure(
                        NativeAuthenticationSignFailure.BRIDGE_ERROR,
                    )
                }
            }
        AppTrace.nativeAuthenticationSignCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    @JvmStatic
    private external fun validateAtrNative(atr: ByteArray): Int

    @JvmStatic
    private external fun selectPkcs15ApplicationNative(
        exchangeLevel: Int,
        callback: Any,
    ): Int

    @JvmStatic
    private external fun readAuthenticationCertificateNative(
        exchangeLevel: Int,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun probePin1StatusNative(
        exchangeLevel: Int,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun authenticateAndSignNative(
        exchangeLevel: Int,
        request: Int,
        pin: ByteArray,
        input: ByteArray,
        callback: Any,
    ): ByteArray
}

internal object NativeAuthenticationCertificateReply {
    fun decode(reply: ByteArray): NativeAuthenticationCertificateReadResult =
        try {
            if (reply.isEmpty() || reply.size > MAXIMUM_REPLY_LENGTH) {
                return bridgeFailure()
            }

            when (reply[CERTIFICATE_REPLY_TAG_OFFSET].toInt()) {
                CERTIFICATE_SUCCEEDED -> {
                    decodeSuccess(reply)
                }

                CERTIFICATE_CARD_UNAVAILABLE -> {
                    decodeFailure(
                        reply,
                        NativeAuthenticationCertificateReadFailure.CARD_UNAVAILABLE,
                    )
                }

                CERTIFICATE_REJECTED -> {
                    decodeFailure(
                        reply,
                        NativeAuthenticationCertificateReadFailure.REJECTED,
                    )
                }

                CERTIFICATE_TRANSPORT_ERROR -> {
                    decodeFailure(
                        reply,
                        NativeAuthenticationCertificateReadFailure.TRANSPORT_ERROR,
                    )
                }

                CERTIFICATE_INVALID -> {
                    decodeFailure(
                        reply,
                        NativeAuthenticationCertificateReadFailure.INVALID_CERTIFICATE,
                    )
                }

                CERTIFICATE_BRIDGE_ERROR -> {
                    decodeFailure(
                        reply,
                        NativeAuthenticationCertificateReadFailure.BRIDGE_ERROR,
                    )
                }

                else -> {
                    bridgeFailure()
                }
            }
        } finally {
            reply.fill(0)
        }

    private fun decodeSuccess(reply: ByteArray): NativeAuthenticationCertificateReadResult {
        if (reply.size <= CERTIFICATE_REPLY_HEADER_LENGTH) {
            return bridgeFailure()
        }
        val profile =
            when (reply[KEY_PROFILE_OFFSET].toInt()) {
                KEY_PROFILE_RSA_2048 -> NativeAuthenticationKeyProfile.RSA_2048
                KEY_PROFILE_RSA_3072 -> NativeAuthenticationKeyProfile.RSA_3072
                KEY_PROFILE_ECDSA_P256 -> NativeAuthenticationKeyProfile.ECDSA_P256
                KEY_PROFILE_ECDSA_P384 -> NativeAuthenticationKeyProfile.ECDSA_P384
                else -> return bridgeFailure()
            }
        return NativeAuthenticationCertificateReadResult.Success(
            NativeAuthenticationCertificate(
                keyProfile = profile,
                ownedDer = reply.copyOfRange(CERTIFICATE_REPLY_HEADER_LENGTH, reply.size),
            ),
        )
    }

    private fun decodeFailure(
        reply: ByteArray,
        kind: NativeAuthenticationCertificateReadFailure,
    ): NativeAuthenticationCertificateReadResult =
        if (reply.size == FAILURE_REPLY_LENGTH) {
            NativeAuthenticationCertificateReadResult.Failure(kind)
        } else {
            bridgeFailure()
        }

    private fun bridgeFailure(): NativeAuthenticationCertificateReadResult.Failure =
        NativeAuthenticationCertificateReadResult.Failure(
            NativeAuthenticationCertificateReadFailure.BRIDGE_ERROR,
        )

    private const val CERTIFICATE_BRIDGE_ERROR = 0
    private const val CERTIFICATE_SUCCEEDED = 1
    private const val CERTIFICATE_CARD_UNAVAILABLE = 2
    private const val CERTIFICATE_REJECTED = 3
    private const val CERTIFICATE_TRANSPORT_ERROR = 4
    private const val CERTIFICATE_INVALID = 5

    private const val KEY_PROFILE_RSA_2048 = 0
    private const val KEY_PROFILE_RSA_3072 = 1
    private const val KEY_PROFILE_ECDSA_P256 = 2
    private const val KEY_PROFILE_ECDSA_P384 = 3

    private const val FAILURE_REPLY_LENGTH = 1
    private const val CERTIFICATE_REPLY_TAG_OFFSET = 0
    private const val KEY_PROFILE_OFFSET = 1
    private const val CERTIFICATE_REPLY_HEADER_LENGTH = 2
    private const val MAXIMUM_CERTIFICATE_LENGTH = 16 * 1_024
    private const val MAXIMUM_REPLY_LENGTH =
        CERTIFICATE_REPLY_HEADER_LENGTH + MAXIMUM_CERTIFICATE_LENGTH
}
