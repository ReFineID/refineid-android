package fi.refineid.android.core

import fi.refineid.android.diagnostics.AppTrace

/** Native boundary for credential-free PIN2 state and qualified signing. */
internal object NativeQualifiedCore {
    fun readQualifiedCertificate(
        exchangeLevel: NativeCardExchangeLevel,
        exchange: NativeBlockExchange,
    ): NativeCertificateReadResult<NativeQualifiedCertificate> {
        val startedAt = AppTrace.nativeQualifiedCertificateReadStarted(exchangeLevel)
        val result =
            if (!NativeCore.isLoaded) {
                NativeCertificateReadResult.Failure(
                    NativeCertificateReadFailure.BRIDGE_ERROR,
                )
            } else {
                try {
                    NativeCertificateReply.decode(
                        reply =
                            readQualifiedCertificateNative(
                                exchangeLevel = exchangeLevel.wireValue,
                                callback = exchange,
                            ),
                        certificate = { profile, der ->
                            NativeQualifiedCertificate(
                                keyProfile = profile,
                                ownedDer = der,
                            )
                        },
                    )
                } catch (_: LinkageError) {
                    NativeCertificateReadResult.Failure(
                        NativeCertificateReadFailure.BRIDGE_ERROR,
                    )
                } catch (_: RuntimeException) {
                    NativeCertificateReadResult.Failure(
                        NativeCertificateReadFailure.BRIDGE_ERROR,
                    )
                }
            }
        AppTrace.nativeQualifiedCertificateReadCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    fun probePin2Status(
        exchangeLevel: NativeCardExchangeLevel,
        exchange: NativeBlockExchange,
    ): NativePin2PreflightResult {
        val startedAt = AppTrace.nativePin2StatusProbeStarted(exchangeLevel)
        val result =
            if (!NativeCore.isLoaded) {
                NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)
            } else {
                try {
                    NativePin2PreflightReply.decode(
                        probePin2StatusNative(
                            exchangeLevel = exchangeLevel.wireValue,
                            callback = exchange,
                        ),
                    )
                } catch (_: LinkageError) {
                    NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)
                } catch (_: RuntimeException) {
                    NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)
                }
            }
        AppTrace.nativePin2StatusProbeCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    fun qualifiedSign(
        exchangeLevel: NativeCardExchangeLevel,
        algorithm: QualifiedSigningAlgorithm,
        pin2: Pin2Submission,
        content: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
        exchange: NativeBlockExchange,
    ): NativeQualifiedSignResult =
        qualifiedSignInput(
            exchangeLevel = exchangeLevel,
            algorithm = algorithm,
            inputMode = QualifiedSigningInputMode.MESSAGE,
            pin2 = pin2,
            input = content,
            expectedCertificate = expectedCertificate,
            exchange = exchange,
        )

    fun qualifiedSignInput(
        exchangeLevel: NativeCardExchangeLevel,
        algorithm: QualifiedSigningAlgorithm,
        inputMode: QualifiedSigningInputMode,
        pin2: Pin2Submission,
        input: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
        exchange: NativeBlockExchange,
    ): NativeQualifiedSignResult {
        val startedAt =
            AppTrace.nativeQualifiedSignStarted(
                algorithm = algorithm,
                contentLength = input.size,
            )
        val result =
            if (!algorithm.acceptsInputLength(inputMode, input.size)) {
                pin2.close()
                NativeQualifiedSignResult.Failure(NativeQualifiedSignFailure.BRIDGE_ERROR)
            } else {
                val expectedDer =
                    try {
                        expectedCertificate.copyDer()
                    } catch (_: IllegalStateException) {
                        pin2.close()
                        null
                    }
                if (expectedDer == null) {
                    NativeQualifiedSignResult.Failure(NativeQualifiedSignFailure.BRIDGE_ERROR)
                } else {
                    try {
                        pin2.consume { pinBytes ->
                            if (!NativeCore.isLoaded) {
                                NativeQualifiedSignResult.Failure(
                                    NativeQualifiedSignFailure.BRIDGE_ERROR,
                                )
                            } else {
                                NativeQualifiedSignReply.decode(
                                    qualifiedSignNative(
                                        exchangeLevel = exchangeLevel.wireValue,
                                        algorithm = algorithm.requestWireValue(inputMode),
                                        pin = pinBytes,
                                        content = input,
                                        expectedCertificate = expectedDer,
                                        callback = exchange,
                                    ),
                                )
                            }
                        }
                    } catch (_: LinkageError) {
                        NativeQualifiedSignResult.Failure(
                            NativeQualifiedSignFailure.BRIDGE_ERROR,
                        )
                    } catch (_: RuntimeException) {
                        NativeQualifiedSignResult.Failure(
                            NativeQualifiedSignFailure.BRIDGE_ERROR,
                        )
                    } finally {
                        expectedDer.fill(ZERO_BYTE)
                    }
                }
            }
        AppTrace.nativeQualifiedSignCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    @JvmStatic
    private external fun readQualifiedCertificateNative(
        exchangeLevel: Int,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun probePin2StatusNative(
        exchangeLevel: Int,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun qualifiedSignNative(
        exchangeLevel: Int,
        algorithm: Int,
        pin: ByteArray,
        content: ByteArray,
        expectedCertificate: ByteArray,
        callback: Any,
    ): ByteArray

    private const val ZERO_BYTE: Byte = 0
}
