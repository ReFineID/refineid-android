// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedSignature
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.diagnostics.AppTrace

/** CMS operations kept injectable so orchestration ownership can be tested independently. */
internal interface QualifiedPdfCryptography {
    fun signedAttributes(
        byteRangeDigest: ByteArray,
        signerCertificate: NativeQualifiedCertificate,
    ): ByteArray

    fun assemble(
        signedAttributes: ByteArray,
        signature: NativeQualifiedSignature,
        signerCertificate: NativeQualifiedCertificate,
    ): ByteArray

    /** Returns a fresh owned SHA-384 digest over the CMS signature value. */
    fun signatureTimestampDigest(signature: NativeQualifiedSignature): ByteArray

    fun assembleTimestamped(
        signedAttributes: ByteArray,
        signature: NativeQualifiedSignature,
        signerCertificate: NativeQualifiedCertificate,
        timestampTokens: List<VerifiedTimestampToken>,
    ): ByteArray
}

internal object ProductionQualifiedPdfCryptography : QualifiedPdfCryptography {
    override fun signedAttributes(
        byteRangeDigest: ByteArray,
        signerCertificate: NativeQualifiedCertificate,
    ): ByteArray =
        QualifiedDocumentCms.signedAttributes(
            byteRangeDigest = byteRangeDigest,
            signerCertificate = signerCertificate,
        )

    override fun assemble(
        signedAttributes: ByteArray,
        signature: NativeQualifiedSignature,
        signerCertificate: NativeQualifiedCertificate,
    ): ByteArray =
        QualifiedDocumentCms.assemble(
            signedAttributesSet = signedAttributes,
            signature = signature,
            signerCertificate = signerCertificate,
        )

    override fun signatureTimestampDigest(signature: NativeQualifiedSignature): ByteArray =
        QualifiedDocumentCms.signatureTimestampDigest(signature)

    override fun assembleTimestamped(
        signedAttributes: ByteArray,
        signature: NativeQualifiedSignature,
        signerCertificate: NativeQualifiedCertificate,
        timestampTokens: List<VerifiedTimestampToken>,
    ): ByteArray =
        QualifiedDocumentCms.assembleTimestamped(
            signedAttributesSet = signedAttributes,
            signature = signature,
            signerCertificate = signerCertificate,
            timestampTokens = timestampTokens,
        )
}

/** Owns one PDF-signing request through the locally verified card-signature stage. */
internal class QualifiedPdfSigningCoordinator(
    private val cardService: QualifiedCardService,
    private val cryptography: QualifiedPdfCryptography = ProductionQualifiedPdfCryptography,
) {
    fun sign(
        document: ByteArray,
        claim: PdfSignatureClaim,
        pin2: Pin2Submission,
        onResult: (QualifiedPdfSigningResult) -> Unit,
    ) {
        val startedAt = AppTrace.qualifiedPdfSigningStarted(document.size)
        prepare(document = document, claim = claim, pin2 = pin2) { preparation ->
            val result = baselineResult(preparation)
            AppTrace.qualifiedPdfSigningCompleted(startedAt = startedAt, result = result)
            onResult(result)
        }
    }

    fun prepare(
        document: ByteArray,
        claim: PdfSignatureClaim,
        pin2: Pin2Submission,
        onResult: (QualifiedPdfPreparationResult) -> Unit,
    ) {
        val startedAt = AppTrace.qualifiedPdfPreparationStarted(document.size)
        val tracedResult: (QualifiedPdfPreparationResult) -> Unit = { result ->
            AppTrace.qualifiedPdfPreparationCompleted(startedAt = startedAt, result = result)
            onResult(result)
        }
        val placeholder =
            try {
                PdfIncrementalSigner.prepare(
                    document = document,
                    revision = PdfSignatureRevision.Signature(claim),
                )
            } catch (failure: PdfSigningException) {
                pin2.close()
                tracedResult(
                    QualifiedPdfPreparationResult.Failure(
                        QualifiedPdfSigningFailure.Document(failure.kind),
                    ),
                )
                return
            } catch (_: RuntimeException) {
                pin2.close()
                tracedResult(internalPreparationFailure())
                return
            }
        cardService.requestQualifiedCertificate { certificateResult ->
            certificateReceived(
                result = certificateResult,
                placeholder = placeholder,
                pin2 = pin2,
                onResult = tracedResult,
            )
        }
    }

    private fun certificateReceived(
        result: NativeCertificateReadResult<NativeQualifiedCertificate>,
        placeholder: PdfSignaturePlaceholder,
        pin2: Pin2Submission,
        onResult: (QualifiedPdfPreparationResult) -> Unit,
    ) {
        when (result) {
            is NativeCertificateReadResult.Failure -> {
                placeholder.close()
                pin2.close()
                onResult(
                    QualifiedPdfPreparationResult.Failure(
                        QualifiedPdfSigningFailure.Certificate(result.kind),
                    ),
                )
            }

            is NativeCertificateReadResult.Success -> {
                signPrepared(
                    placeholder = placeholder,
                    certificate = result.certificate,
                    pin2 = pin2,
                    onResult = onResult,
                )
            }
        }
    }

    private fun signPrepared(
        placeholder: PdfSignaturePlaceholder,
        certificate: NativeQualifiedCertificate,
        pin2: Pin2Submission,
        onResult: (QualifiedPdfPreparationResult) -> Unit,
    ) {
        val algorithm = algorithm(certificate.keyProfile)
        if (algorithm == null) {
            placeholder.close()
            certificate.close()
            pin2.close()
            onResult(
                QualifiedPdfPreparationResult.Failure(
                    QualifiedPdfSigningFailure.KeyProfileUnsupported,
                ),
            )
            return
        }
        val digest = placeholder.digest()
        val signedAttributes =
            try {
                cryptography.signedAttributes(
                    byteRangeDigest = digest,
                    signerCertificate = certificate,
                )
            } catch (failure: QualifiedDocumentCmsException) {
                placeholder.close()
                certificate.close()
                pin2.close()
                onResult(
                    QualifiedPdfPreparationResult.Failure(
                        QualifiedPdfSigningFailure.Cms(failure.kind),
                    ),
                )
                return
            } catch (_: RuntimeException) {
                placeholder.close()
                certificate.close()
                pin2.close()
                onResult(internalPreparationFailure())
                return
            } finally {
                digest.fill(ZERO_BYTE)
            }
        cardService.requestQualifiedSignature(
            algorithm = algorithm,
            pin2 = pin2,
            content = signedAttributes,
            expectedCertificate = certificate,
        ) { signatureResult ->
            signatureReceived(
                result = signatureResult,
                placeholder = placeholder,
                signedAttributes = signedAttributes,
                certificate = certificate,
                onResult = onResult,
            )
        }
    }

    private fun signatureReceived(
        result: QualifiedSignResult,
        placeholder: PdfSignaturePlaceholder,
        signedAttributes: ByteArray,
        certificate: NativeQualifiedCertificate,
        onResult: (QualifiedPdfPreparationResult) -> Unit,
    ) {
        when (result) {
            is QualifiedSignResult.Failure -> {
                placeholder.close()
                signedAttributes.fill(ZERO_BYTE)
                certificate.close()
                onResult(
                    QualifiedPdfPreparationResult.Failure(
                        QualifiedPdfSigningFailure.Card(result.kind),
                    ),
                )
            }

            is QualifiedSignResult.Success -> {
                onResult(
                    QualifiedPdfPreparationResult.Success(
                        PreparedQualifiedPdfSignature(
                            ownedPlaceholder = placeholder,
                            ownedSignedAttributes = signedAttributes,
                            ownedSignature = result.signature,
                            ownedSignerCertificate = certificate,
                            cryptography = cryptography,
                        ),
                    ),
                )
            }
        }
    }

    private fun baselineResult(preparation: QualifiedPdfPreparationResult): QualifiedPdfSigningResult =
        when (preparation) {
            is QualifiedPdfPreparationResult.Failure -> {
                QualifiedPdfSigningResult.Failure(preparation.kind)
            }

            is QualifiedPdfPreparationResult.Success -> {
                try {
                    QualifiedPdfSigningResult.Success(preparation.prepared.completeBaseline())
                } catch (failure: QualifiedDocumentCmsException) {
                    QualifiedPdfSigningResult.Failure(
                        QualifiedPdfSigningFailure.Cms(failure.kind),
                    )
                } catch (failure: PdfSigningException) {
                    QualifiedPdfSigningResult.Failure(
                        QualifiedPdfSigningFailure.Document(failure.kind),
                    )
                } catch (_: RuntimeException) {
                    internalFailure()
                } finally {
                    preparation.prepared.close()
                }
            }
        }

    private fun algorithm(profile: NativeCardKeyProfile): QualifiedSigningAlgorithm? =
        QualifiedSigningAlgorithm.entries.firstOrNull { algorithm ->
            algorithm.keyProfile == profile
        }

    private fun internalFailure(): QualifiedPdfSigningResult.Failure =
        QualifiedPdfSigningResult.Failure(QualifiedPdfSigningFailure.InternalError)

    private fun internalPreparationFailure(): QualifiedPdfPreparationResult.Failure =
        QualifiedPdfPreparationResult.Failure(QualifiedPdfSigningFailure.InternalError)

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}
