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
}

/** Owns one baseline PDF-signing request from local preparation through filled CMS. */
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
        val tracedResult: (QualifiedPdfSigningResult) -> Unit = { result ->
            AppTrace.qualifiedPdfSigningCompleted(startedAt = startedAt, result = result)
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
                    QualifiedPdfSigningResult.Failure(
                        QualifiedPdfSigningFailure.Document(failure.kind),
                    ),
                )
                return
            } catch (_: RuntimeException) {
                pin2.close()
                tracedResult(internalFailure())
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
        onResult: (QualifiedPdfSigningResult) -> Unit,
    ) {
        when (result) {
            is NativeCertificateReadResult.Failure -> {
                placeholder.close()
                pin2.close()
                onResult(
                    QualifiedPdfSigningResult.Failure(
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
        onResult: (QualifiedPdfSigningResult) -> Unit,
    ) {
        val algorithm = algorithm(certificate.keyProfile)
        if (algorithm == null) {
            placeholder.close()
            certificate.close()
            pin2.close()
            onResult(
                QualifiedPdfSigningResult.Failure(
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
                    QualifiedPdfSigningResult.Failure(
                        QualifiedPdfSigningFailure.Cms(failure.kind),
                    ),
                )
                return
            } catch (_: RuntimeException) {
                placeholder.close()
                certificate.close()
                pin2.close()
                onResult(internalFailure())
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
        onResult: (QualifiedPdfSigningResult) -> Unit,
    ) {
        val completion =
            try {
                when (result) {
                    is QualifiedSignResult.Failure -> {
                        QualifiedPdfSigningResult.Failure(
                            QualifiedPdfSigningFailure.Card(result.kind),
                        )
                    }

                    is QualifiedSignResult.Success -> {
                        assembled(
                            placeholder = placeholder,
                            signedAttributes = signedAttributes,
                            certificate = certificate,
                            signature = result.signature,
                        )
                    }
                }
            } finally {
                placeholder.close()
                signedAttributes.fill(ZERO_BYTE)
                certificate.close()
                if (result is QualifiedSignResult.Success) {
                    result.signature.close()
                }
            }
        onResult(completion)
    }

    private fun assembled(
        placeholder: PdfSignaturePlaceholder,
        signedAttributes: ByteArray,
        certificate: NativeQualifiedCertificate,
        signature: NativeQualifiedSignature,
    ): QualifiedPdfSigningResult {
        val cms =
            try {
                cryptography.assemble(
                    signedAttributes = signedAttributes,
                    signature = signature,
                    signerCertificate = certificate,
                )
            } catch (failure: QualifiedDocumentCmsException) {
                return QualifiedPdfSigningResult.Failure(
                    QualifiedPdfSigningFailure.Cms(failure.kind),
                )
            } catch (_: RuntimeException) {
                return internalFailure()
            }
        return try {
            QualifiedPdfSigningResult.Success(
                SignedPdfDocument(placeholder.filledWith(cms)),
            )
        } catch (failure: PdfSigningException) {
            QualifiedPdfSigningResult.Failure(
                QualifiedPdfSigningFailure.Document(failure.kind),
            )
        } catch (_: RuntimeException) {
            internalFailure()
        } finally {
            cms.fill(ZERO_BYTE)
        }
    }

    private fun algorithm(profile: NativeCardKeyProfile): QualifiedSigningAlgorithm? =
        QualifiedSigningAlgorithm.entries.firstOrNull { algorithm ->
            algorithm.keyProfile == profile
        }

    private fun internalFailure(): QualifiedPdfSigningResult.Failure =
        QualifiedPdfSigningResult.Failure(QualifiedPdfSigningFailure.InternalError)

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}
