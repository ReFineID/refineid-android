// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import fi.refineid.android.diagnostics.AppTrace

/** Sanitized orchestration stage exposed only to the variant trace sink. */
internal enum class QualifiedPdfArchivalStage {
    SIGNATURE_TIMESTAMP,
    TIMESTAMPED_SIGNATURE,
    VALIDATION_MATERIAL,
    ARCHIVE_PREPARATION,
    ARCHIVE_TIMESTAMP,
}

/** The exact RFC 3161 request whose failure prevented archival completion. */
internal enum class QualifiedPdfTimestampPhase {
    SIGNATURE,
    ARCHIVE,
}

/** Coarse failure from an injected timestamp source after its own retry policy. */
internal class QualifiedPdfTimestampSourceException : RuntimeException()

internal fun interface QualifiedPdfTimestampSource {
    /** The digest is borrowed; the returned verified token transfers to the caller. */
    fun acquire(digest: ByteArray): VerifiedTimestampToken
}

/** Coarse non-path failure from an injected validation-material source. */
internal class QualifiedPdfValidationSourceException : RuntimeException()

internal fun interface QualifiedPdfValidationSource {
    /** Inputs are borrowed; the returned validation material transfers to the caller. */
    fun collect(
        signerCertificate: ByteArray,
        signatureTimestamp: VerifiedTimestampToken,
    ): PdfValidationMaterial
}

internal sealed interface QualifiedPdfArchivalFailure {
    data class Timestamp(
        val phase: QualifiedPdfTimestampPhase,
    ) : QualifiedPdfArchivalFailure

    data class Validation(
        val kind: ValidationMaterialCollectionFailure,
        val pathRole: ValidationPathRole?,
    ) : QualifiedPdfArchivalFailure

    data class Cms(
        val kind: QualifiedDocumentCmsFailure,
    ) : QualifiedPdfArchivalFailure

    data class Document(
        val kind: PdfSigningFailure,
    ) : QualifiedPdfArchivalFailure

    data object ValidationUnavailable : QualifiedPdfArchivalFailure

    data object InternalError : QualifiedPdfArchivalFailure
}

internal sealed interface QualifiedPdfArchivalResult {
    class Success(
        val document: SignedPdfDocument,
    ) : QualifiedPdfArchivalResult {
        override fun toString(): String = "Success(" + document + ")"
    }

    data class Failure(
        val kind: QualifiedPdfArchivalFailure,
    ) : QualifiedPdfArchivalResult
}

/** Synchronous PAdES-B-LTA completion. Callers must invoke it away from the UI thread. */
internal object QualifiedPdfArchivalCompletion {
    fun complete(
        prepared: PreparedQualifiedPdfSignature,
        timestampSource: QualifiedPdfTimestampSource,
        validationSource: QualifiedPdfValidationSource,
    ): QualifiedPdfArchivalResult {
        val startedAt = AppTrace.qualifiedPdfArchivalStarted()
        val result =
            try {
                QualifiedPdfArchivalResult.Success(
                    completeOwned(
                        prepared = prepared,
                        timestampSource = timestampSource,
                        validationSource = validationSource,
                    ),
                )
            } catch (failure: CompletionException) {
                QualifiedPdfArchivalResult.Failure(failure.kind)
            } catch (failure: QualifiedDocumentCmsException) {
                QualifiedPdfArchivalResult.Failure(
                    QualifiedPdfArchivalFailure.Cms(failure.kind),
                )
            } catch (failure: PdfSigningException) {
                QualifiedPdfArchivalResult.Failure(
                    QualifiedPdfArchivalFailure.Document(failure.kind),
                )
            } catch (_: RuntimeException) {
                QualifiedPdfArchivalResult.Failure(QualifiedPdfArchivalFailure.InternalError)
            } finally {
                prepared.close()
            }
        AppTrace.qualifiedPdfArchivalCompleted(startedAt = startedAt, result = result)
        return result
    }

    private fun completeOwned(
        prepared: PreparedQualifiedPdfSignature,
        timestampSource: QualifiedPdfTimestampSource,
        validationSource: QualifiedPdfValidationSource,
    ): SignedPdfDocument =
        prepared.copySignerCertificate().useOwnedBytes { signerCertificate ->
            prepared.signatureTimestampDigest().useOwnedBytes { signatureDigest ->
                AppTrace.qualifiedPdfArchivalStage(QualifiedPdfArchivalStage.SIGNATURE_TIMESTAMP)
                acquireTimestamp(
                    source = timestampSource,
                    digest = signatureDigest,
                    phase = QualifiedPdfTimestampPhase.SIGNATURE,
                ).use { signatureTimestamp ->
                    AppTrace.qualifiedPdfArchivalStage(QualifiedPdfArchivalStage.TIMESTAMPED_SIGNATURE)
                    prepared.completeTimestamped(listOf(signatureTimestamp)).use { timestampedDocument ->
                        AppTrace.qualifiedPdfArchivalStage(QualifiedPdfArchivalStage.VALIDATION_MATERIAL)
                        validationMaterial(
                            source = validationSource,
                            signerCertificate = signerCertificate,
                            signatureTimestamp = signatureTimestamp,
                        ).use { material ->
                            timestampedDocument.copyBytes().useOwnedBytes { timestampedBytes ->
                                AppTrace.qualifiedPdfArchivalStage(
                                    QualifiedPdfArchivalStage.ARCHIVE_PREPARATION,
                                )
                                completeArchiveTimestamp(
                                    timestampedDocument = timestampedBytes,
                                    validationMaterial = material,
                                    timestampSource = timestampSource,
                                )
                            }
                        }
                    }
                }
            }
        }

    private fun completeArchiveTimestamp(
        timestampedDocument: ByteArray,
        validationMaterial: PdfValidationMaterial,
        timestampSource: QualifiedPdfTimestampSource,
    ): SignedPdfDocument =
        PdfArchiveTimestamp
            .prepare(
                timestampedDocument = timestampedDocument,
                validationMaterial = validationMaterial,
            ).use { preparedArchiveTimestamp ->
                preparedArchiveTimestamp.copyDigest().useOwnedBytes { archiveDigest ->
                    AppTrace.qualifiedPdfArchivalStage(QualifiedPdfArchivalStage.ARCHIVE_TIMESTAMP)
                    acquireTimestamp(
                        source = timestampSource,
                        digest = archiveDigest,
                        phase = QualifiedPdfTimestampPhase.ARCHIVE,
                    ).use { archiveTimestamp ->
                        try {
                            preparedArchiveTimestamp.complete(archiveTimestamp)
                        } catch (_: PdfArchiveTimestampException) {
                            throw completionFailure(QualifiedPdfTimestampPhase.ARCHIVE)
                        }
                    }
                }
            }

    private fun acquireTimestamp(
        source: QualifiedPdfTimestampSource,
        digest: ByteArray,
        phase: QualifiedPdfTimestampPhase,
    ): VerifiedTimestampToken {
        val token =
            try {
                source.acquire(digest)
            } catch (_: QualifiedPdfTimestampSourceException) {
                throw completionFailure(phase)
            }
        val matches =
            try {
                token.matchesMessageImprint(digest)
            } catch (_: IllegalStateException) {
                false
            }
        if (!matches) {
            token.close()
            throw completionFailure(phase)
        }
        return token
    }

    private fun validationMaterial(
        source: QualifiedPdfValidationSource,
        signerCertificate: ByteArray,
        signatureTimestamp: VerifiedTimestampToken,
    ): PdfValidationMaterial =
        try {
            source.collect(
                signerCertificate = signerCertificate,
                signatureTimestamp = signatureTimestamp,
            )
        } catch (failure: ValidationMaterialCollectionException) {
            throw CompletionException(
                kind =
                    QualifiedPdfArchivalFailure.Validation(
                        kind = failure.kind,
                        pathRole = failure.pathRole,
                    ),
                cause = failure,
            )
        } catch (_: QualifiedPdfValidationSourceException) {
            throw CompletionException(QualifiedPdfArchivalFailure.ValidationUnavailable)
        }

    private fun completionFailure(phase: QualifiedPdfTimestampPhase): CompletionException =
        CompletionException(QualifiedPdfArchivalFailure.Timestamp(phase))

    private inline fun <T> ByteArray.useOwnedBytes(operation: (ByteArray) -> T): T =
        try {
            operation(this)
        } finally {
            fill(CLEARED_BYTE)
        }

    private class CompletionException(
        val kind: QualifiedPdfArchivalFailure,
        cause: Throwable? = null,
    ) : RuntimeException(null, cause)

    private const val CLEARED_BYTE: Byte = 0
}
