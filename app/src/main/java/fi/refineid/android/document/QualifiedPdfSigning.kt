// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.QualifiedSignFailure

internal sealed interface QualifiedPdfSigningFailure {
    data class Document(
        val kind: PdfSigningFailure,
    ) : QualifiedPdfSigningFailure

    data class Certificate(
        val kind: NativeCertificateReadFailure,
    ) : QualifiedPdfSigningFailure

    data object KeyProfileUnsupported : QualifiedPdfSigningFailure

    data class Card(
        val kind: QualifiedSignFailure,
    ) : QualifiedPdfSigningFailure

    data class Cms(
        val kind: QualifiedDocumentCmsFailure,
    ) : QualifiedPdfSigningFailure

    data object InternalError : QualifiedPdfSigningFailure
}

internal sealed interface QualifiedPdfSigningResult {
    class Success(
        val document: SignedPdfDocument,
    ) : QualifiedPdfSigningResult {
        override fun toString(): String = "Success(" + document + ")"
    }

    data class Failure(
        val kind: QualifiedPdfSigningFailure,
    ) : QualifiedPdfSigningResult
}

internal sealed interface QualifiedPdfPreparationResult {
    class Success(
        val prepared: PreparedQualifiedPdfSignature,
    ) : QualifiedPdfPreparationResult {
        override fun toString(): String = "Success(" + prepared + ")"
    }

    data class Failure(
        val kind: QualifiedPdfSigningFailure,
    ) : QualifiedPdfPreparationResult
}

/** Mutable signed-document bytes owned by one result and cleared when released. */
internal class SignedPdfDocument(
    private val ownedBytes: ByteArray,
) : AutoCloseable {
    private var isClosed = false

    val length: Int
        get() = ownedBytes.size

    fun <T> useBytes(operation: (ByteArray) -> T): T {
        check(!isClosed) {
            "signed PDF is closed"
        }
        return operation(ownedBytes)
    }

    fun copyBytes(): ByteArray = useBytes(ByteArray::copyOf)

    override fun close() {
        if (!isClosed) {
            ownedBytes.fill(ZERO_BYTE)
            isClosed = true
        }
    }

    override fun toString(): String = "SignedPdfDocument(length=" + length + ", closed=" + isClosed + ")"

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}
