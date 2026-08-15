// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

internal enum class PdfArchiveTimestampFailure {
    TOKEN_IMPRINT_MISMATCH,
}

internal class PdfArchiveTimestampException(
    val kind: PdfArchiveTimestampFailure,
) : Exception(kind.name)

/** A DSS revision followed by a prepared whole-document RFC 3161 timestamp revision. */
internal object PdfArchiveTimestamp {
    fun prepare(
        timestampedDocument: ByteArray,
        validationMaterial: PdfValidationMaterial,
    ): PreparedPdfArchiveTimestamp {
        val withValidationMaterial =
            PdfValidationStore.append(
                document = timestampedDocument,
                material = validationMaterial,
            )
        var placeholder: PdfSignaturePlaceholder? = null
        try {
            placeholder =
                PdfIncrementalSigner.prepare(
                    document = withValidationMaterial,
                    revision = PdfSignatureRevision.DocumentTimestamp,
                )
            val digest = placeholder.digest()
            return PreparedPdfArchiveTimestamp(
                ownedPlaceholder = placeholder,
                ownedDigest = digest,
            ).also {
                placeholder = null
            }
        } finally {
            placeholder?.close()
            withValidationMaterial.fill(CLEARED_BYTE)
        }
    }

    private const val CLEARED_BYTE: Byte = 0
}

/** One-use request boundary that accepts only a verified token for its exact PDF digest. */
internal class PreparedPdfArchiveTimestamp internal constructor(
    private val ownedPlaceholder: PdfSignaturePlaceholder,
    private val ownedDigest: ByteArray,
) : AutoCloseable {
    private var isClosed = false

    val documentLength: Int
        get() {
            requireOpen()
            return ownedPlaceholder.documentLength
        }

    fun copyDigest(): ByteArray {
        requireOpen()
        return ownedDigest.copyOf()
    }

    fun complete(token: VerifiedTimestampToken): SignedPdfDocument {
        requireOpen()
        if (!token.matchesMessageImprint(ownedDigest)) {
            throw PdfArchiveTimestampException(PdfArchiveTimestampFailure.TOKEN_IMPRINT_MISMATCH)
        }
        val encoded = token.copyEncoding()
        return try {
            val document = ownedPlaceholder.filledWith(encoded)
            close()
            SignedPdfDocument(document)
        } finally {
            encoded.fill(CLEARED_BYTE)
        }
    }

    override fun close() {
        if (!isClosed) {
            ownedDigest.fill(CLEARED_BYTE)
            ownedPlaceholder.close()
            isClosed = true
        }
    }

    override fun toString(): String = "PreparedPdfArchiveTimestamp(closed=" + isClosed + ")"

    private fun requireOpen() {
        check(!isClosed) {
            "prepared PDF archive timestamp is closed"
        }
    }

    private companion object {
        const val CLEARED_BYTE: Byte = 0
    }
}
