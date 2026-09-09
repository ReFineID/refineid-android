// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedSignature

/** One-use owner of the exact locally verified card-signature stage. */
internal class PreparedQualifiedPdfSignature internal constructor(
    private val ownedPlaceholder: PdfSignaturePlaceholder,
    private val ownedSignedAttributes: ByteArray,
    private val ownedSignature: NativeQualifiedSignature,
    private val ownedSignerCertificate: NativeQualifiedCertificate,
    private val cryptography: QualifiedPdfCryptography,
) : AutoCloseable {
    private var isClosed = false

    val documentLength: Int
        get() {
            requireOpen()
            return ownedPlaceholder.documentLength
        }

    fun signatureTimestampDigest(): ByteArray {
        requireOpen()
        return cryptography.signatureTimestampDigest(ownedSignature)
    }

    fun copySignerCertificate(): ByteArray {
        requireOpen()
        return ownedSignerCertificate.copyDer()
    }

    fun completeBaseline(): SignedPdfDocument =
        complete {
            cryptography.assemble(
                signedAttributes = ownedSignedAttributes,
                signature = ownedSignature,
                signerCertificate = ownedSignerCertificate,
            )
        }

    fun completeTimestamped(timestampTokens: List<VerifiedTimestampToken>): SignedPdfDocument =
        complete {
            cryptography.assembleTimestamped(
                signedAttributes = ownedSignedAttributes,
                signature = ownedSignature,
                signerCertificate = ownedSignerCertificate,
                timestampTokens = timestampTokens,
            )
        }

    override fun close() {
        if (!isClosed) {
            ownedPlaceholder.close()
            ownedSignedAttributes.fill(CLEARED_BYTE)
            ownedSignature.close()
            ownedSignerCertificate.close()
            isClosed = true
        }
    }

    override fun toString(): String =
        "PreparedQualifiedPdfSignature(profile=" + ownedSignerCertificate.keyProfile +
            ", closed=" + isClosed + ")"

    private fun complete(assemble: () -> ByteArray): SignedPdfDocument {
        requireOpen()
        val cms = assemble()
        return try {
            SignedPdfDocument(ownedPlaceholder.filledWith(cms)).also { close() }
        } finally {
            cms.fill(CLEARED_BYTE)
        }
    }

    private fun requireOpen() {
        check(!isClosed) {
            "prepared qualified PDF signature is closed"
        }
    }

    private companion object {
        const val CLEARED_BYTE: Byte = 0
    }
}
