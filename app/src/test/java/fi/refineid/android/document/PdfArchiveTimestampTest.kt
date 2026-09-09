// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class PdfArchiveTimestampTest {
    @Test
    fun appendsDssBeforeCompletingExactDocumentTimestamp() {
        val original = PdfTestDocuments.minimalClassic().document
        validationMaterial().use { material ->
            PdfArchiveTimestamp.prepare(original, material).use { prepared ->
                val digest = prepared.copyDigest()
                try {
                    assertEquals(SHA384_DIGEST_LENGTH_BYTES, digest.size)
                    verifiedToken(digest).use { token ->
                        val archived = prepared.complete(token)
                        try {
                            archived.useBytes { document ->
                                assertTrue(
                                    document.copyOfRange(FIRST_DOCUMENT_OFFSET, original.size).contentEquals(original),
                                )
                                val text = document.toString(Charsets.ISO_8859_1)
                                val validationStoreOffset = text.indexOf(VALIDATION_STORE_TYPE)
                                val timestampOffset = text.indexOf(DOCUMENT_TIMESTAMP_TYPE)
                                assertTrue(validationStoreOffset >= FIRST_DOCUMENT_OFFSET)
                                assertTrue(timestampOffset > validationStoreOffset)
                                assertTrue(text.contains(SYNTHETIC_TOKEN_HEX))
                            }
                        } finally {
                            archived.close()
                        }
                        assertThrows(IllegalStateException::class.java) {
                            archived.copyBytes().fill(ZERO_BYTE)
                        }
                    }
                    assertThrows(IllegalStateException::class.java) {
                        prepared.copyDigest().fill(ZERO_BYTE)
                    }
                } finally {
                    digest.fill(ZERO_BYTE)
                }
            }
        }
    }

    @Test
    fun rejectsAnotherImprintWithoutConsumingPreparation() {
        val original = PdfTestDocuments.minimalClassic().document
        validationMaterial().use { material ->
            PdfArchiveTimestamp.prepare(original, material).use { prepared ->
                val digest = prepared.copyDigest()
                val anotherDigest = digest.copyOf()
                anotherDigest[anotherDigest.lastIndex] =
                    (anotherDigest.last().toInt() xor DIFFERENT_DIGEST_BIT).toByte()
                try {
                    verifiedToken(anotherDigest).use { wrongToken ->
                        val failure =
                            assertThrows(PdfArchiveTimestampException::class.java) {
                                prepared.complete(wrongToken).close()
                            }
                        assertEquals(PdfArchiveTimestampFailure.TOKEN_IMPRINT_MISMATCH, failure.kind)
                    }
                    val stillPrepared = prepared.copyDigest()
                    try {
                        assertTrue(stillPrepared.contentEquals(digest))
                    } finally {
                        stillPrepared.fill(ZERO_BYTE)
                    }
                    verifiedToken(digest).use { correctToken ->
                        prepared.complete(correctToken).close()
                    }
                } finally {
                    digest.fill(ZERO_BYTE)
                    anotherDigest.fill(ZERO_BYTE)
                }
            }
        }
    }

    private fun validationMaterial(): PdfValidationMaterial =
        PdfValidationMaterial.copyOf(
            certificates = listOf(byteArrayOf(SYNTHETIC_CERTIFICATE_MARKER)),
            ocspResponses = listOf(byteArrayOf(SYNTHETIC_OCSP_MARKER)),
            revocationLists = listOf(byteArrayOf(SYNTHETIC_CRL_MARKER)),
        )

    private fun verifiedToken(imprint: ByteArray): VerifiedTimestampToken =
        VerifiedTimestampToken(
            ownedEncoding = SYNTHETIC_TOKEN.copyOf(),
            ownedMessageImprint = imprint.copyOf(),
            ownedSignerCertificate = byteArrayOf(SYNTHETIC_SIGNER_CERTIFICATE_MARKER),
            ownedEmbeddedCertificates = emptyList(),
            ownedCertificatePath =
                VerifiedTimestampCertificatePath(
                    ownedCertificates = emptyList(),
                    ownedTrustAnchor = byteArrayOf(SYNTHETIC_TRUST_ANCHOR_MARKER),
                ),
            generatedAt = TOKEN_GENERATION_TIME,
        )

    private companion object {
        const val FIRST_DOCUMENT_OFFSET = 0
        const val DIFFERENT_DIGEST_BIT = 1
        const val SYNTHETIC_CERTIFICATE_MARKER: Byte = 0x31
        const val SYNTHETIC_OCSP_MARKER: Byte = 0x32
        const val SYNTHETIC_CRL_MARKER: Byte = 0x33
        const val SYNTHETIC_SIGNER_CERTIFICATE_MARKER: Byte = 0x34
        const val SYNTHETIC_TRUST_ANCHOR_MARKER: Byte = 0x35
        const val ZERO_BYTE: Byte = 0
        const val VALIDATION_STORE_TYPE = "/Type /DSS"
        const val DOCUMENT_TIMESTAMP_TYPE = "/Type /DocTimeStamp"
        const val SYNTHETIC_TOKEN_HEX = "3003020101"
        val SYNTHETIC_TOKEN = DerEncoder.sequence(listOf(DerEncoder.integer(1)))
        val TOKEN_GENERATION_TIME: Instant = Instant.parse("2026-08-15T12:00:00Z")
    }
}
