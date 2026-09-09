// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class OcspRequestTest {
    @Test
    fun encodesExactCertificateIdentityAndDoubleWrappedNonce() {
        val issuerName = SYNTHETIC_ISSUER_NAME_TEXT.encodeToByteArray()
        val issuerKey = SYNTHETIC_ISSUER_KEY_TEXT.encodeToByteArray()
        val serialNumber =
            byteArrayOf(
                POSITIVE_INTEGER_PREFIX,
                SERIAL_NUMBER_HIGH_BYTE,
                SERIAL_NUMBER_LOW_BYTE,
            )
        val nonce = ByteArray(OcspRequest.NONCE_BYTE_COUNT) { NONCE_FILL_BYTE }
        val request =
            OcspRequest.encoded(
                issuerName = issuerName,
                issuerKeyBits = issuerKey,
                serialNumber = serialNumber,
                nonce = nonce,
            )
        val issuerNameHash = MessageDigest.getInstance(SHA1_JAVA_NAME).digest(issuerName)
        val issuerKeyHash = MessageDigest.getInstance(SHA1_JAVA_NAME).digest(issuerKey)
        try {
            assertEquals(RECOMMENDED_NONCE_BYTE_COUNT, OcspRequest.NONCE_BYTE_COUNT)
            assertTrue(request.contains(DerEncoder.octetString(issuerNameHash)))
            assertTrue(request.contains(DerEncoder.octetString(issuerKeyHash)))
            assertTrue(request.contains(DerEncoder.tlv(DerValues.TAG_INTEGER, serialNumber)))
            assertTrue(request.contains(DerEncoder.octetString(DerEncoder.octetString(nonce))))
        } finally {
            issuerName.fill(ZERO_BYTE)
            issuerKey.fill(ZERO_BYTE)
            serialNumber.fill(ZERO_BYTE)
            nonce.fill(ZERO_BYTE)
            request.fill(ZERO_BYTE)
            issuerNameHash.fill(ZERO_BYTE)
            issuerKeyHash.fill(ZERO_BYTE)
        }
    }

    @Test
    fun rejectsNonCanonicalSerialAndWrongNonceLength() {
        val identity = SYNTHETIC_ISSUER_NAME_TEXT.encodeToByteArray()
        val nonce = ByteArray(OcspRequest.NONCE_BYTE_COUNT) { NONCE_FILL_BYTE }
        val shortNonce = ByteArray(OcspRequest.NONCE_BYTE_COUNT - MISSING_NONCE_BYTE_COUNT)
        val negativeSerial = byteArrayOf(NEGATIVE_INTEGER_BYTE)
        try {
            assertThrows(IllegalArgumentException::class.java) {
                OcspRequest.encoded(identity, identity, negativeSerial, nonce)
            }
            assertThrows(IllegalArgumentException::class.java) {
                OcspRequest.encoded(identity, identity, VALID_SERIAL_NUMBER, shortNonce)
            }
        } finally {
            identity.fill(ZERO_BYTE)
            nonce.fill(ZERO_BYTE)
            shortNonce.fill(ZERO_BYTE)
            negativeSerial.fill(ZERO_BYTE)
        }
    }

    private fun ByteArray.contains(expected: ByteArray): Boolean {
        if (expected.isEmpty() || expected.size > size) {
            return false
        }
        return indices
            .asSequence()
            .take(size - expected.size + LAST_MATCH_OFFSET)
            .any { start ->
                expected.indices.all { relative -> this[start + relative] == expected[relative] }
            }
    }

    private companion object {
        const val RECOMMENDED_NONCE_BYTE_COUNT = 32
        const val MISSING_NONCE_BYTE_COUNT = 1
        const val LAST_MATCH_OFFSET = 1
        const val SYNTHETIC_ISSUER_NAME_TEXT = "encoded issuer name"
        const val SYNTHETIC_ISSUER_KEY_TEXT = "subject public key bits"
        const val SHA1_JAVA_NAME = "SHA-1"
        const val POSITIVE_INTEGER_PREFIX: Byte = 0
        const val SERIAL_NUMBER_HIGH_BYTE: Byte = -128
        const val SERIAL_NUMBER_LOW_BYTE: Byte = -95
        const val NONCE_FILL_BYTE: Byte = 0x5A
        const val NEGATIVE_INTEGER_BYTE: Byte = -1
        const val VALID_SERIAL_NUMBER_BYTE: Byte = 0x21
        const val ZERO_BYTE: Byte = 0

        val VALID_SERIAL_NUMBER = byteArrayOf(VALID_SERIAL_NUMBER_BYTE)
    }
}
