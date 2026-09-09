package fi.refineid.android.document

import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class Rfc3161TimestampTest {
    @Test
    fun requestCarriesCanonicalSha384ImprintNonceAndCertificateRequest() {
        val request =
            Rfc3161Timestamp.request(
                digest = SYNTHETIC_DIGEST,
                nonce = SYNTHETIC_NONCE,
            )

        assertTrue(request.containsEncoding(DerEncoder.octetString(SYNTHETIC_DIGEST)))
        assertTrue(request.containsEncoding(DerEncoder.unsignedInteger(SYNTHETIC_NONCE)))
        assertTrue(request.containsEncoding(DerEncoder.objectIdentifier(QualifiedCmsOids.SHA384)))
        assertTrue(request.endsWith(DerEncoder.booleanTrue()))

        assertFailure(Rfc3161TimestampFailure.REQUEST_MALFORMED) {
            Rfc3161Timestamp.request(
                digest = ByteArray(SHA384_DIGEST_LENGTH_BYTES - SINGLE_BYTE_COUNT),
                nonce = SYNTHETIC_NONCE,
            )
        }
        assertFailure(Rfc3161TimestampFailure.REQUEST_MALFORMED) {
            Rfc3161Timestamp.request(
                digest = SYNTHETIC_DIGEST,
                nonce = byteArrayOf(),
            )
        }
        assertFailure(Rfc3161TimestampFailure.REQUEST_MALFORMED) {
            Rfc3161Timestamp.request(
                digest = SYNTHETIC_DIGEST,
                nonce = ByteArray(OVERLIMIT_NONCE_BYTES),
            )
        }
    }

    @Test
    fun matchingGrantedResponseReturnsItsTokenAndRequestBoundClaimTime() {
        for (status in GRANTED_STATUSES) {
            val fixture = response(status = status, time = FRACTIONAL_GENERALIZED_TIME)
            val token =
                Rfc3161Timestamp.token(
                    response = fixture.response,
                    digest = SYNTHETIC_DIGEST,
                    nonce = SYNTHETIC_NONCE,
                )
            try {
                assertArrayEquals(fixture.token, token.copyEncoding())
                assertEquals(EXPECTED_GENERATION_INSTANT, token.generatedAt)
                assertFalse(token.toString().contains(fixture.token.toString(Charsets.ISO_8859_1)))
            } finally {
                token.close()
            }
        }
    }

    @Test
    fun orderedOptionalFieldsAreAcceptedAndTheirMalformedFormsAreRefused() {
        val optionals =
            listOf(
                accuracy(seconds = ACCURACY_SECONDS),
                DerEncoder.booleanTrue(),
                DerEncoder.unsignedInteger(SYNTHETIC_NONCE),
                tsaName(),
                timestampExtensions(),
            )
        Rfc3161Timestamp
            .token(
                response = response(includeNonce = false, optionals = optionals).response,
                digest = SYNTHETIC_DIGEST,
                nonce = SYNTHETIC_NONCE,
            ).close()

        val malformedOptionals =
            listOf(
                listOf(accuracy(seconds = INVALID_ACCURACY_SECONDS)),
                listOf(DerEncoder.tlv(DerValues.TAG_BOOLEAN, byteArrayOf(DerValues.DER_FALSE_BYTE))),
                listOf(
                    DerEncoder.unsignedInteger(SYNTHETIC_NONCE),
                    DerEncoder.unsignedInteger(SYNTHETIC_NONCE),
                ),
                listOf(tsaName(), DerEncoder.unsignedInteger(SYNTHETIC_NONCE)),
                listOf(DerEncoder.nullValue()),
            )
        for (malformed in malformedOptionals) {
            assertFailure(Rfc3161TimestampFailure.RESPONSE_MALFORMED) {
                Rfc3161Timestamp.token(
                    response = response(includeNonce = false, optionals = malformed).response,
                    digest = SYNTHETIC_DIGEST,
                    nonce = SYNTHETIC_NONCE,
                )
            }
        }
    }

    @Test
    fun imprintAlgorithmDigestAndNonceMustMatchTheRequest() {
        assertFailure(Rfc3161TimestampFailure.IMPRINT_ALGORITHM_MISMATCH) {
            Rfc3161Timestamp.token(
                response = response(imprintAlgorithm = SHA256_OID).response,
                digest = SYNTHETIC_DIGEST,
                nonce = SYNTHETIC_NONCE,
            )
        }
        assertFailure(Rfc3161TimestampFailure.IMPRINT_MISMATCH) {
            Rfc3161Timestamp.token(
                response = response(digest = ALTERNATE_DIGEST).response,
                digest = SYNTHETIC_DIGEST,
                nonce = SYNTHETIC_NONCE,
            )
        }
        assertFailure(Rfc3161TimestampFailure.IMPRINT_MISMATCH) {
            Rfc3161Timestamp.token(
                response = response(digest = SHORT_DIGEST).response,
                digest = SYNTHETIC_DIGEST,
                nonce = SYNTHETIC_NONCE,
            )
        }
        assertFailure(Rfc3161TimestampFailure.NONCE_MISMATCH) {
            Rfc3161Timestamp.token(
                response = response(includeNonce = false).response,
                digest = SYNTHETIC_DIGEST,
                nonce = SYNTHETIC_NONCE,
            )
        }
        assertFailure(Rfc3161TimestampFailure.NONCE_MISMATCH) {
            Rfc3161Timestamp.token(
                response = response(nonce = ALTERNATE_NONCE).response,
                digest = SYNTHETIC_DIGEST,
                nonce = SYNTHETIC_NONCE,
            )
        }
    }

    @Test
    fun malformedTimesTrailingBytesAndOversizedResponsesAreRefused() {
        for (time in MALFORMED_GENERALIZED_TIMES) {
            assertFailure(Rfc3161TimestampFailure.RESPONSE_MALFORMED) {
                Rfc3161Timestamp.token(
                    response = response(time = time).response,
                    digest = SYNTHETIC_DIGEST,
                    nonce = SYNTHETIC_NONCE,
                )
            }
        }

        val trailing = response().response + byteArrayOf(TRAILING_BYTE)
        assertFailure(Rfc3161TimestampFailure.RESPONSE_MALFORMED) {
            Rfc3161Timestamp.token(
                response = trailing,
                digest = SYNTHETIC_DIGEST,
                nonce = SYNTHETIC_NONCE,
            )
        }
        assertFailure(Rfc3161TimestampFailure.RESPONSE_UNUSABLE) {
            Rfc3161Timestamp.token(
                response = ByteArray(OVERLIMIT_RESPONSE_BYTES),
                digest = SYNTHETIC_DIGEST,
                nonce = SYNTHETIC_NONCE,
            )
        }
    }

    @Test
    fun refusalAndGrantedResponseWithoutTokenStayDistinct() {
        val rejected = response(status = REJECTED_STATUS, includeToken = false).response
        val rejection =
            assertFailure(Rfc3161TimestampFailure.REJECTED) {
                Rfc3161Timestamp.token(
                    response = rejected,
                    digest = SYNTHETIC_DIGEST,
                    nonce = SYNTHETIC_NONCE,
                )
            }
        assertEquals(REJECTED_STATUS.toLong(), rejection.rejectedStatus)

        assertFailure(Rfc3161TimestampFailure.TOKEN_MISSING) {
            Rfc3161Timestamp.token(
                response = response(includeToken = false).response,
                digest = SYNTHETIC_DIGEST,
                nonce = SYNTHETIC_NONCE,
            )
        }
    }

    @Test
    fun unverifiedTokenOwnsAndClearsItsEncoding() {
        val fixture = response()
        val token =
            Rfc3161Timestamp.token(
                response = fixture.response,
                digest = SYNTHETIC_DIGEST,
                nonce = SYNTHETIC_NONCE,
            )
        var owned: ByteArray? = null
        token.useEncoding { encoding -> owned = encoding }

        token.close()

        assertTrue(checkNotNull(owned).all { byte -> byte == ZERO_BYTE })
        assertThrows(IllegalStateException::class.java, token::copyEncoding)
    }

    private fun response(
        status: Int = GRANTED_STATUS,
        imprintAlgorithm: String = QualifiedCmsOids.SHA384,
        digest: ByteArray = SYNTHETIC_DIGEST,
        nonce: ByteArray = SYNTHETIC_NONCE,
        includeNonce: Boolean = true,
        optionals: List<ByteArray> = emptyList(),
        time: String = WHOLE_SECOND_GENERALIZED_TIME,
        includeToken: Boolean = true,
    ): TimestampFixture {
        val timestampFields =
            mutableListOf(
                DerEncoder.integer(TST_INFO_VERSION),
                DerEncoder.objectIdentifier(SYNTHETIC_POLICY_OID),
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.sequence(
                            listOf(
                                DerEncoder.objectIdentifier(imprintAlgorithm),
                                DerEncoder.nullValue(),
                            ),
                        ),
                        DerEncoder.octetString(digest),
                    ),
                ),
                DerEncoder.integer(SYNTHETIC_SERIAL_NUMBER),
                DerEncoder.tlv(
                    tag = DerValues.TAG_GENERALIZED_TIME,
                    content = time.encodeToByteArray(),
                ),
            )
        if (includeNonce) {
            timestampFields += DerEncoder.unsignedInteger(nonce)
        }
        timestampFields += optionals
        val timestampInformation = DerEncoder.sequence(timestampFields)
        val encapsulated =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.objectIdentifier(Rfc3161Oids.TST_INFO),
                    DerEncoder.tlv(
                        tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                        content = DerEncoder.octetString(timestampInformation),
                    ),
                ),
            )
        val signedData =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.integer(TIMESTAMP_CMS_VERSION),
                    DerEncoder.setOf(
                        listOf(
                            DerEncoder.sequence(
                                listOf(DerEncoder.objectIdentifier(imprintAlgorithm)),
                            ),
                        ),
                    ),
                    encapsulated,
                    DerEncoder.setOf(emptyList()),
                ),
            )
        val token =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.objectIdentifier(QualifiedCmsOids.SIGNED_DATA),
                    DerEncoder.tlv(
                        tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                        content = signedData,
                    ),
                ),
            )
        val responseFields = mutableListOf(DerEncoder.sequence(listOf(DerEncoder.integer(status))))
        if (includeToken) {
            responseFields += token
        }
        return TimestampFixture(
            response = DerEncoder.sequence(responseFields),
            token = token,
        )
    }

    private fun accuracy(seconds: Int): ByteArray =
        DerEncoder.sequence(
            listOf(
                DerEncoder.integer(seconds),
                DerEncoder.retagged(
                    encoded = DerEncoder.integer(ACCURACY_MILLISECONDS),
                    tag = DerValues.TAG_CONTEXT_0_PRIMITIVE,
                ),
                DerEncoder.retagged(
                    encoded = DerEncoder.integer(ACCURACY_MICROSECONDS),
                    tag = DerValues.TAG_CONTEXT_1_PRIMITIVE,
                ),
            ),
        )

    private fun tsaName(): ByteArray =
        DerEncoder.tlv(
            tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
            content =
                DerEncoder.tlv(
                    tag = DerValues.TAG_CONTEXT_1_PRIMITIVE,
                    content = SYNTHETIC_TSA_MAILBOX.encodeToByteArray(),
                ),
        )

    private fun timestampExtensions(): ByteArray {
        val extension =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.objectIdentifier(SYNTHETIC_EXTENSION_OID),
                    DerEncoder.tlv(
                        tag = DerValues.TAG_BOOLEAN,
                        content = byteArrayOf(DerValues.DER_FALSE_BYTE),
                    ),
                    DerEncoder.octetString(SYNTHETIC_EXTENSION_VALUE),
                ),
            )
        return DerEncoder.tlv(
            tag = DerValues.TAG_CONTEXT_1_CONSTRUCTED,
            content = extension,
        )
    }

    private fun assertFailure(
        expected: Rfc3161TimestampFailure,
        operation: () -> Unit,
    ): Rfc3161TimestampException {
        val failure =
            assertThrows(Rfc3161TimestampException::class.java) {
                operation()
            }
        assertEquals(expected, failure.kind)
        return failure
    }

    private fun ByteArray.containsEncoding(expected: ByteArray): Boolean {
        if (expected.size > size) {
            return false
        }
        return indices.any { start ->
            start <= size - expected.size &&
                expected.indices.all { offset -> this[start + offset] == expected[offset] }
        }
    }

    private fun ByteArray.endsWith(expected: ByteArray): Boolean =
        expected.size <= size &&
            expected.indices.all { offset ->
                this[size - expected.size + offset] == expected[offset]
            }

    private data class TimestampFixture(
        val response: ByteArray,
        val token: ByteArray,
    )

    private companion object {
        const val SHA256_OID = "2.16.840.1.101.3.4.2.1"
        const val SYNTHETIC_POLICY_OID = "1.2.3.4"
        const val SYNTHETIC_EXTENSION_OID = "1.2.3.5"
        const val SYNTHETIC_TSA_MAILBOX = "tsa@example.invalid"
        const val WHOLE_SECOND_GENERALIZED_TIME = "20260804074633Z"
        const val FRACTIONAL_GENERALIZED_TIME = "20260804074633.125Z"
        const val INVALID_MONTH_GENERALIZED_TIME = "20261304074633Z"
        const val OVERPRECISE_GENERALIZED_TIME = "20260804074633.1234567891Z"
        const val NON_CANONICAL_FRACTION_GENERALIZED_TIME = "20260804074633.120Z"
        const val GRANTED_STATUS = 0
        const val GRANTED_WITH_MODIFICATIONS_STATUS = 1
        const val REJECTED_STATUS = 2
        const val TST_INFO_VERSION = 1
        const val TIMESTAMP_CMS_VERSION = 3
        const val SYNTHETIC_SERIAL_NUMBER = 7
        const val ACCURACY_SECONDS = 1
        const val INVALID_ACCURACY_SECONDS = 0
        const val ACCURACY_MILLISECONDS = 250
        const val ACCURACY_MICROSECONDS = 125
        const val SINGLE_BYTE_COUNT = 1
        const val MAXIMUM_NONCE_BYTES = 64
        const val OVERLIMIT_NONCE_BYTES = MAXIMUM_NONCE_BYTES + SINGLE_BYTE_COUNT
        const val MAXIMUM_RESPONSE_BYTES = 65_536
        const val OVERLIMIT_RESPONSE_BYTES = MAXIMUM_RESPONSE_BYTES + SINGLE_BYTE_COUNT
        const val TRAILING_BYTE: Byte = 0
        const val SYNTHETIC_DIGEST_FILL: Byte = 0x5A
        const val ALTERNATE_DIGEST_FILL: Byte = 0x31
        const val SHORT_DIGEST_BYTES = 32
        const val ZERO_BYTE: Byte = 0
        val EXPECTED_GENERATION_INSTANT: Instant = Instant.parse("2026-08-04T07:46:33.125Z")
        val GRANTED_STATUSES = listOf(GRANTED_STATUS, GRANTED_WITH_MODIFICATIONS_STATUS)
        val MALFORMED_GENERALIZED_TIMES =
            listOf(
                INVALID_MONTH_GENERALIZED_TIME,
                OVERPRECISE_GENERALIZED_TIME,
                NON_CANONICAL_FRACTION_GENERALIZED_TIME,
            )
        val SYNTHETIC_DIGEST = ByteArray(SHA384_DIGEST_LENGTH_BYTES) { SYNTHETIC_DIGEST_FILL }
        val ALTERNATE_DIGEST = ByteArray(SHA384_DIGEST_LENGTH_BYTES) { ALTERNATE_DIGEST_FILL }
        val SHORT_DIGEST = ByteArray(SHORT_DIGEST_BYTES) { SYNTHETIC_DIGEST_FILL }
        val SYNTHETIC_NONCE =
            byteArrayOf(
                0x00,
                0x80.toByte(),
                0x21,
                0x43,
                0x65,
            )
        val ALTERNATE_NONCE =
            byteArrayOf(
                0x01,
                0x02,
                0x03,
            )
        val SYNTHETIC_EXTENSION_VALUE = byteArrayOf(0x01)
    }
}
