package fi.refineid.android.document

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

class TimestampCmsAlgorithmsTest {
    @Test
    fun acceptsSupportedSha2DigestIdentifiersWithAbsentOrNullParameters() {
        for (digest in TimestampCmsDigest.entries) {
            assertEquals(digest, TimestampCmsAlgorithmParser.digest(digestIdentifier(digest)))
            assertEquals(digest, TimestampCmsAlgorithmParser.digest(digestIdentifier(digest, includeNull = true)))
            assertEquals(digest.byteCount, digest.digest(SYNTHETIC_CONTENT).size)
        }
    }

    @Test
    fun acceptsMatchingEcdsaRsaPkcs1AndExplicitRsaPssIdentifiers() {
        for (digest in TimestampCmsDigest.entries) {
            assertNotNull(
                TimestampCmsAlgorithmParser.signature(
                    encoded = signatureIdentifier(ecdsaIdentifier(digest), parameters = null),
                    digest = digest,
                ),
            )
            assertNotNull(
                TimestampCmsAlgorithmParser.signature(
                    encoded = signatureIdentifier(rsaPkcs1Identifier(digest), DerEncoder.nullValue()),
                    digest = digest,
                ),
            )
            assertNotNull(
                TimestampCmsAlgorithmParser.signature(
                    encoded = signatureIdentifier(TimestampCmsOids.RSA_ENCRYPTION, DerEncoder.nullValue()),
                    digest = digest,
                ),
            )
            assertNotNull(
                TimestampCmsAlgorithmParser.signature(
                    encoded = signatureIdentifier(TimestampCmsOids.RSA_PSS, pssParameters(digest)),
                    digest = digest,
                ),
            )
        }
    }

    @Test
    fun rejectsUnknownMismatchedAndAmbiguousAlgorithmParameters() {
        assertFailure(TimestampTokenVerificationFailure.INVALID_SIGNATURE) {
            TimestampCmsAlgorithmParser.digest(
                DerEncoder.sequence(listOf(DerEncoder.objectIdentifier(UNSUPPORTED_DIGEST_OID))),
            )
        }
        assertFailure(TimestampTokenVerificationFailure.INVALID_SIGNATURE) {
            TimestampCmsAlgorithmParser.signature(
                encoded =
                    signatureIdentifier(
                        rsaPkcs1Identifier(TimestampCmsDigest.SHA384),
                        DerEncoder.nullValue(),
                    ),
                digest = TimestampCmsDigest.SHA256,
            )
        }
        assertFailure(TimestampTokenVerificationFailure.INVALID_SIGNATURE) {
            TimestampCmsAlgorithmParser.signature(
                encoded = signatureIdentifier(TimestampCmsOids.RSA_ENCRYPTION, parameters = null),
                digest = TimestampCmsDigest.SHA384,
            )
        }
        assertFailure(TimestampTokenVerificationFailure.INVALID_SIGNATURE) {
            TimestampCmsAlgorithmParser.signature(
                encoded =
                    signatureIdentifier(
                        TimestampCmsOids.RSA_PSS,
                        pssParameters(
                            digest = TimestampCmsDigest.SHA384,
                            saltLength =
                                TimestampCmsDigest.SHA384.byteCount +
                                    INVALID_PSS_SALT_LENGTH_INCREMENT,
                        ),
                    ),
                digest = TimestampCmsDigest.SHA384,
            )
        }
    }

    @Test
    fun parsedRsaPssParametersVerifyARealSignature() {
        val digest = TimestampCmsDigest.SHA384
        val keyPair =
            KeyPairGenerator
                .getInstance(RSA_KEY_ALGORITHM)
                .apply { initialize(TEST_RSA_KEY_LENGTH_BITS) }
                .generateKeyPair()
        val parameters =
            PSSParameterSpec(
                digest.javaName,
                MASK_GENERATION_FUNCTION_NAME,
                MGF1ParameterSpec.SHA384,
                digest.byteCount,
                PSS_TRAILER_FIELD,
            )
        val signature =
            Signature
                .getInstance(RSA_PSS_JAVA_NAME)
                .apply {
                    setParameter(parameters)
                    initSign(keyPair.private)
                    update(SYNTHETIC_CONTENT)
                }.sign()
        val parsed =
            TimestampCmsAlgorithmParser.signature(
                encoded = signatureIdentifier(TimestampCmsOids.RSA_PSS, pssParameters(digest)),
                digest = digest,
            )
        try {
            assertTrue(
                parsed
                    .verifier()
                    .apply {
                        initVerify(keyPair.public)
                        update(SYNTHETIC_CONTENT)
                    }.verify(signature),
            )
        } finally {
            signature.fill(ZERO_BYTE)
        }
    }

    private fun digestIdentifier(
        digest: TimestampCmsDigest,
        includeNull: Boolean = false,
    ): ByteArray =
        DerEncoder.sequence(
            buildList {
                add(DerEncoder.objectIdentifier(digest.objectIdentifier))
                if (includeNull) {
                    add(DerEncoder.nullValue())
                }
            },
        )

    private fun signatureIdentifier(
        identifier: String,
        parameters: ByteArray?,
    ): ByteArray =
        DerEncoder.sequence(
            buildList {
                add(DerEncoder.objectIdentifier(identifier))
                parameters?.let(::add)
            },
        )

    private fun pssParameters(
        digest: TimestampCmsDigest,
        saltLength: Int = digest.byteCount,
    ): ByteArray =
        DerEncoder.sequence(
            listOf(
                DerEncoder.tlv(
                    tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                    content = digestIdentifier(digest),
                ),
                DerEncoder.tlv(
                    tag = DerValues.TAG_CONTEXT_1_CONSTRUCTED,
                    content =
                        DerEncoder.sequence(
                            listOf(
                                DerEncoder.objectIdentifier(TimestampCmsOids.MASK_GENERATION_FUNCTION_1),
                                digestIdentifier(digest),
                            ),
                        ),
                ),
                DerEncoder.tlv(
                    tag = DerValues.TAG_CONTEXT_2_CONSTRUCTED,
                    content = DerEncoder.integer(saltLength),
                ),
            ),
        )

    private fun ecdsaIdentifier(digest: TimestampCmsDigest): String =
        when (digest) {
            TimestampCmsDigest.SHA256 -> TimestampCmsOids.ECDSA_WITH_SHA256
            TimestampCmsDigest.SHA384 -> QualifiedCmsOids.ECDSA_WITH_SHA384
            TimestampCmsDigest.SHA512 -> TimestampCmsOids.ECDSA_WITH_SHA512
        }

    private fun rsaPkcs1Identifier(digest: TimestampCmsDigest): String =
        when (digest) {
            TimestampCmsDigest.SHA256 -> TimestampCmsOids.SHA256_WITH_RSA
            TimestampCmsDigest.SHA384 -> QualifiedCmsOids.SHA384_WITH_RSA
            TimestampCmsDigest.SHA512 -> TimestampCmsOids.SHA512_WITH_RSA
        }

    private fun assertFailure(
        expected: TimestampTokenVerificationFailure,
        operation: () -> Unit,
    ) {
        val failure =
            assertThrows(TimestampTokenVerificationException::class.java) {
                operation()
            }
        assertEquals(expected, failure.kind)
    }

    private companion object {
        const val UNSUPPORTED_DIGEST_OID = "1.2.3.4.9"
        const val INVALID_PSS_SALT_LENGTH_INCREMENT = 1
        const val TEST_RSA_KEY_LENGTH_BITS = 2_048
        const val PSS_TRAILER_FIELD = 1
        const val RSA_KEY_ALGORITHM = "RSA"
        const val RSA_PSS_JAVA_NAME = "RSASSA-PSS"
        const val MASK_GENERATION_FUNCTION_NAME = "MGF1"
        const val SYNTHETIC_CONTENT_TEXT = "timestamp-algorithm-test"
        const val ZERO_BYTE: Byte = 0
        val SYNTHETIC_CONTENT = SYNTHETIC_CONTENT_TEXT.encodeToByteArray()
    }
}
