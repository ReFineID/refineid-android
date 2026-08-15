package fi.refineid.android.document

import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedSignature
import fi.refineid.android.core.P384EcdsaSignature
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

class QualifiedDocumentCmsTest {
    @Test
    fun signedAttributesBindTheDocumentAndExactCertificateCanonically() {
        val attributes =
            QualifiedDocumentCms.signedAttributes(
                byteRangeDigest = SYNTHETIC_DOCUMENT_DIGEST,
                signerCertificateDer = SYNTHETIC_CERTIFICATE,
            )
        val certificateHash = sha384(SYNTHETIC_CERTIFICATE)

        assertTrue(attributes.containsEncoding(DerEncoder.octetString(SYNTHETIC_DOCUMENT_DIGEST)))
        assertTrue(attributes.containsEncoding(DerEncoder.octetString(certificateHash)))
        QualifiedDocumentCmsValidation.validateSignedAttributes(
            signedAttributesSet = attributes,
            signerCertificateDer = SYNTHETIC_CERTIFICATE,
        )

        val changedCertificate = SYNTHETIC_CERTIFICATE.copyOf()
        changedCertificate[FIRST_BYTE_OFFSET] = ALTERNATE_CERTIFICATE_BYTE
        assertCmsFailure(QualifiedDocumentCmsFailure.SIGNED_ATTRIBUTES_MALFORMED) {
            QualifiedDocumentCmsValidation.validateSignedAttributes(
                signedAttributesSet = attributes,
                signerCertificateDer = changedCertificate,
            )
        }
    }

    @Test
    fun signedAttributeBoundaryRejectsWrongDigestLengthAndMutation() {
        assertCmsFailure(QualifiedDocumentCmsFailure.DOCUMENT_DIGEST_MALFORMED) {
            QualifiedDocumentCms.signedAttributes(
                byteRangeDigest = ByteArray(SHA384_DIGEST_LENGTH_BYTES - SINGLE_BYTE_COUNT),
                signerCertificateDer = SYNTHETIC_CERTIFICATE,
            )
        }
        val attributes =
            QualifiedDocumentCms.signedAttributes(
                byteRangeDigest = SYNTHETIC_DOCUMENT_DIGEST,
                signerCertificateDer = SYNTHETIC_CERTIFICATE,
            )
        attributes[attributes.lastIndex] =
            (attributes.last().toUnsignedInt() xor SINGLE_BIT_CORRUPTION_MASK).toByte()

        assertCmsFailure(QualifiedDocumentCmsFailure.SIGNED_ATTRIBUTES_MALFORMED) {
            QualifiedDocumentCmsValidation.validateSignedAttributes(
                signedAttributesSet = attributes,
                signerCertificateDer = SYNTHETIC_CERTIFICATE,
            )
        }
    }

    @Test
    fun extractsTheCertificatesRawIssuerAndSerial() {
        val identity =
            QualifiedDocumentCmsValidation.issuerAndSerial(SYNTHETIC_X509_STRUCTURE)

        assertArrayEquals(
            DerEncoder.sequence(listOf(SYNTHETIC_ISSUER, SYNTHETIC_SERIAL)),
            identity,
        )
    }

    @Test
    fun rejectsAnUnparseableCertificateBeforeProfileUse() {
        assertCmsFailure(QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE) {
            QualifiedDocumentCmsValidation.validateCertificateProfile(
                certificateDer = SYNTHETIC_X509_STRUCTURE,
                expectedProfile = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384.keyProfile,
            )
        }
    }

    @Test
    fun timestampDigestCoversTheCmsSignatureShape() {
        val rsaBytes =
            ByteArray(QualifiedSigningAlgorithm.RSA_PKCS1_SHA384.signatureLength) {
                SYNTHETIC_SIGNATURE_BYTE
            }
        val rsa =
            NativeQualifiedSignature(
                algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                ownedBytes = rsaBytes,
            )
        val rawEcBytes =
            ByteArray(QualifiedSigningAlgorithm.ECDSA_P384_SHA384.signatureLength) {
                SYNTHETIC_SIGNATURE_BYTE
            }
        val ec =
            NativeQualifiedSignature(
                algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
                ownedBytes = rawEcBytes,
            )
        val derEc = P384EcdsaSignature.toDer(rawEcBytes)

        try {
            assertArrayEquals(sha384(rsaBytes), QualifiedDocumentCms.signatureTimestampDigest(rsa))
            assertArrayEquals(sha384(derEc), QualifiedDocumentCms.signatureTimestampDigest(ec))
        } finally {
            rsa.close()
            ec.close()
            derEc.fill(ZERO_BYTE)
        }
    }

    @Test
    fun rejectsMalformedSignatureShapesBeforeConversion() {
        for (algorithm in QualifiedSigningAlgorithm.entries) {
            val malformed =
                NativeQualifiedSignature(
                    algorithm = algorithm,
                    ownedBytes = ByteArray(algorithm.signatureLength - SINGLE_BYTE_COUNT),
                )
            try {
                assertCmsFailure(QualifiedDocumentCmsFailure.SIGNATURE_MALFORMED) {
                    QualifiedDocumentCms.signatureTimestampDigest(malformed)
                }
            } finally {
                malformed.close()
            }
        }
    }

    @Test
    fun assemblesAndRevalidatesTheIndependentRsaFixture() {
        val certificateDer = decodeFixture(SYNTHETIC_RSA_CERTIFICATE_BASE64)
        val signatureBytes = decodeFixture(SYNTHETIC_RSA_SIGNATURE_BASE64)
        val certificate =
            NativeQualifiedCertificate(
                keyProfile = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384.keyProfile,
                ownedDer = certificateDer.copyOf(),
            )
        val signature =
            NativeQualifiedSignature(
                algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                ownedBytes = signatureBytes.copyOf(),
            )
        try {
            val attributes =
                QualifiedDocumentCms.signedAttributes(
                    byteRangeDigest = SYNTHETIC_DOCUMENT_DIGEST,
                    signerCertificate = certificate,
                )
            val cms =
                QualifiedDocumentCms.assemble(
                    signedAttributesSet = attributes,
                    signature = signature,
                    signerCertificate = certificate,
                )

            assertDetachedCms(
                cms = cms,
                attributes = attributes,
                certificate = certificateDer,
                signature = signatureBytes,
                signatureAlgorithm = rsaSignatureAlgorithmIdentifier(),
            )

            val alteredAttributes = attributes.copyOf()
            alteredAttributes[alteredAttributes.lastIndex] =
                (alteredAttributes.last().toUnsignedInt() xor SINGLE_BIT_CORRUPTION_MASK).toByte()
            assertCmsFailure(QualifiedDocumentCmsFailure.SIGNED_ATTRIBUTES_MALFORMED) {
                QualifiedDocumentCms.assemble(
                    signedAttributesSet = alteredAttributes,
                    signature = signature,
                    signerCertificate = certificate,
                )
            }

            val alteredSignatureBytes = signatureBytes.copyOf()
            alteredSignatureBytes[FIRST_BYTE_OFFSET] =
                (
                    alteredSignatureBytes[FIRST_BYTE_OFFSET].toUnsignedInt() xor
                        SINGLE_BIT_CORRUPTION_MASK
                ).toByte()
            val alteredSignature =
                NativeQualifiedSignature(
                    algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                    ownedBytes = alteredSignatureBytes,
                )
            try {
                assertCmsFailure(QualifiedDocumentCmsFailure.SIGNATURE_MALFORMED) {
                    QualifiedDocumentCms.assemble(
                        signedAttributesSet = attributes,
                        signature = alteredSignature,
                        signerCertificate = certificate,
                    )
                }
            } finally {
                alteredSignature.close()
            }
        } finally {
            certificate.close()
            signature.close()
            certificateDer.fill(ZERO_BYTE)
            signatureBytes.fill(ZERO_BYTE)
        }
    }

    @Test
    fun assemblesAndRevalidatesTheIndependentP384Fixture() {
        val certificateDer = decodeFixture(SYNTHETIC_P384_CERTIFICATE_BASE64)
        val rawSignatureBytes = decodeFixture(SYNTHETIC_P384_RAW_SIGNATURE_BASE64)
        val certificate =
            NativeQualifiedCertificate(
                keyProfile = QualifiedSigningAlgorithm.ECDSA_P384_SHA384.keyProfile,
                ownedDer = certificateDer.copyOf(),
            )
        val signature =
            NativeQualifiedSignature(
                algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
                ownedBytes = rawSignatureBytes.copyOf(),
            )
        val derSignature = P384EcdsaSignature.toDer(rawSignatureBytes)
        try {
            val attributes =
                QualifiedDocumentCms.signedAttributes(
                    byteRangeDigest = SYNTHETIC_DOCUMENT_DIGEST,
                    signerCertificate = certificate,
                )
            val cms =
                QualifiedDocumentCms.assemble(
                    signedAttributesSet = attributes,
                    signature = signature,
                    signerCertificate = certificate,
                )

            assertDetachedCms(
                cms = cms,
                attributes = attributes,
                certificate = certificateDer,
                signature = derSignature,
                signatureAlgorithm = ecdsaSignatureAlgorithmIdentifier(),
            )
        } finally {
            certificate.close()
            signature.close()
            certificateDer.fill(ZERO_BYTE)
            rawSignatureBytes.fill(ZERO_BYTE)
            derSignature.fill(ZERO_BYTE)
        }
    }

    private fun assertDetachedCms(
        cms: ByteArray,
        attributes: ByteArray,
        certificate: ByteArray,
        signature: ByteArray,
        signatureAlgorithm: ByteArray,
    ) {
        val outer = DerReader(cms)
        val contentInfo = checkNotNull(outer.next())
        assertEquals(DerValues.TAG_SEQUENCE, contentInfo.tag)
        assertTrue(outer.isAtEnd)

        val contentInfoFields = outer.children(contentInfo)
        val contentType = checkNotNull(contentInfoFields.next())
        val explicitSignedData = checkNotNull(contentInfoFields.next())
        assertArrayEquals(
            DerEncoder.objectIdentifier(QualifiedCmsOids.SIGNED_DATA),
            contentInfoFields.raw(contentType),
        )
        assertEquals(DerValues.TAG_CONTEXT_0_CONSTRUCTED, explicitSignedData.tag)
        assertTrue(contentInfoFields.isAtEnd)

        val explicitFields = contentInfoFields.children(explicitSignedData)
        val signedData = checkNotNull(explicitFields.next())
        assertEquals(DerValues.TAG_SEQUENCE, signedData.tag)
        assertTrue(explicitFields.isAtEnd)
        val signedDataFields = explicitFields.children(signedData)
        checkNotNull(signedDataFields.next())
        checkNotNull(signedDataFields.next())
        checkNotNull(signedDataFields.next())
        val certificates = checkNotNull(signedDataFields.next())
        val signerInfos = checkNotNull(signedDataFields.next())
        assertTrue(signedDataFields.isAtEnd)
        assertEquals(DerValues.TAG_CONTEXT_0_CONSTRUCTED, certificates.tag)
        assertArrayEquals(certificate, signedDataFields.content(certificates))

        val signerSet = signedDataFields.children(signerInfos)
        val signerInfo = checkNotNull(signerSet.next())
        assertTrue(signerSet.isAtEnd)
        val signerFields = signerSet.children(signerInfo)
        checkNotNull(signerFields.next())
        checkNotNull(signerFields.next())
        checkNotNull(signerFields.next())
        val signedAttributes = checkNotNull(signerFields.next())
        val encodedSignatureAlgorithm = checkNotNull(signerFields.next())
        val signatureValue = checkNotNull(signerFields.next())
        assertTrue(signerFields.isAtEnd)
        assertArrayEquals(
            attributes,
            DerEncoder.retagged(
                encoded = signerFields.raw(signedAttributes),
                tag = DerValues.TAG_SET,
            ),
        )
        assertArrayEquals(signatureAlgorithm, signerFields.raw(encodedSignatureAlgorithm))
        assertArrayEquals(signature, signerFields.content(signatureValue))
    }

    private fun rsaSignatureAlgorithmIdentifier(): ByteArray =
        DerEncoder.sequence(
            listOf(
                DerEncoder.objectIdentifier(QualifiedCmsOids.SHA384_WITH_RSA),
                DerEncoder.nullValue(),
            ),
        )

    private fun ecdsaSignatureAlgorithmIdentifier(): ByteArray =
        DerEncoder.sequence(
            listOf(DerEncoder.objectIdentifier(QualifiedCmsOids.ECDSA_WITH_SHA384)),
        )

    private fun assertCmsFailure(
        expected: QualifiedDocumentCmsFailure,
        operation: () -> Unit,
    ) {
        val failure =
            assertThrows(QualifiedDocumentCmsException::class.java) {
                operation()
            }
        assertEquals(expected, failure.kind)
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

    private fun sha384(bytes: ByteArray): ByteArray = MessageDigest.getInstance(SHA384_DIGEST_ALGORITHM).digest(bytes)

    private fun decodeFixture(encoded: String): ByteArray = Base64.getMimeDecoder().decode(encoded)

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private companion object {
        const val SHA384_DIGEST_ALGORITHM = "SHA-384"
        const val SINGLE_BYTE_COUNT = 1
        const val FIRST_BYTE_OFFSET = 0
        const val SINGLE_BIT_CORRUPTION_MASK = 1
        const val SYNTHETIC_SIGNATURE_BYTE: Byte = 0x5A
        const val ALTERNATE_CERTIFICATE_BYTE: Byte = 0x31
        const val ZERO_BYTE: Byte = 0

        // Public-only KAT material generated from ephemeral RSA-3072 and P-384 keys.
        const val SYNTHETIC_RSA_CERTIFICATE_BASE64 =
            """
            MIIETDCCArSgAwIBAgIDBnkyMA0GCSqGSIb3DQEBDAUAMD4xJDAiBgNVBAMMG1Jl
            RmluZUlEIFN5bnRoZXRpYyBDTVMgVGVzdDEWMBQGA1UECgwNUmVGaW5lSUQgVGVz
            dDAeFw0yNjA4MTUxNjIxMDJaFw0zNjA4MTIxNjIxMDJaMD4xJDAiBgNVBAMMG1Jl
            RmluZUlEIFN5bnRoZXRpYyBDTVMgVGVzdDEWMBQGA1UECgwNUmVGaW5lSUQgVGVz
            dDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAMG6fCOZoZ5IWC0gvimW
            Pt5AoZyc9jlpbz7Q5wibPg6T8ilap95R5R0/iDW7kKybYfw697q0eORRLi4m0BNw
            Ahxw+Ll0R/Sil2rV2HORje6jZ7AufQIDe2utbpdKkKVunupQ4MuSylxWvBCCg7q9
            AI/+k92b7GcJVZZ3qaBZuELNYzKBCQsRqKr0TdaIBbjj6MG3Nx3CUGYWiPlKoB/K
            1kv0my1J1HKP+6zEzCwTPkrSRFF96ZyR20YnO0ahUO1kniNqxGqmGnAZOFPD3ejc
            dwhbEjsZ4GeZeGbXKsfVMzUOJrV/dRUZ2y1WOqnwOKG/WICFieAwjXCRdqxa0y+h
            BhhIlFwW8LGzT1y/m9y/wnuQPiUYppUxUWhUUZHx9GnxZkydJGD6VtIUynccSAYU
            W+/1ckc0lhUETprR0l07IcKD4fQzaWV3J0ssN5vUO5S9TdmD7TiqTgDfBFLo4Sg9
            zew8Sp/+nJLGLUFGwHtOcf+TGeJFW8slMo0Xm4kgTuqBcwIDAQABo1MwUTAdBgNV
            HQ4EFgQUDs6VkGSA9jIQ0xbCIllPZGG0fkkwHwYDVR0jBBgwFoAUDs6VkGSA9jIQ
            0xbCIllPZGG0fkkwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQwFAAOCAYEA
            RgYQWKuTbritUXMbEsJmb+9O/3tRjjV5mMaG4y8vN1/qlAVxj7Czx56IiOWCN0nS
            mginJkvhLJnqyBSc3sA55ZJBPwzlR7evnYnFGaAmbP1EIKsbO0hDhTjrZ8fWkn6I
            hqYKZ1msRbd72HnF5ivoZEZZ/+Q+3kFX+PoBZ3W0SZmm8IHWsw/gCVWpc9XiBmVK
            m8g0/oDoL+IiriErNWVHAQVSZsqcu1q8Ep7u7/0HgyXR3i0ZP1hTbMpqqgwIa9fs
            1LPZYdG+Z4422BH5NhD4eSr8c0kW5IQaNfOzxXT4wy9UQrdFK9q3ruItVtvswtCP
            ib0gl9mYtu0UGmwD4ONzHR1P0V10YxE8Y6C16aKTx0WrRkJWPJSxFTYfGOIdnBRz
            tsQ5WV7s4nhCj0QFCqC7w3ynVQ4sBBnLBQuauxpNiG/R4P2Vwz7Mz3J10aUS2Q/Q
            yT4wtfwtnFvF3TwpPHKtjZEottMdw/+Jbxold0cQvgMnAoXRIIdBJLP0rqfiKfHS
            """
        const val SYNTHETIC_RSA_SIGNATURE_BASE64 =
            """
            Hc/gS7VfgNtaocRXwSEsuX6z/x3V6ahu/GhBdBCK+1ty2FtI5u3B66gp32MuRtn8
            esAjsavLtA30eAOPSpQCv4AiDnE3Ixf6L742CcCj3PWpHE9SJl6ooka3/cQxZXDY
            TU6aXC3iPtjmWhWPiMYM17a3QftuWJndAPCYveWDE+yRaBplNopGXLox3oWCf35+
            z9rDbot7poTowN0IMybRJQ6GYjwVzQDsBkQqVxoIQwiRq/Ex07gJAzS38oobIRDe
            C9fS3v1mtIJKeZgw1MkOr7Jb8z7WHisY9qb1QThZDrWksOe5Oj9SphBhb1KsIhsi
            lZfgFGQ4M4yrKC8JFdPDcgTT9yTsrlBMUK/OuVfa1/ZlBBakPHXhmHFbA/Wf28BI
            6CD6UlwrcNKCWIj9iTZP08cYhbwai9b1mTY3cJPQnS4UdXPCqQ37nWgTpdH6Ekg6
            Gjt8Ylp7bQpkSD0k5mulMadrABbSlZnewR2j51CPF9HuYOxTB/f7ffs7TriW6esz
            """
        const val SYNTHETIC_P384_CERTIFICATE_BASE64 =
            """
            MIICEzCCAZqgAwIBAgIDB9xPMAoGCCqGSM49BAMDMEMxKTAnBgNVBAMMIFJlRmlu
            ZUlEIFN5bnRoZXRpYyBQMzg0IENNUyBUZXN0MRYwFAYDVQQKDA1SZUZpbmVJRCBU
            ZXN0MB4XDTI2MDgxNTE2MjgyM1oXDTM2MDgxMjE2MjgyM1owQzEpMCcGA1UEAwwg
            UmVGaW5lSUQgU3ludGhldGljIFAzODQgQ01TIFRlc3QxFjAUBgNVBAoMDVJlRmlu
            ZUlEIFRlc3QwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATdllqv+Jps9MgHE49BLZSW
            9zVa+Ong7GJbTNzNlKSfTHYMKondlnaDCQmxmTOGwi7Gx9UIPPDmd8b/Fg1Bd8D0
            seeWLfowcxY3Fhd/zRIkGmlA4s+KwasjV0M3RG/x6Z+jYDBeMB0GA1UdDgQWBBQk
            VSfGuM+Uf1T4h0v+Pj8Kss0PejAfBgNVHSMEGDAWgBQkVSfGuM+Uf1T4h0v+Pj8K
            ss0PejAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAwNn
            ADBkAjBdJL+z3BeYJfW7oI1bHUdSipuz28nMcrFMg3FCzzKiWrlm/DGolWsXwc5F
            ujsGu1ACMHUu72UZcvhqd8moZwjYdwLiENYBd20zGlavRRXPpraa14x6phmQiydI
            5rAlqKX4Zg==
            """
        const val SYNTHETIC_P384_RAW_SIGNATURE_BASE64 =
            """
            b51h213k9pX0cVny+I4ZGQ7zFQb25tDl8bq9PDY3+JWxEvMrUPrGxbEwjccD25ps
            GROIvzOsa6VhvzlReu9E+a5pjfP5NZMrcCbh9rm6lC9JzHM9Do7D7cXqKnEf2Wpo
            """

        val SYNTHETIC_DOCUMENT_DIGEST =
            ByteArray(SHA384_DIGEST_LENGTH_BYTES) { SYNTHETIC_DIGEST_BYTE }
        val SYNTHETIC_CERTIFICATE = "synthetic qualified certificate".encodeToByteArray()
        val SYNTHETIC_ISSUER_VALUE = "Synthetic issuer".encodeToByteArray()
        val SYNTHETIC_SERIAL = DerEncoder.integer(SYNTHETIC_SERIAL_VALUE)
        val SYNTHETIC_ISSUER =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.octetString(SYNTHETIC_ISSUER_VALUE),
                ),
            )
        val SYNTHETIC_SIGNATURE_ALGORITHM = DerEncoder.sequence(emptyList())
        val SYNTHETIC_X509_STRUCTURE =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.sequence(
                        listOf(
                            DerEncoder.tlv(
                                tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                                content = DerEncoder.integer(SYNTHETIC_CERTIFICATE_VERSION),
                            ),
                            SYNTHETIC_SERIAL,
                            SYNTHETIC_SIGNATURE_ALGORITHM,
                            SYNTHETIC_ISSUER,
                        ),
                    ),
                    SYNTHETIC_SIGNATURE_ALGORITHM,
                    DerEncoder.octetString(byteArrayOf(SYNTHETIC_SIGNATURE_BYTE)),
                ),
            )

        const val SYNTHETIC_DIGEST_BYTE: Byte = 0x5C
        const val SYNTHETIC_SERIAL_VALUE = 7
        const val SYNTHETIC_CERTIFICATE_VERSION = 2
    }
}
