// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CertificateFactsTest {
    @Test
    fun preservesOcspIdentityAndSelectsOnlyDistinctHttpLocations() {
        val certificate =
            certificate(
                extensions =
                    listOf(
                        accessExtension(),
                        revocationListExtension(),
                    ),
            )
        val facts = checkNotNull(CertificateFacts.parse(certificate))
        var transientIssuer = ByteArray(EMPTY_BYTE_COUNT)
        var transientSerial = ByteArray(EMPTY_BYTE_COUNT)
        var transientKey = ByteArray(EMPTY_BYTE_COUNT)
        try {
            assertTrue(facts.isSelfIssued)
            assertEquals(listOf(ISSUER_CERTIFICATE_ADDRESS), facts.issuerCertificateUrls)
            assertEquals(listOf(OCSP_RESPONDER_ADDRESS), facts.ocspUrls)
            assertEquals(
                listOf(REVOCATION_LIST_ADDRESS, REVOCATION_LIST_FALLBACK_ADDRESS),
                facts.revocationListUrls,
            )
            facts.useOcspIdentity { issuer, serial ->
                transientIssuer = issuer
                transientSerial = serial
                assertTrue(issuer.contentEquals(ENCODED_NAME))
                assertTrue(serial.contentEquals(SERIAL_NUMBER_CONTENT))
            }
            facts.usePublicKeyBits { key ->
                transientKey = key
                assertTrue(key.contentEquals(PUBLIC_KEY_BITS))
            }
        } finally {
            facts.close()
            certificate.fill(ZERO_BYTE)
        }
        assertTrue(transientIssuer.all { byte -> byte == ZERO_BYTE })
        assertTrue(transientSerial.all { byte -> byte == ZERO_BYTE })
        assertTrue(transientKey.all { byte -> byte == ZERO_BYTE })
    }

    @Test
    fun rejectsIncompleteMismatchedAndDuplicateCertificateStructures() {
        val valid = certificate(extensions = emptyList())
        val truncated = valid.copyOf(valid.size - TRUNCATED_BYTE_COUNT)
        val mismatched =
            certificate(
                extensions = emptyList(),
                outerSignatureAlgorithm = DIFFERENT_SIGNATURE_ALGORITHM,
            )
        val duplicated =
            certificate(
                extensions = listOf(accessExtension(), accessExtension()),
            )
        try {
            assertNull(CertificateFacts.parse(ByteArray(EMPTY_BYTE_COUNT)))
            assertNull(CertificateFacts.parse(MALFORMED_CERTIFICATE_TEXT.encodeToByteArray()))
            assertNull(CertificateFacts.parse(truncated))
            assertNull(CertificateFacts.parse(mismatched))
            assertNull(CertificateFacts.parse(duplicated))
        } finally {
            valid.fill(ZERO_BYTE)
            truncated.fill(ZERO_BYTE)
            mismatched.fill(ZERO_BYTE)
            duplicated.fill(ZERO_BYTE)
        }
    }

    @Test
    fun distinguishesDifferentIssuerAndSubjectNames() {
        val certificate = certificate(extensions = emptyList(), subjectName = DIFFERENT_ENCODED_NAME)
        val facts = checkNotNull(CertificateFacts.parse(certificate))
        try {
            assertFalse(facts.isSelfIssued)
        } finally {
            facts.close()
            certificate.fill(ZERO_BYTE)
        }
    }

    private fun certificate(
        extensions: List<ByteArray>,
        subjectName: ByteArray = ENCODED_NAME,
        outerSignatureAlgorithm: ByteArray = SIGNATURE_ALGORITHM,
    ): ByteArray {
        val fields =
            mutableListOf(
                DerEncoder.tlv(
                    tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                    content = DerEncoder.integer(CERTIFICATE_VERSION_THREE),
                ),
                DerEncoder.tlv(DerValues.TAG_INTEGER, SERIAL_NUMBER_CONTENT),
                SIGNATURE_ALGORITHM,
                ENCODED_NAME,
                DerEncoder.sequence(emptyList()),
                subjectName,
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.sequence(emptyList()),
                        DerEncoder.tlv(
                            tag = DerValues.TAG_BIT_STRING,
                            content = byteArrayOf(NO_UNUSED_BITS) + PUBLIC_KEY_BITS,
                        ),
                    ),
                ),
            )
        if (extensions.isNotEmpty()) {
            fields +=
                DerEncoder.tlv(
                    tag = DerValues.TAG_CONTEXT_3_CONSTRUCTED,
                    content = DerEncoder.sequence(extensions),
                )
        }
        return DerEncoder.sequence(
            listOf(
                DerEncoder.sequence(fields),
                outerSignatureAlgorithm,
                DerEncoder.tlv(
                    tag = DerValues.TAG_BIT_STRING,
                    content = byteArrayOf(NO_UNUSED_BITS, SYNTHETIC_SIGNATURE_BYTE),
                ),
            ),
        )
    }

    private fun accessExtension(): ByteArray {
        val issuer = accessDescription(CertificateOids.CA_ISSUERS_ACCESS_METHOD, ISSUER_CERTIFICATE_ADDRESS)
        val duplicateIssuer = accessDescription(CertificateOids.CA_ISSUERS_ACCESS_METHOD, ISSUER_CERTIFICATE_ADDRESS)
        val responder = accessDescription(CertificateOids.OCSP_ACCESS_METHOD, OCSP_RESPONDER_ADDRESS)
        val unsupported = accessDescription(CertificateOids.OCSP_ACCESS_METHOD, UNSUPPORTED_LDAP_ADDRESS)
        val credentialed = accessDescription(CertificateOids.OCSP_ACCESS_METHOD, CREDENTIALED_HTTP_ADDRESS)
        return extension(
            identifier = CertificateOids.AUTHORITY_INFORMATION_ACCESS,
            value = DerEncoder.sequence(listOf(issuer, duplicateIssuer, responder, unsupported, credentialed)),
        )
    }

    private fun accessDescription(
        method: String,
        address: String,
    ): ByteArray =
        DerEncoder.sequence(
            listOf(
                DerEncoder.objectIdentifier(method),
                DerEncoder.tlv(DerValues.TAG_CONTEXT_6_PRIMITIVE, address.encodeToByteArray()),
            ),
        )

    private fun revocationListExtension(): ByteArray {
        val first = distributionPoint(listOf(REVOCATION_LIST_ADDRESS, UNSUPPORTED_LDAP_ADDRESS))
        val second = distributionPoint(listOf(REVOCATION_LIST_ADDRESS, REVOCATION_LIST_FALLBACK_ADDRESS))
        return extension(
            identifier = CertificateOids.CRL_DISTRIBUTION_POINTS,
            value = DerEncoder.sequence(listOf(first, second)),
        )
    }

    private fun distributionPoint(addresses: List<String>): ByteArray {
        val names =
            addresses.map { address ->
                DerEncoder.tlv(DerValues.TAG_CONTEXT_6_PRIMITIVE, address.encodeToByteArray())
            }
        return DerEncoder.sequence(
            listOf(
                DerEncoder.tlv(
                    tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                    content =
                        DerEncoder.tlv(
                            tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                            content = concatenate(names),
                        ),
                ),
            ),
        )
    }

    private fun extension(
        identifier: String,
        value: ByteArray,
    ): ByteArray =
        DerEncoder.sequence(
            listOf(
                DerEncoder.objectIdentifier(identifier),
                DerEncoder.octetString(value),
            ),
        )

    private fun concatenate(values: List<ByteArray>): ByteArray {
        val combined = ByteArray(values.sumOf(ByteArray::size))
        var offset = FIRST_BYTE_OFFSET
        for (value in values) {
            value.copyInto(combined, destinationOffset = offset)
            offset += value.size
        }
        return combined
    }

    private companion object {
        const val CERTIFICATE_VERSION_THREE = 2
        const val EMPTY_BYTE_COUNT = 0
        const val TRUNCATED_BYTE_COUNT = 1
        const val FIRST_BYTE_OFFSET = 0
        const val NO_UNUSED_BITS: Byte = 0
        const val SYNTHETIC_SIGNATURE_BYTE: Byte = 0x5A
        const val ZERO_BYTE: Byte = 0
        const val MALFORMED_CERTIFICATE_TEXT = "not a certificate"
        const val ISSUER_CERTIFICATE_ADDRESS = "https://issuer.example/certificate.der"
        const val OCSP_RESPONDER_ADDRESS = "http://status.example/ocsp"
        const val REVOCATION_LIST_ADDRESS = "https://issuer.example/current.crl"
        const val REVOCATION_LIST_FALLBACK_ADDRESS = "http://issuer.example/fallback.crl"
        const val UNSUPPORTED_LDAP_ADDRESS = "ldap://issuer.example/directory"
        const val CREDENTIALED_HTTP_ADDRESS = "https://name:secret@status.example/ocsp"

        val SERIAL_NUMBER_CONTENT = byteArrayOf(SYNTHETIC_SERIAL_NUMBER_BYTE)
        val PUBLIC_KEY_BITS = SYNTHETIC_PUBLIC_KEY_TEXT.encodeToByteArray()
        val ENCODED_NAME = DerEncoder.sequence(emptyList())
        val DIFFERENT_ENCODED_NAME = DerEncoder.sequence(listOf(DerEncoder.setOf(emptyList())))
        val SIGNATURE_ALGORITHM =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.objectIdentifier(SHA256_WITH_RSA_IDENTIFIER),
                    DerEncoder.nullValue(),
                ),
            )
        val DIFFERENT_SIGNATURE_ALGORITHM =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.objectIdentifier(SHA384_WITH_RSA_IDENTIFIER),
                    DerEncoder.nullValue(),
                ),
            )

        const val SYNTHETIC_SERIAL_NUMBER_BYTE: Byte = 0x13
        const val SYNTHETIC_PUBLIC_KEY_TEXT = "1357"
        const val SHA256_WITH_RSA_IDENTIFIER = "1.2.840.113549.1.1.11"
        const val SHA384_WITH_RSA_IDENTIFIER = "1.2.840.113549.1.1.12"
    }
}
