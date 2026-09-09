// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ValidationMaterialCollectorTest {
    @Test
    fun collectsAuthenticatedOcspWithoutCrlFallback() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            val events = mutableListOf<IoEvent>()
            val material =
                ValidationMaterialCollector.collect(
                    request = documentRequest(fixture),
                    dependencies =
                        dependencies(
                            fixture,
                            DependencyOptions(
                                revocationList = fixture.goodRevocationList,
                                ocspResponse = fixture.goodOcspResponse,
                                events = events,
                            ),
                        ),
                )
            try {
                material.useCopies { certificates, ocspResponses, revocationLists ->
                    assertEquals(SINGLE_VALUE_COUNT, certificates.size)
                    assertArrayEquals(fixture.issuerCertificate, certificates.single())
                    assertEquals(SINGLE_VALUE_COUNT, ocspResponses.size)
                    assertArrayEquals(fixture.goodOcspResponse, ocspResponses.single())
                    assertTrue(revocationLists.isEmpty())
                }
            } finally {
                material.close()
            }
            assertEquals(listOf(IoEvent.GET_CERTIFICATE, IoEvent.POST_OCSP), events)
        }
    }

    @Test
    fun collectsAuthenticatedCrlAfterOcspFailure() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            val events = mutableListOf<IoEvent>()
            val material =
                ValidationMaterialCollector.collect(
                    request = documentRequest(fixture),
                    dependencies =
                        dependencies(
                            fixture,
                            DependencyOptions(
                                revocationList = fixture.goodRevocationList,
                                events = events,
                            ),
                        ),
                )
            try {
                material.useCopies { certificates, ocspResponses, revocationLists ->
                    assertEquals(SINGLE_VALUE_COUNT, certificates.size)
                    assertArrayEquals(fixture.issuerCertificate, certificates.single())
                    assertTrue(ocspResponses.isEmpty())
                    assertEquals(SINGLE_VALUE_COUNT, revocationLists.size)
                    assertArrayEquals(fixture.goodRevocationList, revocationLists.single())
                }
            } finally {
                material.close()
            }
            assertEquals(
                listOf(IoEvent.GET_CERTIFICATE, IoEvent.POST_OCSP, IoEvent.GET_REVOCATION_LIST),
                events,
            )
        }
    }

    @Test
    fun authenticatedDocumentRevocationRetainsPathRole() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            val failure =
                assertThrows(ValidationMaterialCollectionException::class.java) {
                    ValidationMaterialCollector
                        .collect(
                            request = documentRequest(fixture),
                            dependencies =
                                dependencies(
                                    fixture,
                                    DependencyOptions(revocationList = fixture.revokedRevocationList),
                                ),
                        ).close()
                }

            assertEquals(ValidationMaterialCollectionFailure.REVOKED, failure.kind)
            assertEquals(ValidationPathRole.DOCUMENT_SIGNER, failure.pathRole)
        }
    }

    @Test
    fun authenticatedTimestampRevocationIsClassifiedBeforeDocumentSigner() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            verifiedTimestampToken(fixture).use { token ->
                val failure =
                    assertThrows(ValidationMaterialCollectionException::class.java) {
                        ValidationMaterialCollector
                            .collect(
                                request =
                                    ValidationMaterialCollectionRequest(
                                        signerCertificate = fixture.documentSignerCertificate,
                                        timestampTokens = listOf(token),
                                        signerTrustCertificates = listOf(fixture.issuerCertificate),
                                    ),
                                dependencies =
                                    dependencies(
                                        fixture,
                                        DependencyOptions(
                                            revocationList = fixture.revokedRevocationList,
                                        ),
                                    ),
                            ).close()
                    }

                assertEquals(ValidationMaterialCollectionFailure.REVOKED, failure.kind)
                assertEquals(ValidationPathRole.TIMESTAMP_AUTHORITY, failure.pathRole)
            }
        }
    }

    @Test
    fun randomFailureStillAllowsAuthenticatedCrlFallback() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            val events = mutableListOf<IoEvent>()
            val material =
                ValidationMaterialCollector.collect(
                    request = documentRequest(fixture),
                    dependencies =
                        dependencies(
                            fixture,
                            DependencyOptions(
                                revocationList = fixture.goodRevocationList,
                                randomAvailable = false,
                                events = events,
                            ),
                        ),
                )
            material.close()

            assertEquals(
                listOf(IoEvent.GET_CERTIFICATE, IoEvent.GET_REVOCATION_LIST),
                events,
            )
        }
    }

    @Test
    fun randomFailureWinsOnlyWhenCrlIsUnavailable() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            val failure =
                assertThrows(ValidationMaterialCollectionException::class.java) {
                    ValidationMaterialCollector
                        .collect(
                            request = documentRequest(fixture),
                            dependencies =
                                dependencies(
                                    fixture,
                                    DependencyOptions(
                                        revocationList = null,
                                        randomAvailable = false,
                                    ),
                                ),
                        ).close()
                }

            assertEquals(ValidationMaterialCollectionFailure.RANDOM_UNAVAILABLE, failure.kind)
            assertEquals(null, failure.pathRole)
        }
    }

    @Test
    fun unavailableIssuerFailsInsteadOfReturningPartialMaterial() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            val failure =
                assertThrows(ValidationMaterialCollectionException::class.java) {
                    ValidationMaterialCollector
                        .collect(
                            request = documentRequest(fixture),
                            dependencies = offlineDependencies(fixture),
                        ).close()
                }

            assertEquals(ValidationMaterialCollectionFailure.ISSUER_UNAVAILABLE, failure.kind)
        }
    }

    @Test
    fun unavailableRevocationEvidenceFailsClosed() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            val failure =
                assertThrows(ValidationMaterialCollectionException::class.java) {
                    ValidationMaterialCollector
                        .collect(
                            request = documentRequest(fixture),
                            dependencies =
                                dependencies(
                                    fixture,
                                    DependencyOptions(revocationList = null),
                                ),
                        ).close()
                }

            assertEquals(ValidationMaterialCollectionFailure.REVOCATION_UNAVAILABLE, failure.kind)
        }
    }

    @Test
    fun verifiedTimestampSignerAndSharedEvidenceAreRetainedOnce() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            verifiedTimestampToken(fixture).use { token ->
                val material =
                    ValidationMaterialCollector.collect(
                        request =
                            ValidationMaterialCollectionRequest(
                                signerCertificate = fixture.documentSignerCertificate,
                                timestampTokens = listOf(token),
                                signerTrustCertificates = listOf(fixture.issuerCertificate),
                            ),
                        dependencies =
                            dependencies(
                                fixture,
                                DependencyOptions(revocationList = fixture.goodRevocationList),
                            ),
                    )
                try {
                    material.useCopies { certificates, ocspResponses, revocationLists ->
                        assertEquals(TIMESTAMP_PATH_CERTIFICATE_COUNT, certificates.size)
                        assertArrayEquals(fixture.timestampAuthorityCertificate, certificates.first())
                        assertArrayEquals(fixture.issuerCertificate, certificates.last())
                        assertTrue(ocspResponses.isEmpty())
                        assertEquals(SINGLE_VALUE_COUNT, revocationLists.size)
                        assertArrayEquals(fixture.goodRevocationList, revocationLists.single())
                    }
                } finally {
                    material.close()
                }
            }
        }
    }

    @Test
    fun rejectsMorePathsThanTheMaterialBound() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            verifiedTimestampToken(fixture).use { token ->
                val failure =
                    assertThrows(ValidationMaterialCollectionException::class.java) {
                        ValidationMaterialCollector
                            .collect(
                                request =
                                    ValidationMaterialCollectionRequest(
                                        signerCertificate = fixture.documentSignerCertificate,
                                        timestampTokens = listOf(token, token),
                                        signerTrustCertificates = listOf(fixture.issuerCertificate),
                                    ),
                                dependencies = offlineDependencies(fixture),
                            ).close()
                    }

                assertEquals(ValidationMaterialCollectionFailure.PATH_LIMIT_EXCEEDED, failure.kind)
            }
        }
    }

    @Test
    fun explicitLeafAnchorNeedsNeitherIssuerNorStatus() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            val material =
                ValidationMaterialCollector.collect(
                    request =
                        ValidationMaterialCollectionRequest(
                            signerCertificate = fixture.documentSignerCertificate,
                            timestampTokens = emptyList(),
                            signerTrustCertificates = listOf(fixture.documentSignerCertificate),
                        ),
                    dependencies = offlineDependencies(fixture),
                )
            try {
                assertTrue(material.isEmpty)
            } finally {
                material.close()
            }
        }
    }

    @Test
    fun selfIssuedNameIsNotAnImplicitAnchor() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            val failure =
                assertThrows(ValidationMaterialCollectionException::class.java) {
                    ValidationMaterialCollector
                        .collect(
                            request =
                                ValidationMaterialCollectionRequest(
                                    signerCertificate = fixture.issuerCertificate,
                                    timestampTokens = emptyList(),
                                    signerTrustCertificates = emptyList(),
                                ),
                            dependencies = offlineDependencies(fixture),
                        ).close()
                }

            assertEquals(ValidationMaterialCollectionFailure.TRUST_ANCHOR_UNAVAILABLE, failure.kind)
        }
    }

    @Test
    fun malformedSignerFailsBeforeTrustOrIo() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            val malformed = byteArrayOf(MALFORMED_CERTIFICATE_MARKER)
            try {
                val failure =
                    assertThrows(ValidationMaterialCollectionException::class.java) {
                        ValidationMaterialCollector
                            .collect(
                                request =
                                    ValidationMaterialCollectionRequest(
                                        signerCertificate = malformed,
                                        timestampTokens = emptyList(),
                                        signerTrustCertificates = emptyList(),
                                    ),
                                dependencies = offlineDependencies(fixture),
                            ).close()
                    }

                assertEquals(ValidationMaterialCollectionFailure.CERTIFICATE_MALFORMED, failure.kind)
            } finally {
                malformed.fill(ZERO_BYTE)
            }
        }
    }

    @Test
    fun certificateAddressBudgetIsDistinctAndBounded() {
        val selected =
            ValidationMaterialCollector.boundedCertificateAddresses(
                listOf(ADDRESS_ONE, ADDRESS_ONE, ADDRESS_TWO, ADDRESS_THREE, ADDRESS_FOUR),
            )

        assertEquals(listOf(ADDRESS_ONE, ADDRESS_TWO, ADDRESS_THREE), selected)
        assertEquals(ValidationMaterialCollector.MAXIMUM_CERTIFICATE_ADDRESSES, selected.size)
    }

    private fun documentRequest(fixture: ValidationMaterialCollectorFixture): ValidationMaterialCollectionRequest =
        ValidationMaterialCollectionRequest(
            signerCertificate = fixture.documentSignerCertificate,
            timestampTokens = emptyList(),
            signerTrustCertificates = listOf(fixture.issuerCertificate),
        )

    private fun dependencies(
        fixture: ValidationMaterialCollectorFixture,
        options: DependencyOptions,
    ): ValidationMaterialCollectorDependencies =
        ValidationMaterialCollectorDependencies(
            get =
                ValidationMaterialGetter { address, resource ->
                    when {
                        address == ValidationMaterialCollectorFixture.ISSUER_ADDRESS &&
                            resource == ValidationMaterialGetResource.CERTIFICATE -> {
                            options.events += IoEvent.GET_CERTIFICATE
                            fixture.issuerCertificate.copyOf()
                        }

                        address == ValidationMaterialCollectorFixture.REVOCATION_LIST_ADDRESS &&
                            resource == ValidationMaterialGetResource.REVOCATION_LIST &&
                            options.revocationList != null -> {
                            options.events += IoEvent.GET_REVOCATION_LIST
                            options.revocationList.copyOf()
                        }

                        else -> {
                            throw UnexpectedIoException()
                        }
                    }
                },
            post =
                ValidationMaterialPoster { request, address, contentType ->
                    assertTrue(request.isNotEmpty())
                    assertEquals(ValidationMaterialCollectorFixture.OCSP_ADDRESS, address)
                    assertEquals(OCSP_REQUEST_CONTENT_TYPE, contentType)
                    options.events += IoEvent.POST_OCSP
                    options.ocspResponse?.copyOf() ?: byteArrayOf(MALFORMED_OCSP_RESPONSE_MARKER)
                },
            now = { fixture.currentTime },
            random =
                ValidationSecureRandom { byteCount ->
                    if (!options.randomAvailable) {
                        throw UnexpectedIoException()
                    }
                    ByteArray(byteCount) { ValidationMaterialCollectorFixture.OCSP_NONCE_FILL_BYTE }
                },
        )

    private fun offlineDependencies(
        fixture: ValidationMaterialCollectorFixture,
    ): ValidationMaterialCollectorDependencies =
        ValidationMaterialCollectorDependencies(
            get = ValidationMaterialGetter { _, _ -> throw UnexpectedIoException() },
            post = ValidationMaterialPoster { _, _, _ -> throw UnexpectedIoException() },
            now = { fixture.currentTime },
            random = ValidationSecureRandom { _ -> throw UnexpectedIoException() },
        )

    private fun verifiedTimestampToken(fixture: ValidationMaterialCollectorFixture): VerifiedTimestampToken =
        VerifiedTimestampToken(
            ownedEncoding = byteArrayOf(SYNTHETIC_TOKEN_MARKER),
            ownedMessageImprint = byteArrayOf(SYNTHETIC_IMPRINT_MARKER),
            ownedSignerCertificate = fixture.timestampAuthorityCertificate.copyOf(),
            ownedEmbeddedCertificates =
                listOf(
                    fixture.timestampAuthorityCertificate.copyOf(),
                    fixture.issuerCertificate.copyOf(),
                ),
            ownedCertificatePath =
                VerifiedTimestampCertificatePath(
                    ownedCertificates =
                        listOf(
                            fixture.timestampAuthorityCertificate.copyOf(),
                            fixture.issuerCertificate.copyOf(),
                        ),
                    ownedTrustAnchor = fixture.issuerCertificate.copyOf(),
                ),
            generatedAt = fixture.currentTime,
        )

    private data class DependencyOptions(
        val revocationList: ByteArray?,
        val ocspResponse: ByteArray? = null,
        val randomAvailable: Boolean = true,
        val events: MutableList<IoEvent> = mutableListOf(),
    )

    private enum class IoEvent {
        GET_CERTIFICATE,
        GET_REVOCATION_LIST,
        POST_OCSP,
    }

    private class UnexpectedIoException : Exception()

    private companion object {
        const val SINGLE_VALUE_COUNT = 1
        const val TIMESTAMP_PATH_CERTIFICATE_COUNT = 2
        const val OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request"
        const val MALFORMED_CERTIFICATE_MARKER: Byte = 0x31
        const val MALFORMED_OCSP_RESPONSE_MARKER: Byte = 0x32
        const val SYNTHETIC_TOKEN_MARKER: Byte = 0x33
        const val SYNTHETIC_IMPRINT_MARKER: Byte = 0x34
        const val ZERO_BYTE: Byte = 0
        const val ADDRESS_ONE = "https://one.example/status"
        const val ADDRESS_TWO = "https://two.example/status"
        const val ADDRESS_THREE = "https://three.example/status"
        const val ADDRESS_FOUR = "https://four.example/status"
    }
}
