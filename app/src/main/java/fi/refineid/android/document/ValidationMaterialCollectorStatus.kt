// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.time.Instant

internal enum class AuthenticatedStatusKind {
    OCSP,
    REVOCATION_LIST,
}

internal class AuthenticatedStatusEvidence private constructor(
    val kind: AuthenticatedStatusKind,
    private val ownedEncoding: ByteArray,
) : AutoCloseable {
    fun <T> useEncoding(operation: (ByteArray) -> T): T {
        val copy = ownedEncoding.copyOf()
        return try {
            operation(copy)
        } finally {
            copy.fill(ZERO_BYTE)
        }
    }

    override fun close() {
        ownedEncoding.fill(ZERO_BYTE)
    }

    companion object {
        fun takeOwnership(
            kind: AuthenticatedStatusKind,
            encoding: ByteArray,
        ): AuthenticatedStatusEvidence = AuthenticatedStatusEvidence(kind, encoding)

        private const val ZERO_BYTE: Byte = 0
    }
}

internal class AuthenticatedRevocationException : Exception()

/** Authenticates one current OCSP answer or falls back to one complete current CRL. */
internal object ValidationMaterialCollectorStatus {
    fun authenticate(
        certificate: ByteArray,
        facts: CertificateFacts,
        issuer: ByteArray,
        currentTime: Instant,
        dependencies: ValidationMaterialCollectorDependencies,
    ): AuthenticatedStatusEvidence {
        val context = StatusContext(certificate, facts, issuer, currentTime, dependencies)
        val ocsp = ocsp(context)
        ocsp.evidence?.let { evidence -> return evidence }
        crl(context)?.let { evidence -> return evidence }
        if (ocsp.randomFailed) {
            throw failure(ValidationMaterialCollectionFailure.RANDOM_UNAVAILABLE)
        }
        throw failure(ValidationMaterialCollectionFailure.REVOCATION_UNAVAILABLE)
    }

    private fun ocsp(context: StatusContext): OcspAttempt {
        val issuerFacts =
            CertificateFacts.parse(context.issuer)
                ?: throw failure(ValidationMaterialCollectionFailure.CERTIFICATE_MALFORMED)
        issuerFacts.use { parsedIssuer ->
            val addresses =
                ValidationMaterialCollector.boundedCertificateAddresses(context.facts.ocspUrls)
            for (address in addresses) {
                when (val result = ocspAtAddress(context, parsedIssuer, address)) {
                    is OcspAddressResult.Success -> return OcspAttempt.success(result.evidence)
                    OcspAddressResult.RandomFailure -> return OcspAttempt.randomFailure()
                    OcspAddressResult.Unavailable -> Unit
                }
            }
        }
        return OcspAttempt.noEvidence()
    }

    private fun ocspAtAddress(
        context: StatusContext,
        issuerFacts: CertificateFacts,
        address: String,
    ): OcspAddressResult {
        val nonce = randomNonce(context.dependencies) ?: return OcspAddressResult.RandomFailure
        try {
            val request = ocspRequest(context.facts, issuerFacts, nonce)
            val response =
                try {
                    post(request, address, context.dependencies)
                } finally {
                    request.fill(ZERO_BYTE)
                } ?: return OcspAddressResult.Unavailable
            try {
                val verified =
                    try {
                        OcspResponse.verify(
                            response = response,
                            certificateDer = context.certificate,
                            issuerCertificateDer = context.issuer,
                            nonce = nonce,
                            currentTime = context.currentTime,
                        )
                    } catch (validation: OcspResponseValidationException) {
                        if (validation.kind == OcspResponseValidationFailure.REVOKED) {
                            throw AuthenticatedRevocationException()
                        }
                        return OcspAddressResult.Unavailable
                    }
                verified.use { authenticated ->
                    return OcspAddressResult.Success(
                        AuthenticatedStatusEvidence.takeOwnership(
                            kind = AuthenticatedStatusKind.OCSP,
                            encoding = authenticated.copyEncoding(),
                        ),
                    )
                }
            } finally {
                response.fill(ZERO_BYTE)
            }
        } finally {
            nonce.fill(ZERO_BYTE)
        }
    }

    private fun crl(context: StatusContext): AuthenticatedStatusEvidence? {
        val addresses =
            ValidationMaterialCollector.boundedCertificateAddresses(context.facts.revocationListUrls)
        for (address in addresses) {
            crlAtAddress(context, address)?.let { evidence -> return evidence }
        }
        return null
    }

    private fun crlAtAddress(
        context: StatusContext,
        address: String,
    ): AuthenticatedStatusEvidence? {
        val response =
            get(
                address = address,
                resource = ValidationMaterialGetResource.REVOCATION_LIST,
                dependencies = context.dependencies,
            ) ?: return null
        try {
            val verified =
                try {
                    CertificateRevocationList.verify(
                        input = response,
                        certificateDer = context.certificate,
                        issuerCertificateDer = context.issuer,
                        currentTime = context.currentTime,
                    )
                } catch (validation: RevocationListValidationException) {
                    if (validation.kind == RevocationListValidationFailure.REVOKED) {
                        throw AuthenticatedRevocationException()
                    }
                    return null
                }
            verified.use { authenticated ->
                return AuthenticatedStatusEvidence.takeOwnership(
                    kind = AuthenticatedStatusKind.REVOCATION_LIST,
                    encoding = authenticated.copyEncoding(),
                )
            }
        } finally {
            response.fill(ZERO_BYTE)
        }
    }

    private fun randomNonce(dependencies: ValidationMaterialCollectorDependencies): ByteArray? {
        val nonce =
            try {
                dependencies.random.generate(OcspRequest.NONCE_BYTE_COUNT)
            } catch (_: Exception) {
                return null
            }
        if (nonce.size != OcspRequest.NONCE_BYTE_COUNT) {
            nonce.fill(ZERO_BYTE)
            return null
        }
        return nonce
    }

    private fun ocspRequest(
        facts: CertificateFacts,
        issuerFacts: CertificateFacts,
        nonce: ByteArray,
    ): ByteArray =
        try {
            facts.useOcspIdentity { issuerName, serialNumber ->
                issuerFacts.usePublicKeyBits { issuerKeyBits ->
                    OcspRequest.encoded(
                        issuerName = issuerName,
                        issuerKeyBits = issuerKeyBits,
                        serialNumber = serialNumber,
                        nonce = nonce,
                    )
                }
            }
        } catch (_: IllegalArgumentException) {
            throw failure(ValidationMaterialCollectionFailure.CERTIFICATE_MALFORMED)
        }

    private fun post(
        request: ByteArray,
        address: String,
        dependencies: ValidationMaterialCollectorDependencies,
    ): ByteArray? =
        try {
            dependencies.post.send(request, address, OCSP_REQUEST_CONTENT_TYPE)
        } catch (_: Exception) {
            null
        }

    internal fun get(
        address: String,
        resource: ValidationMaterialGetResource,
        dependencies: ValidationMaterialCollectorDependencies,
    ): ByteArray? =
        try {
            dependencies.get.fetch(address, resource)
        } catch (_: Exception) {
            null
        }

    private fun failure(kind: ValidationMaterialCollectionFailure): ValidationMaterialCollectionException =
        ValidationMaterialCollectionException(kind)

    private data class StatusContext(
        val certificate: ByteArray,
        val facts: CertificateFacts,
        val issuer: ByteArray,
        val currentTime: Instant,
        val dependencies: ValidationMaterialCollectorDependencies,
    )

    private sealed interface OcspAddressResult {
        data class Success(
            val evidence: AuthenticatedStatusEvidence,
        ) : OcspAddressResult

        data object RandomFailure : OcspAddressResult

        data object Unavailable : OcspAddressResult
    }

    private class OcspAttempt private constructor(
        val evidence: AuthenticatedStatusEvidence?,
        val randomFailed: Boolean,
    ) {
        companion object {
            fun success(evidence: AuthenticatedStatusEvidence): OcspAttempt =
                OcspAttempt(evidence, randomFailed = false)

            fun noEvidence(): OcspAttempt = OcspAttempt(evidence = null, randomFailed = false)

            fun randomFailure(): OcspAttempt = OcspAttempt(evidence = null, randomFailed = true)
        }
    }

    private const val OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request"
    private const val ZERO_BYTE: Byte = 0
}
