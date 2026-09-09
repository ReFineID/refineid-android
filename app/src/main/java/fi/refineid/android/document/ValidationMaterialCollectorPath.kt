// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.time.Instant

/** Bounded certificate-path construction for validation-material collection. */
internal object ValidationMaterialCollectorPath {
    fun walk(
        start: ValidationChainStart,
        evidenceTime: Instant,
        collection: ValidationMaterialCollection,
        dependencies: ValidationMaterialCollectorDependencies,
    ) {
        val context = PathContext(start, evidenceTime, collection, dependencies)
        var current = start.copyCertificate()
        val visited = mutableListOf<ByteArray>()
        try {
            for (depth in INITIAL_PATH_DEPTH until ValidationMaterialCollector.MAXIMUM_DEPTH) {
                if (visited.any { certificate -> certificate.contentEquals(current) }) {
                    throw failure(ValidationMaterialCollectionFailure.CHAIN_CYCLE)
                }
                visited += current.copyOf()
                val next = nextCertificate(current, depth, context) ?: return
                current.fill(ZERO_BYTE)
                current = next
            }
            throw failure(ValidationMaterialCollectionFailure.CHAIN_TOO_DEEP)
        } finally {
            current.fill(ZERO_BYTE)
            visited.forEach { certificate -> certificate.fill(ZERO_BYTE) }
        }
    }

    private fun nextCertificate(
        current: ByteArray,
        depth: Int,
        context: PathContext,
    ): ByteArray? {
        val facts =
            CertificateFacts.parse(current)
                ?: throw failure(ValidationMaterialCollectionFailure.CERTIFICATE_MALFORMED)
        facts.use { parsed ->
            if (!context.start.hasTrustAnchor) {
                throw failure(ValidationMaterialCollectionFailure.TRUST_ANCHOR_UNAVAILABLE)
            }
            if (context.start.trusts(current)) {
                context.collection.addCertificate(current)
                enrichAboveAnchor(
                    anchor = current,
                    context =
                        EnrichmentContext(
                            referenceTime = context.start.referenceTime,
                            evidenceTime = context.evidenceTime,
                            maximumAdditionalDepth =
                                ValidationMaterialCollector.MAXIMUM_DEPTH - depth - PATH_NODE_COUNT,
                            collection = context.collection,
                            dependencies = context.dependencies,
                        ),
                )
                return null
            }
            val issuer =
                issuer(
                    certificate = current,
                    facts = parsed,
                    referenceTime = context.start.referenceTime,
                    collection = context.collection,
                    dependencies = context.dependencies,
                )
            var transferred = false
            return try {
                context.collection.addCertificate(issuer)
                if (!context.collection.isChecked(current)) {
                    ValidationMaterialCollectorStatus
                        .authenticate(
                            certificate = current,
                            facts = parsed,
                            issuer = issuer,
                            currentTime = context.evidenceTime,
                            dependencies = context.dependencies,
                        ).use { evidence ->
                            context.collection.addEvidence(evidence)
                        }
                    context.collection.markChecked(current)
                }
                transferred = true
                issuer
            } finally {
                if (!transferred) {
                    issuer.fill(ZERO_BYTE)
                }
            }
        }
    }

    private fun issuer(
        certificate: ByteArray,
        facts: CertificateFacts,
        referenceTime: Instant,
        collection: ValidationMaterialCollection,
        dependencies: ValidationMaterialCollectorDependencies,
    ): ByteArray {
        collection.directIssuer(certificate, referenceTime)?.let { issuer -> return issuer }
        val addresses = ValidationMaterialCollector.boundedCertificateAddresses(facts.issuerCertificateUrls)
        for (address in addresses) {
            fetchedIssuer(certificate, address, referenceTime, collection, dependencies)?.let { issuer ->
                return issuer
            }
        }
        throw failure(ValidationMaterialCollectionFailure.ISSUER_UNAVAILABLE)
    }

    private fun fetchedIssuer(
        certificate: ByteArray,
        address: String,
        referenceTime: Instant,
        collection: ValidationMaterialCollection,
        dependencies: ValidationMaterialCollectorDependencies,
    ): ByteArray? {
        val body =
            ValidationMaterialCollectorStatus.get(
                address = address,
                resource = ValidationMaterialGetResource.CERTIFICATE,
                dependencies = dependencies,
            ) ?: return null
        var candidate: ByteArray? = null
        var transferred = false
        try {
            candidate = ValidationCertificateInput.derEncoded(body) ?: return null
            if (!CertificateIssuer.isDirectlyIssued(certificate, candidate, referenceTime)) {
                return null
            }
            collection.addCandidate(candidate)
            transferred = true
            return candidate
        } finally {
            body.fill(ZERO_BYTE)
            if (!transferred) {
                candidate?.fill(ZERO_BYTE)
            }
        }
    }

    private fun enrichAboveAnchor(
        anchor: ByteArray,
        context: EnrichmentContext,
    ) {
        var current = anchor.copyOf()
        val visited = mutableListOf<ByteArray>()
        try {
            repeat(context.maximumAdditionalDepth) {
                if (visited.any { certificate -> certificate.contentEquals(current) }) {
                    return
                }
                visited += current.copyOf()
                val parent = enrichmentParent(current, context) ?: return
                var transferred = false
                try {
                    if (!addEnrichmentParent(parent, context.collection)) {
                        return
                    }
                    authenticateEnrichmentStatus(current, parent, context)
                    current.fill(ZERO_BYTE)
                    current = parent
                    transferred = true
                } finally {
                    if (!transferred) {
                        parent.fill(ZERO_BYTE)
                    }
                }
            }
        } finally {
            current.fill(ZERO_BYTE)
            visited.forEach { certificate -> certificate.fill(ZERO_BYTE) }
        }
    }

    private fun enrichmentParent(
        current: ByteArray,
        context: EnrichmentContext,
    ): ByteArray? {
        val facts = CertificateFacts.parse(current) ?: return null
        return facts.use { parsed ->
            try {
                issuer(
                    certificate = current,
                    facts = parsed,
                    referenceTime = context.referenceTime,
                    collection = context.collection,
                    dependencies = context.dependencies,
                )
            } catch (_: ValidationMaterialCollectionException) {
                null
            }
        }
    }

    private fun addEnrichmentParent(
        parent: ByteArray,
        collection: ValidationMaterialCollection,
    ): Boolean =
        try {
            collection.addCertificate(parent)
            true
        } catch (_: ValidationMaterialCollectionException) {
            false
        }

    private fun authenticateEnrichmentStatus(
        current: ByteArray,
        parent: ByteArray,
        context: EnrichmentContext,
    ) {
        if (context.collection.isChecked(current)) {
            return
        }
        val facts = CertificateFacts.parse(current) ?: return
        facts.use { parsed ->
            try {
                ValidationMaterialCollectorStatus
                    .authenticate(
                        certificate = current,
                        facts = parsed,
                        issuer = parent,
                        currentTime = context.evidenceTime,
                        dependencies = context.dependencies,
                    ).use { evidence ->
                        context.collection.addEvidence(evidence)
                    }
                context.collection.markChecked(current)
            } catch (_: ValidationMaterialCollectionException) {
                Unit
            } catch (_: AuthenticatedRevocationException) {
                Unit
            }
        }
    }

    private fun failure(kind: ValidationMaterialCollectionFailure): ValidationMaterialCollectionException =
        ValidationMaterialCollectionException(kind)

    private data class PathContext(
        val start: ValidationChainStart,
        val evidenceTime: Instant,
        val collection: ValidationMaterialCollection,
        val dependencies: ValidationMaterialCollectorDependencies,
    )

    private data class EnrichmentContext(
        val referenceTime: Instant,
        val evidenceTime: Instant,
        val maximumAdditionalDepth: Int,
        val collection: ValidationMaterialCollection,
        val dependencies: ValidationMaterialCollectorDependencies,
    )

    private const val INITIAL_PATH_DEPTH = 0
    private const val PATH_NODE_COUNT = 1
    private const val ZERO_BYTE: Byte = 0
}
