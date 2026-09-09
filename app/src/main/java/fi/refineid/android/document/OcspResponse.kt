// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.time.Instant

internal enum class OcspResponseValidationFailure {
    CERTIFICATE_MISMATCH,
    CERTIFICATE_UNPARSEABLE,
    ISSUER_MISMATCH,
    MALFORMED,
    NONCE_MALFORMED,
    NONCE_MISMATCH,
    REJECTED,
    RESPONDER_REVOCATION_UNCHECKED,
    RESPONDER_UNAUTHORIZED,
    RESPONDER_UNIDENTIFIED,
    RESPONSE_EXPIRED,
    RESPONSE_FROM_FUTURE,
    REVOKED,
    SIGNATURE_INVALID,
    UNKNOWN,
    UNSUPPORTED_CRITICAL_EXTENSION,
    UNSUPPORTED_RESPONSE_TYPE,
    UNSUPPORTED_SIGNATURE_ALGORITHM,
}

internal class OcspResponseValidationException(
    val kind: OcspResponseValidationFailure,
    val responderStatus: Int? = null,
) : Exception(kind.name)

internal class VerifiedOcspResponse internal constructor(
    private val ownedEncoding: ByteArray,
    val producedAt: Instant,
    val thisUpdate: Instant,
    val nextUpdate: Instant?,
) : AutoCloseable {
    private var isClosed = false

    val encodedLength: Int
        get() = ownedEncoding.size

    fun copyEncoding(): ByteArray {
        check(!isClosed) {
            "verified OCSP response is closed"
        }
        return ownedEncoding.copyOf()
    }

    override fun close() {
        if (!isClosed) {
            ownedEncoding.fill(ZERO_BYTE)
            isClosed = true
        }
    }

    override fun toString(): String =
        "VerifiedOcspResponse(length=" + encodedLength +
            ", producedAt=" + producedAt +
            ", thisUpdate=" + thisUpdate +
            ", hasNextUpdate=" + (nextUpdate != null) +
            ", closed=" + isClosed + ")"

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}

internal enum class OcspCertificateStatus {
    GOOD,
    REVOKED,
    UNKNOWN,
}

internal sealed interface OcspResponderId : AutoCloseable {
    fun matches(facts: CertificateFacts): Boolean

    class ByName(
        private val ownedName: ByteArray,
    ) : OcspResponderId {
        override fun matches(facts: CertificateFacts): Boolean =
            facts.useSubjectName { subjectName -> MessageDigest.isEqual(ownedName, subjectName) }

        override fun close() {
            ownedName.fill(ZERO_BYTE)
        }
    }

    class ByKey(
        private val ownedHash: ByteArray,
    ) : OcspResponderId {
        override fun matches(facts: CertificateFacts): Boolean =
            facts.usePublicKeyBits { publicKeyBits ->
                val actual = MessageDigest.getInstance(SHA1_JAVA_NAME).digest(publicKeyBits)
                try {
                    MessageDigest.isEqual(ownedHash, actual)
                } finally {
                    actual.fill(ZERO_BYTE)
                }
            }

        override fun close() {
            ownedHash.fill(ZERO_BYTE)
        }
    }

    private companion object {
        const val SHA1_JAVA_NAME = "SHA-1"
        const val ZERO_BYTE: Byte = 0
    }
}

internal class ParsedOcspResponseData(
    val nextUpdate: Instant?,
    val producedAt: Instant,
    private val ownedRaw: ByteArray,
    val responderId: OcspResponderId,
    val status: OcspCertificateStatus,
    val thisUpdate: Instant,
) : AutoCloseable {
    fun copyRaw(): ByteArray = ownedRaw.copyOf()

    override fun close() {
        ownedRaw.fill(ZERO_BYTE)
        responderId.close()
    }

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}

internal class ParsedBasicOcspResponse(
    val responseData: ParsedOcspResponseData,
    private val ownedSignatureAlgorithm: ByteArray,
    private val ownedSignature: ByteArray,
    private val ownedCertificates: List<ByteArray>,
) : AutoCloseable {
    fun copySignatureAlgorithm(): ByteArray = ownedSignatureAlgorithm.copyOf()

    fun copySignature(): ByteArray = ownedSignature.copyOf()

    fun copyCertificates(): List<ByteArray> = ownedCertificates.map(ByteArray::copyOf)

    override fun close() {
        responseData.close()
        ownedSignatureAlgorithm.fill(ZERO_BYTE)
        ownedSignature.fill(ZERO_BYTE)
        ownedCertificates.forEach { certificate -> certificate.fill(ZERO_BYTE) }
    }

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}

internal class ExpectedOcspCertificateId private constructor(
    private val ownedIssuerNameHash: ByteArray,
    private val ownedIssuerKeyHash: ByteArray,
    private val ownedSerialNumber: ByteArray,
) : AutoCloseable {
    fun matches(
        issuerNameHash: ByteArray,
        issuerKeyHash: ByteArray,
        serialNumber: ByteArray,
    ): Boolean =
        MessageDigest.isEqual(ownedIssuerNameHash, issuerNameHash) &&
            MessageDigest.isEqual(ownedIssuerKeyHash, issuerKeyHash) &&
            MessageDigest.isEqual(ownedSerialNumber, serialNumber)

    override fun close() {
        ownedIssuerNameHash.fill(ZERO_BYTE)
        ownedIssuerKeyHash.fill(ZERO_BYTE)
        ownedSerialNumber.fill(ZERO_BYTE)
    }

    companion object {
        fun create(
            target: CertificateFacts,
            issuer: CertificateFacts,
        ): ExpectedOcspCertificateId =
            target.useOcspIdentity { issuerName, serialNumber ->
                issuer.usePublicKeyBits { issuerKeyBits ->
                    ExpectedOcspCertificateId(
                        ownedIssuerNameHash = sha1(issuerName),
                        ownedIssuerKeyHash = sha1(issuerKeyBits),
                        ownedSerialNumber = serialNumber.copyOf(),
                    )
                }
            }

        private fun sha1(value: ByteArray): ByteArray = MessageDigest.getInstance(SHA1_JAVA_NAME).digest(value)

        private const val SHA1_JAVA_NAME = "SHA-1"
        private const val ZERO_BYTE: Byte = 0
    }
}

/** Authenticates one nonce-bound OCSP response for an exact target and issuer. */
internal object OcspResponse {
    fun verify(
        response: ByteArray,
        certificateDer: ByteArray,
        issuerCertificateDer: ByteArray,
        nonce: ByteArray,
        currentTime: Instant,
    ): VerifiedOcspResponse {
        if (nonce.isEmpty() || nonce.size > MAXIMUM_NONCE_BYTE_COUNT) {
            throw failure(OcspResponseValidationFailure.NONCE_MALFORMED)
        }
        if (response.isEmpty() || response.size > PdfValidationMaterialLimits.MAXIMUM_OCSP_RESPONSE_BYTES) {
            throw failure(OcspResponseValidationFailure.MALFORMED)
        }
        val ownedResponse = response.copyOf()
        var transferred = false
        try {
            val target =
                ResponderCertificate.parse(certificateDer)
                    ?: throw failure(OcspResponseValidationFailure.CERTIFICATE_UNPARSEABLE)
            val issuer =
                ResponderCertificate.parse(issuerCertificateDer)
                    ?: run {
                        target.close()
                        throw failure(OcspResponseValidationFailure.CERTIFICATE_UNPARSEABLE)
                    }
            target.use { parsedTarget ->
                issuer.use { parsedIssuer ->
                    val expected = ExpectedOcspCertificateId.create(parsedTarget.facts, parsedIssuer.facts)
                    expected.use { certificateId ->
                        val basic = OcspResponseEnvelopeParser.parse(ownedResponse, certificateId, nonce)
                        basic.use { parsedBasic ->
                            OcspResponseTime.requireCurrent(parsedBasic.responseData, currentTime)
                            requireDirectIssuer(
                                certificateDer,
                                issuerCertificateDer,
                                parsedBasic.responseData.producedAt,
                            )
                            val signatureAlgorithm =
                                parsedBasic.copySignatureAlgorithm().useBytes(OcspSignatureAlgorithms::parse)
                            val responders = authorizedResponders(parsedBasic, parsedIssuer)
                            responders.useAll { candidates ->
                                verifyResponderSignature(parsedBasic, candidates, signatureAlgorithm)
                            }
                            val verified = statusResult(ownedResponse, parsedBasic.responseData)
                            transferred = true
                            return verified
                        }
                    }
                }
            }
        } finally {
            if (!transferred) {
                ownedResponse.fill(ZERO_BYTE)
            }
        }
    }

    private fun requireDirectIssuer(
        certificateDer: ByteArray,
        issuerCertificateDer: ByteArray,
        producedAt: Instant,
    ) {
        if (!CertificateIssuer.isDirectlyIssued(certificateDer, issuerCertificateDer, producedAt)) {
            throw failure(OcspResponseValidationFailure.ISSUER_MISMATCH)
        }
    }

    private fun authorizedResponders(
        basic: ParsedBasicOcspResponse,
        issuer: ResponderCertificate,
    ): List<ResponderCertificate> {
        val embedded = basic.copyCertificates()
        val candidates = mutableListOf<ResponderCertificate>()
        try {
            candidates += issuer.copyCandidate()
            for (encoded in embedded) {
                val candidate =
                    ResponderCertificate.parse(encoded)
                        ?: throw failure(OcspResponseValidationFailure.CERTIFICATE_UNPARSEABLE)
                if (candidates.none { existing -> existing.encodingEquals(encoded) }) {
                    candidates += candidate
                } else {
                    candidate.close()
                }
            }
            val matching = candidates.filter { candidate -> basic.responseData.responderId.matches(candidate.facts) }
            if (matching.isEmpty()) {
                throw failure(OcspResponseValidationFailure.RESPONDER_UNIDENTIFIED)
            }
            val authorized = mutableListOf<ResponderCertificate>()
            var needsRevocationEvidence = false
            for (candidate in matching) {
                when (candidate.authorizationBy(issuer, basic.responseData.producedAt)) {
                    ResponderAuthorization.AUTHORIZED -> authorized += candidate.copyCandidate()
                    ResponderAuthorization.REVOCATION_CHECK_REQUIRED -> needsRevocationEvidence = true
                    ResponderAuthorization.UNAUTHORIZED -> Unit
                }
            }
            if (authorized.isEmpty()) {
                val kind =
                    if (needsRevocationEvidence) {
                        OcspResponseValidationFailure.RESPONDER_REVOCATION_UNCHECKED
                    } else {
                        OcspResponseValidationFailure.RESPONDER_UNAUTHORIZED
                    }
                throw failure(kind)
            }
            return authorized
        } finally {
            embedded.forEach { encoded -> encoded.fill(ZERO_BYTE) }
            candidates.forEach(ResponderCertificate::close)
        }
    }

    private fun verifyResponderSignature(
        basic: ParsedBasicOcspResponse,
        candidates: List<ResponderCertificate>,
        algorithm: String,
    ) {
        val signed = basic.responseData.copyRaw()
        val signature = basic.copySignature()
        try {
            val valid =
                candidates.any { candidate ->
                    try {
                        Signature.getInstance(algorithm).run {
                            initVerify(candidate.certificate.publicKey)
                            update(signed)
                            verify(signature)
                        }
                    } catch (_: GeneralSecurityException) {
                        false
                    } catch (_: RuntimeException) {
                        false
                    }
                }
            if (!valid) {
                throw failure(OcspResponseValidationFailure.SIGNATURE_INVALID)
            }
        } finally {
            signed.fill(ZERO_BYTE)
            signature.fill(ZERO_BYTE)
        }
    }

    private fun statusResult(
        ownedResponse: ByteArray,
        data: ParsedOcspResponseData,
    ): VerifiedOcspResponse =
        when (data.status) {
            OcspCertificateStatus.GOOD -> {
                VerifiedOcspResponse(
                    ownedEncoding = ownedResponse,
                    producedAt = data.producedAt,
                    thisUpdate = data.thisUpdate,
                    nextUpdate = data.nextUpdate,
                )
            }

            OcspCertificateStatus.REVOKED -> {
                throw failure(OcspResponseValidationFailure.REVOKED)
            }

            OcspCertificateStatus.UNKNOWN -> {
                throw failure(OcspResponseValidationFailure.UNKNOWN)
            }
        }

    private fun failure(kind: OcspResponseValidationFailure): OcspResponseValidationException =
        OcspResponseValidationException(kind)

    private inline fun <R> ByteArray.useBytes(operation: (ByteArray) -> R): R =
        try {
            operation(this)
        } finally {
            fill(ZERO_BYTE)
        }

    private inline fun <T : AutoCloseable, R> List<T>.useAll(operation: (List<T>) -> R): R =
        try {
            operation(this)
        } finally {
            forEach(AutoCloseable::close)
        }

    private const val MAXIMUM_NONCE_BYTE_COUNT = 128
    private const val ZERO_BYTE: Byte = 0
}

internal enum class ResponderAuthorization {
    AUTHORIZED,
    REVOCATION_CHECK_REQUIRED,
    UNAUTHORIZED,
}

internal class ResponderCertificate private constructor(
    private val ownedEncoding: ByteArray,
    val certificate: X509Certificate,
    val facts: CertificateFacts,
) : AutoCloseable {
    fun encodingEquals(other: ByteArray): Boolean = MessageDigest.isEqual(ownedEncoding, other)

    fun copyCandidate(): ResponderCertificate =
        parse(ownedEncoding) ?: throw OcspResponseValidationException(
            OcspResponseValidationFailure.CERTIFICATE_UNPARSEABLE,
        )

    fun authorizationBy(
        issuer: ResponderCertificate,
        producedAt: Instant,
    ): ResponderAuthorization {
        if (encodingEquals(issuer.ownedEncoding)) {
            return ResponderAuthorization.AUTHORIZED
        }
        if (!isPermittedDelegatedResponder(issuer, producedAt)) {
            return ResponderAuthorization.UNAUTHORIZED
        }
        return if (hasValidNoCheckExtension()) {
            ResponderAuthorization.AUTHORIZED
        } else {
            ResponderAuthorization.REVOCATION_CHECK_REQUIRED
        }
    }

    override fun close() {
        ownedEncoding.fill(ZERO_BYTE)
        facts.close()
    }

    private fun isPermittedDelegatedResponder(
        issuer: ResponderCertificate,
        producedAt: Instant,
    ): Boolean {
        if (certificate.basicConstraints != END_ENTITY_BASIC_CONSTRAINTS) {
            return false
        }
        if (!CertificateIssuer.isDirectlyIssued(ownedEncoding, issuer.ownedEncoding, producedAt)) {
            return false
        }
        val extendedUsage =
            try {
                certificate.extendedKeyUsage
            } catch (_: CertificateParsingException) {
                return false
            } ?: return false
        if (OcspOids.OCSP_SIGNING_KEY_PURPOSE !in extendedUsage) {
            return false
        }
        val usage = certificate.keyUsage
        return usage == null || usage.getOrNull(DIGITAL_SIGNATURE_KEY_USAGE_INDEX) == true
    }

    private fun hasValidNoCheckExtension(): Boolean {
        val value = CertificateExtensionReader.value(ownedEncoding, OcspOids.OCSP_NO_CHECK) ?: return false
        return try {
            val nullValue = DerReader.single(value) ?: return false
            nullValue.tag == DerValues.TAG_NULL && nullValue.contentStart == nullValue.contentEnd
        } finally {
            value.fill(ZERO_BYTE)
        }
    }

    companion object {
        fun parse(encoded: ByteArray): ResponderCertificate? {
            if (encoded.isEmpty() || encoded.size > PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES) {
                return null
            }
            val facts = CertificateFacts.parse(encoded) ?: return null
            return try {
                val parsed =
                    CertificateFactory
                        .getInstance(X509_CERTIFICATE_TYPE)
                        .generateCertificate(encoded.inputStream()) as? X509Certificate
                val canonical = parsed?.encoded
                val exact = canonical?.contentEquals(encoded) == true
                canonical?.fill(ZERO_BYTE)
                if (parsed == null || !exact) {
                    facts.close()
                    null
                } else {
                    ResponderCertificate(encoded.copyOf(), parsed, facts)
                }
            } catch (_: CertificateException) {
                facts.close()
                null
            } catch (_: RuntimeException) {
                facts.close()
                null
            }
        }

        private const val X509_CERTIFICATE_TYPE = "X.509"
        private const val END_ENTITY_BASIC_CONSTRAINTS = -1
        private const val DIGITAL_SIGNATURE_KEY_USAGE_INDEX = 0
        private const val ZERO_BYTE: Byte = 0
    }
}

internal object OcspSignatureAlgorithms {
    fun parse(encoded: ByteArray): String {
        val outer = DerReader(encoded)
        val sequence =
            outer.next()
                ?: throw failure(OcspResponseValidationFailure.UNSUPPORTED_SIGNATURE_ALGORITHM)
        if (sequence.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
            throw failure(OcspResponseValidationFailure.UNSUPPORTED_SIGNATURE_ALGORITHM)
        }
        val fields = outer.children(sequence)
        val identifier =
            fields.next()
                ?: throw failure(OcspResponseValidationFailure.UNSUPPORTED_SIGNATURE_ALGORITHM)
        if (identifier.tag != DerValues.TAG_OBJECT_IDENTIFIER) {
            throw failure(OcspResponseValidationFailure.UNSUPPORTED_SIGNATURE_ALGORITHM)
        }
        val oid = fields.raw(identifier)
        try {
            val algorithm =
                SIGNATURE_ALGORITHMS.firstOrNull { candidate ->
                    oid.contentEquals(candidate.encodedIdentifier)
                } ?: throw failure(OcspResponseValidationFailure.UNSUPPORTED_SIGNATURE_ALGORITHM)
            val parameters = fields.next()
            if (!algorithm.parametersAreValid(fields, parameters)) {
                throw failure(OcspResponseValidationFailure.UNSUPPORTED_SIGNATURE_ALGORITHM)
            }
            return algorithm.javaName
        } finally {
            oid.fill(ZERO_BYTE)
        }
    }

    private fun failure(kind: OcspResponseValidationFailure): OcspResponseValidationException =
        OcspResponseValidationException(kind)

    private class Algorithm(
        identifier: String,
        val javaName: String,
        private val requiresNullParameters: Boolean,
    ) {
        val encodedIdentifier: ByteArray = DerEncoder.objectIdentifier(identifier)

        fun parametersAreValid(
            reader: DerReader,
            parameters: DerReader.Element?,
        ): Boolean =
            if (requiresNullParameters) {
                parameters?.tag == DerValues.TAG_NULL &&
                    parameters.contentStart == parameters.contentEnd &&
                    reader.isAtEnd
            } else {
                parameters == null && reader.isAtEnd
            }
    }

    private const val ZERO_BYTE: Byte = 0
    private val SIGNATURE_ALGORITHMS =
        listOf(
            Algorithm(OcspOids.SHA256_WITH_RSA, "SHA256withRSA", requiresNullParameters = true),
            Algorithm(OcspOids.SHA384_WITH_RSA, "SHA384withRSA", requiresNullParameters = true),
            Algorithm(OcspOids.SHA512_WITH_RSA, "SHA512withRSA", requiresNullParameters = true),
            Algorithm(OcspOids.ECDSA_WITH_SHA256, "SHA256withECDSA", requiresNullParameters = false),
            Algorithm(OcspOids.ECDSA_WITH_SHA384, "SHA384withECDSA", requiresNullParameters = false),
            Algorithm(OcspOids.ECDSA_WITH_SHA512, "SHA512withECDSA", requiresNullParameters = false),
        )
}

internal object OcspOids {
    const val BASIC_RESPONSE = "1.3.6.1.5.5.7.48.1.1"
    const val OCSP_NO_CHECK = "1.3.6.1.5.5.7.48.1.5"
    const val OCSP_SIGNING_KEY_PURPOSE = "1.3.6.1.5.5.7.3.9"
    const val SHA256_WITH_RSA = RevocationListOids.SHA256_WITH_RSA
    const val SHA384_WITH_RSA = RevocationListOids.SHA384_WITH_RSA
    const val SHA512_WITH_RSA = RevocationListOids.SHA512_WITH_RSA
    const val ECDSA_WITH_SHA256 = RevocationListOids.ECDSA_WITH_SHA256
    const val ECDSA_WITH_SHA384 = RevocationListOids.ECDSA_WITH_SHA384
    const val ECDSA_WITH_SHA512 = RevocationListOids.ECDSA_WITH_SHA512
}
