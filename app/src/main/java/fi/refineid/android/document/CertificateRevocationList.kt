// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.GeneralSecurityException
import java.security.cert.CRLException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date

internal enum class RevocationListValidationFailure {
    CERTIFICATE_UNPARSEABLE,
    DELTA_UNSUPPORTED,
    INDIRECT_UNSUPPORTED,
    ISSUER_MISMATCH,
    ISSUER_UNAUTHORIZED,
    LIST_EXPIRED,
    LIST_FROM_FUTURE,
    MALFORMED,
    NEXT_UPDATE_MISSING,
    REVOKED,
    SCOPE_UNSUPPORTED,
    SIGNATURE_INVALID,
    UNSUPPORTED_CRITICAL_EXTENSION,
    UNSUPPORTED_SIGNATURE_ALGORITHM,
}

internal class RevocationListValidationException(
    val kind: RevocationListValidationFailure,
) : Exception(kind.name)

internal class VerifiedRevocationList internal constructor(
    private val ownedEncoding: ByteArray,
    val thisUpdate: Instant,
    val nextUpdate: Instant,
) : AutoCloseable {
    private var isClosed = false

    val encodedLength: Int
        get() = ownedEncoding.size

    fun copyEncoding(): ByteArray {
        check(!isClosed) {
            "verified revocation list is closed"
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
        "VerifiedRevocationList(length=" + encodedLength +
            ", thisUpdate=" + thisUpdate +
            ", nextUpdate=" + nextUpdate +
            ", closed=" + isClosed + ")"

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}

/** Authenticates one complete, direct X.509 certificate revocation list. */
internal object CertificateRevocationList {
    fun verify(
        input: ByteArray,
        certificateDer: ByteArray,
        issuerCertificateDer: ByteArray,
        currentTime: Instant,
    ): VerifiedRevocationList {
        val encoded = CertificateRevocationListInput.derEncoded(input)
        var transferred = false
        try {
            val certificate = parseCertificate(certificateDer)
            val issuer = parseCertificate(issuerCertificateDer)
            if (certificate == null || issuer == null) {
                throw failure(RevocationListValidationFailure.CERTIFICATE_UNPARSEABLE)
            }
            if (!issuerAllowsRevocationListSigning(issuer)) {
                throw failure(RevocationListValidationFailure.ISSUER_UNAUTHORIZED)
            }
            val list = parseRevocationList(encoded)
            requireSupportedSignatureAlgorithm(list)
            requireExactIssuerName(encoded, issuerCertificateDer)
            CertificateRevocationListPolicy.validate(list)
            verifySignature(list, issuer)
            val nextUpdate = requireCurrentTimes(list, currentTime)
            if (
                !CertificateIssuer.isDirectlyIssued(
                    certificateDer,
                    issuerCertificateDer,
                    currentTime,
                )
            ) {
                throw failure(RevocationListValidationFailure.ISSUER_MISMATCH)
            }
            if (list.getRevokedCertificate(certificate.serialNumber) != null) {
                throw failure(RevocationListValidationFailure.REVOKED)
            }
            return VerifiedRevocationList(
                ownedEncoding = encoded,
                thisUpdate = list.thisUpdate.toInstant(),
                nextUpdate = nextUpdate.toInstant(),
            ).also {
                transferred = true
            }
        } finally {
            if (!transferred) {
                encoded.fill(ZERO_BYTE)
            }
        }
    }

    private fun parseCertificate(encoded: ByteArray): X509Certificate? =
        try {
            val certificate =
                CertificateFactory
                    .getInstance(X509_CERTIFICATE_TYPE)
                    .generateCertificate(encoded.inputStream()) as? X509Certificate
            certificate?.takeIf { parsed -> parsed.encoded.contentEquals(encoded) }
        } catch (_: CertificateException) {
            null
        } catch (_: RuntimeException) {
            null
        }

    private fun parseRevocationList(encoded: ByteArray): X509CRL =
        try {
            val parsed =
                CertificateFactory
                    .getInstance(X509_CERTIFICATE_TYPE)
                    .generateCRL(encoded.inputStream()) as? X509CRL
                    ?: throw failure(RevocationListValidationFailure.MALFORMED)
            val canonical = parsed.encoded
            try {
                if (!canonical.contentEquals(encoded)) {
                    throw failure(RevocationListValidationFailure.MALFORMED)
                }
            } finally {
                canonical.fill(ZERO_BYTE)
            }
            parsed
        } catch (failure: RevocationListValidationException) {
            throw failure
        } catch (_: CRLException) {
            throw failure(RevocationListValidationFailure.MALFORMED)
        } catch (_: CertificateException) {
            throw failure(RevocationListValidationFailure.MALFORMED)
        } catch (_: RuntimeException) {
            throw failure(RevocationListValidationFailure.MALFORMED)
        }

    private fun issuerAllowsRevocationListSigning(issuer: X509Certificate): Boolean {
        val usage = issuer.keyUsage ?: return true
        return usage.getOrNull(REVOCATION_LIST_SIGNING_KEY_USAGE_INDEX) == true
    }

    private fun requireSupportedSignatureAlgorithm(list: X509CRL) {
        if (list.sigAlgOID !in SUPPORTED_SIGNATURE_ALGORITHMS) {
            throw failure(RevocationListValidationFailure.UNSUPPORTED_SIGNATURE_ALGORITHM)
        }
    }

    private fun requireExactIssuerName(
        encodedList: ByteArray,
        issuerCertificateDer: ByteArray,
    ) {
        val encodedIssuer = exactIssuerName(encodedList)
            ?: throw failure(RevocationListValidationFailure.MALFORMED)
        val issuerFacts = CertificateFacts.parse(issuerCertificateDer)
            ?: run {
                encodedIssuer.fill(ZERO_BYTE)
                throw failure(RevocationListValidationFailure.CERTIFICATE_UNPARSEABLE)
            }
        try {
            val matches = issuerFacts.useSubjectName { subjectName ->
                java.security.MessageDigest.isEqual(encodedIssuer, subjectName)
            }
            if (!matches) {
                throw failure(RevocationListValidationFailure.ISSUER_MISMATCH)
            }
        } finally {
            encodedIssuer.fill(ZERO_BYTE)
            issuerFacts.close()
        }
    }

    private fun exactIssuerName(encoded: ByteArray): ByteArray? {
        val envelope = listEnvelope(encoded) ?: return null
        return envelope.use { parsed ->
            issuerNameFromTbs(encoded, parsed)
        }
    }

    private fun listEnvelope(encoded: ByteArray): ListEnvelope? {
        val outer = DerReader(encoded)
        val list = outer.next() ?: return null
        if (list.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
            return null
        }
        val listFields = outer.children(list)
        val tbs = listFields.next() ?: return null
        val outerAlgorithm = listFields.next() ?: return null
        val signature = listFields.next() ?: return null
        val outerTagsAreValid =
            tbs.tag == DerValues.TAG_SEQUENCE &&
                outerAlgorithm.tag == DerValues.TAG_SEQUENCE &&
                signature.tag == DerValues.TAG_BIT_STRING
        if (!outerTagsAreValid || !listFields.isAtEnd || !validSignatureBits(listFields, signature)) {
            return null
        }
        return ListEnvelope(
            tbs = tbs,
            outerAlgorithm = listFields.raw(outerAlgorithm),
        )
    }

    private fun issuerNameFromTbs(
        encoded: ByteArray,
        envelope: ListEnvelope,
    ): ByteArray? {
        val fields = DerReader(encoded).children(envelope.tbs)
        var innerAlgorithm = fields.next() ?: return null
        if (innerAlgorithm.tag == DerValues.TAG_INTEGER) {
            if (!isVersionTwo(fields, innerAlgorithm)) {
                return null
            }
            innerAlgorithm = fields.next() ?: return null
        }
        val issuerName = fields.next() ?: return null
        if (innerAlgorithm.tag != DerValues.TAG_SEQUENCE || issuerName.tag != DerValues.TAG_SEQUENCE) {
            return null
        }
        val innerAlgorithmEncoding = fields.raw(innerAlgorithm)
        val algorithmsMatch =
            try {
                innerAlgorithmEncoding.contentEquals(envelope.outerAlgorithm)
            } finally {
                innerAlgorithmEncoding.fill(ZERO_BYTE)
            }
        return if (algorithmsMatch) fields.raw(issuerName) else null
    }

    private fun validSignatureBits(
        reader: DerReader,
        signature: DerReader.Element,
    ): Boolean {
        val content = reader.content(signature)
        return try {
            content.size > BIT_STRING_PREFIX_BYTES && content[UNUSED_BIT_COUNT_OFFSET] == NO_UNUSED_BITS
        } finally {
            content.fill(ZERO_BYTE)
        }
    }

    private fun isVersionTwo(
        reader: DerReader,
        version: DerReader.Element,
    ): Boolean {
        val content = reader.content(version)
        return try {
            content.contentEquals(VERSION_TWO_CONTENT)
        } finally {
            content.fill(ZERO_BYTE)
        }
    }

    private fun verifySignature(
        list: X509CRL,
        issuer: X509Certificate,
    ) {
        try {
            list.verify(issuer.publicKey)
        } catch (_: GeneralSecurityException) {
            throw failure(RevocationListValidationFailure.SIGNATURE_INVALID)
        } catch (_: RuntimeException) {
            throw failure(RevocationListValidationFailure.SIGNATURE_INVALID)
        }
    }

    private fun requireCurrentTimes(
        list: X509CRL,
        currentTime: Instant,
    ): Date {
        val thisUpdate = list.thisUpdate
        val nextUpdate = list.nextUpdate
            ?: throw failure(RevocationListValidationFailure.NEXT_UPDATE_MISSING)
        if (thisUpdate.toInstant().isAfter(currentTime)) {
            throw failure(RevocationListValidationFailure.LIST_FROM_FUTURE)
        }
        if (!nextUpdate.after(thisUpdate) || !nextUpdate.toInstant().isAfter(currentTime)) {
            throw failure(RevocationListValidationFailure.LIST_EXPIRED)
        }
        return nextUpdate
    }

    private fun failure(kind: RevocationListValidationFailure): RevocationListValidationException =
        RevocationListValidationException(kind)

    private class ListEnvelope(
        val tbs: DerReader.Element,
        val outerAlgorithm: ByteArray,
    ) : AutoCloseable {
        override fun close() {
            outerAlgorithm.fill(ZERO_BYTE)
        }
    }

    private const val X509_CERTIFICATE_TYPE = "X.509"
    private const val REVOCATION_LIST_SIGNING_KEY_USAGE_INDEX = 6
    private const val BIT_STRING_PREFIX_BYTES = 1
    private const val UNUSED_BIT_COUNT_OFFSET = 0
    private const val NO_UNUSED_BITS: Byte = 0
    private const val ZERO_BYTE: Byte = 0

    private val VERSION_TWO_CONTENT = byteArrayOf(1)
    private val SUPPORTED_SIGNATURE_ALGORITHMS =
        setOf(
            RevocationListOids.SHA256_WITH_RSA,
            RevocationListOids.SHA384_WITH_RSA,
            RevocationListOids.SHA512_WITH_RSA,
            RevocationListOids.ECDSA_WITH_SHA256,
            RevocationListOids.ECDSA_WITH_SHA384,
            RevocationListOids.ECDSA_WITH_SHA512,
        )
}
