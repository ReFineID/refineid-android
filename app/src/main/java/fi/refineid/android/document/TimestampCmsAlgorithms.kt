// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.MessageDigest
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

private const val SHA256_DIGEST_BYTE_COUNT = 32
private const val SHA384_DIGEST_BYTE_COUNT = 48
private const val SHA512_DIGEST_BYTE_COUNT = 64

/** SHA-2 algorithms accepted for the CMS signature around an RFC 3161 token. */
internal enum class TimestampCmsDigest(
    val objectIdentifier: String,
    val javaName: String,
    val byteCount: Int,
) {
    SHA256(
        objectIdentifier = TimestampCmsOids.SHA256,
        javaName = "SHA-256",
        byteCount = SHA256_DIGEST_BYTE_COUNT,
    ),
    SHA384(
        objectIdentifier = QualifiedCmsOids.SHA384,
        javaName = "SHA-384",
        byteCount = SHA384_DIGEST_BYTE_COUNT,
    ),
    SHA512(
        objectIdentifier = TimestampCmsOids.SHA512,
        javaName = "SHA-512",
        byteCount = SHA512_DIGEST_BYTE_COUNT,
    ),
    ;

    fun digest(content: ByteArray): ByteArray = MessageDigest.getInstance(javaName).digest(content)

    val mgfSpecification: MGF1ParameterSpec
        get() =
            when (this) {
                SHA256 -> MGF1ParameterSpec.SHA256
                SHA384 -> MGF1ParameterSpec.SHA384
                SHA512 -> MGF1ParameterSpec.SHA512
            }
}

/** A JCA signature algorithm after its CMS parameters have been checked. */
internal class TimestampCmsSignatureAlgorithm private constructor(
    private val javaName: String,
    private val pssParameters: PSSParameterSpec?,
) {
    fun verifier(): Signature =
        Signature.getInstance(javaName).also { verifier ->
            pssParameters?.let(verifier::setParameter)
        }

    companion object {
        fun ecdsa(digest: TimestampCmsDigest): TimestampCmsSignatureAlgorithm =
            TimestampCmsSignatureAlgorithm(
                javaName = digest.javaName.withoutHyphen() + "withECDSA",
                pssParameters = null,
            )

        fun rsaPkcs1(digest: TimestampCmsDigest): TimestampCmsSignatureAlgorithm =
            TimestampCmsSignatureAlgorithm(
                javaName = digest.javaName.withoutHyphen() + "withRSA",
                pssParameters = null,
            )

        fun rsaPss(digest: TimestampCmsDigest): TimestampCmsSignatureAlgorithm =
            TimestampCmsSignatureAlgorithm(
                javaName = RSA_PSS_JAVA_NAME,
                pssParameters =
                    PSSParameterSpec(
                        digest.javaName,
                        MASK_GENERATION_FUNCTION_NAME,
                        digest.mgfSpecification,
                        digest.byteCount,
                        PSS_TRAILER_FIELD,
                    ),
            )

        private fun String.withoutHyphen(): String = replace(HYPHEN, EMPTY_TEXT)

        private const val RSA_PSS_JAVA_NAME = "RSASSA-PSS"
        private const val MASK_GENERATION_FUNCTION_NAME = "MGF1"
        private const val PSS_TRAILER_FIELD = 1
        private const val HYPHEN = "-"
        private const val EMPTY_TEXT = ""
    }
}

/** Strict parsing of the digest and signature AlgorithmIdentifiers used by TSA CMS. */
internal object TimestampCmsAlgorithmParser {
    fun digest(encoded: ByteArray): TimestampCmsDigest {
        val fields = algorithmIdentifierFields(encoded)
        try {
            requireAbsentOrNull(fields.parameters)
            return TimestampCmsDigest.entries.firstOrNull { digest ->
                fields.identifier.contentEquals(DerEncoder.objectIdentifier(digest.objectIdentifier))
            } ?: throw invalidSignature()
        } finally {
            fields.close()
        }
    }

    fun signature(
        encoded: ByteArray,
        digest: TimestampCmsDigest,
    ): TimestampCmsSignatureAlgorithm {
        val fields = algorithmIdentifierFields(encoded)
        try {
            ECDSA_SIGNATURE_OIDS[digest]?.let { identifier ->
                if (fields.identifier.contentEquals(DerEncoder.objectIdentifier(identifier))) {
                    if (fields.parameters != null) {
                        throw invalidSignature()
                    }
                    return TimestampCmsSignatureAlgorithm.ecdsa(digest)
                }
            }
            RSA_PKCS1_SIGNATURE_OIDS[digest]?.let { identifier ->
                if (fields.identifier.contentEquals(DerEncoder.objectIdentifier(identifier))) {
                    requireNull(fields.parameters)
                    return TimestampCmsSignatureAlgorithm.rsaPkcs1(digest)
                }
            }
            if (fields.identifier.contentEquals(DerEncoder.objectIdentifier(TimestampCmsOids.RSA_ENCRYPTION))) {
                requireNull(fields.parameters)
                return TimestampCmsSignatureAlgorithm.rsaPkcs1(digest)
            }
            if (fields.identifier.contentEquals(DerEncoder.objectIdentifier(TimestampCmsOids.RSA_PSS))) {
                requirePssParameters(fields.parameters, digest)
                return TimestampCmsSignatureAlgorithm.rsaPss(digest)
            }
            throw invalidSignature()
        } finally {
            fields.close()
        }
    }

    private fun requirePssParameters(
        encoded: ByteArray?,
        digest: TimestampCmsDigest,
    ) {
        val parameters = encoded ?: throw invalidSignature()
        val outer = DerReader(parameters)
        val sequence = outer.next() ?: throw invalidSignature()
        if (sequence.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
            throw invalidSignature()
        }
        val fields = outer.children(sequence)
        val hash = required(fields, DerValues.TAG_CONTEXT_0_CONSTRUCTED)
        val mask = required(fields, DerValues.TAG_CONTEXT_1_CONSTRUCTED)
        val salt = required(fields, DerValues.TAG_CONTEXT_2_CONSTRUCTED)
        if (!fields.isAtEnd) {
            throw invalidSignature()
        }
        if (
            explicitDigest(fields.content(hash)) != digest ||
            maskDigest(fields.content(mask)) != digest ||
            explicitInteger(fields.content(salt)) != digest.byteCount.toLong()
        ) {
            throw invalidSignature()
        }
    }

    private fun explicitDigest(content: ByteArray): TimestampCmsDigest =
        try {
            val reader = DerReader(content)
            val identifier = reader.next() ?: throw invalidSignature()
            if (!reader.isAtEnd) {
                throw invalidSignature()
            }
            digest(reader.raw(identifier))
        } finally {
            content.fill(ZERO_BYTE)
        }

    private fun maskDigest(content: ByteArray): TimestampCmsDigest =
        try {
            val reader = DerReader(content)
            val identifier = required(reader, DerValues.TAG_SEQUENCE)
            if (!reader.isAtEnd) {
                throw invalidSignature()
            }
            val fields = reader.children(identifier)
            val algorithm = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
            val digestIdentifier = fields.next() ?: throw invalidSignature()
            if (
                !fields.raw(algorithm).contentEquals(
                    DerEncoder.objectIdentifier(TimestampCmsOids.MASK_GENERATION_FUNCTION_1),
                ) ||
                !fields.isAtEnd
            ) {
                throw invalidSignature()
            }
            digest(fields.raw(digestIdentifier))
        } finally {
            content.fill(ZERO_BYTE)
        }

    private fun explicitInteger(content: ByteArray): Long =
        try {
            val reader = DerReader(content)
            val integer = required(reader, DerValues.TAG_INTEGER)
            if (!reader.isAtEnd) {
                throw invalidSignature()
            }
            Rfc3161DerValidation.nonNegativeLong(reader, integer) ?: throw invalidSignature()
        } finally {
            content.fill(ZERO_BYTE)
        }

    private fun algorithmIdentifierFields(encoded: ByteArray): AlgorithmIdentifierFields {
        val outer = DerReader(encoded)
        val sequence = outer.next() ?: throw malformed()
        if (sequence.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
            throw malformed()
        }
        val fields = outer.children(sequence)
        val identifier = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
        val parameters = fields.next()
        if (!fields.isAtEnd) {
            throw malformed()
        }
        return AlgorithmIdentifierFields(
            identifier = fields.raw(identifier),
            parameters = parameters?.let(fields::raw),
        )
    }

    private fun requireAbsentOrNull(parameters: ByteArray?) {
        if (parameters != null) {
            requireNull(parameters)
        }
    }

    private fun requireNull(encoded: ByteArray?) {
        val parameters = encoded ?: throw invalidSignature()
        val element = DerReader.single(parameters)
        if (element?.tag != DerValues.TAG_NULL || element.contentStart != element.contentEnd) {
            throw invalidSignature()
        }
    }

    private fun required(
        reader: DerReader,
        tag: Int,
    ): DerReader.Element = reader.next()?.takeIf { element -> element.tag == tag } ?: throw malformed()

    private fun malformed(): TimestampTokenVerificationException =
        TimestampTokenVerificationException(TimestampTokenVerificationFailure.MALFORMED)

    private fun invalidSignature(): TimestampTokenVerificationException =
        TimestampTokenVerificationException(TimestampTokenVerificationFailure.INVALID_SIGNATURE)

    private data class AlgorithmIdentifierFields(
        val identifier: ByteArray,
        val parameters: ByteArray?,
    ) : AutoCloseable {
        override fun close() {
            identifier.fill(ZERO_BYTE)
            parameters?.fill(ZERO_BYTE)
        }
    }

    private const val ZERO_BYTE: Byte = 0
    private val ECDSA_SIGNATURE_OIDS =
        mapOf(
            TimestampCmsDigest.SHA256 to TimestampCmsOids.ECDSA_WITH_SHA256,
            TimestampCmsDigest.SHA384 to QualifiedCmsOids.ECDSA_WITH_SHA384,
            TimestampCmsDigest.SHA512 to TimestampCmsOids.ECDSA_WITH_SHA512,
        )
    private val RSA_PKCS1_SIGNATURE_OIDS =
        mapOf(
            TimestampCmsDigest.SHA256 to TimestampCmsOids.SHA256_WITH_RSA,
            TimestampCmsDigest.SHA384 to QualifiedCmsOids.SHA384_WITH_RSA,
            TimestampCmsDigest.SHA512 to TimestampCmsOids.SHA512_WITH_RSA,
        )
}

internal object TimestampCmsOids {
    const val SHA1 = "1.3.14.3.2.26"
    const val SHA256 = "2.16.840.1.101.3.4.2.1"
    const val SHA512 = "2.16.840.1.101.3.4.2.3"
    const val ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
    const val ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4"
    const val SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
    const val SHA512_WITH_RSA = "1.2.840.113549.1.1.13"
    const val RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
    const val RSA_PSS = "1.2.840.113549.1.1.10"
    const val MASK_GENERATION_FUNCTION_1 = "1.2.840.113549.1.1.8"
    const val SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"
    const val TIMESTAMPING_KEY_PURPOSE = "1.3.6.1.5.5.7.3.8"
    const val SUBJECT_KEY_IDENTIFIER = "2.5.29.14"
    const val EXTENDED_KEY_USAGE = "2.5.29.37"
}
