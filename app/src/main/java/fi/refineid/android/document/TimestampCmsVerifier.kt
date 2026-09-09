// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

private const val CLEARED_BYTE: Byte = 0

/** Authenticates the sole signer over the exact signed TSTInfo attributes. */
internal object TimestampCmsVerifier {
    fun authenticate(token: ByteArray): TimestampCmsAuthenticated {
        val layout = TimestampCmsLayoutParser.parse(token)
        try {
            val signer = TimestampCmsSignerParser.parse(layout.signerInfo)
            try {
                if (layout.digest != signer.digest) {
                    throw malformed()
                }
                TimestampCmsSignedAttributes.verify(
                    signedAttributesSet = signer.signedAttributesSet,
                    digest = signer.digest,
                    content = layout.tstInfo,
                )
                val selected =
                    TimestampCmsCertificateSelector.select(
                        certificates = layout.certificates,
                        identifier = signer.identifier,
                    )
                if (!signatureIsValid(signer, selected.certificate)) {
                    selected.encoded.fill(ZERO_BYTE)
                    throw failure(TimestampTokenVerificationFailure.INVALID_SIGNATURE)
                }
                return TimestampCmsAuthenticated(
                    tstInfo = layout.tstInfo.copyOf(),
                    signedAttributesSet = signer.signedAttributesSet.copyOf(),
                    signerCertificate = selected.encoded,
                    parsedSignerCertificate = selected.certificate,
                    embeddedCertificates = layout.certificates.map(ByteArray::copyOf),
                )
            } finally {
                signer.close()
            }
        } finally {
            layout.close()
        }
    }

    private fun signatureIsValid(
        signer: TimestampCmsSigner,
        certificate: X509Certificate,
    ): Boolean =
        try {
            signer.signatureAlgorithm
                .verifier()
                .apply {
                    initVerify(certificate.publicKey)
                    update(signer.signedAttributesSet)
                }.verify(signer.signature)
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }

    private fun malformed(): TimestampTokenVerificationException = failure(TimestampTokenVerificationFailure.MALFORMED)

    private fun failure(kind: TimestampTokenVerificationFailure): TimestampTokenVerificationException =
        TimestampTokenVerificationException(kind)

    private const val ZERO_BYTE: Byte = 0
}

internal class TimestampCmsAuthenticated(
    val tstInfo: ByteArray,
    val signedAttributesSet: ByteArray,
    val signerCertificate: ByteArray,
    val parsedSignerCertificate: X509Certificate,
    val embeddedCertificates: List<ByteArray>,
) : AutoCloseable {
    override fun close() {
        tstInfo.fill(ZERO_BYTE)
        signedAttributesSet.fill(ZERO_BYTE)
        signerCertificate.fill(ZERO_BYTE)
        embeddedCertificates.forEach { certificate -> certificate.fill(ZERO_BYTE) }
    }

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}

internal class TimestampCmsLayout(
    val digest: TimestampCmsDigest,
    val tstInfo: ByteArray,
    val certificates: List<ByteArray>,
    val signerInfo: ByteArray,
) : AutoCloseable {
    override fun close() {
        tstInfo.fill(ZERO_BYTE)
        certificates.forEach { certificate -> certificate.fill(ZERO_BYTE) }
        signerInfo.fill(ZERO_BYTE)
    }

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}

/** Complete DER layout checks for the SignedData envelope. */
internal object TimestampCmsLayoutParser {
    fun parse(token: ByteArray): TimestampCmsLayout {
        val signedData = signedData(token)
        try {
            return layout(signedData)
        } finally {
            signedData.fill(ZERO_BYTE)
        }
    }

    private fun signedData(token: ByteArray): ByteArray {
        val outer = DerReader(token)
        val contentInfo = required(outer, DerValues.TAG_SEQUENCE)
        if (!outer.isAtEnd) {
            throw malformed()
        }
        val fields = outer.children(contentInfo)
        val type = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
        val wrapper = required(fields, DerValues.TAG_CONTEXT_0_CONSTRUCTED)
        if (
            !fields.raw(type).contentEquals(DerEncoder.objectIdentifier(QualifiedCmsOids.SIGNED_DATA)) ||
            !fields.isAtEnd
        ) {
            throw malformed()
        }
        val wrapped = fields.children(wrapper)
        val signedData = required(wrapped, DerValues.TAG_SEQUENCE)
        if (!wrapped.isAtEnd) {
            throw malformed()
        }
        return wrapped.raw(signedData)
    }

    private fun layout(signedData: ByteArray): TimestampCmsLayout {
        val outer = DerReader(signedData)
        val sequence = required(outer, DerValues.TAG_SEQUENCE)
        if (!outer.isAtEnd) {
            throw malformed()
        }
        val fields = outer.children(sequence)
        requireVersion(fields)
        val digest = soleDigest(fields, required(fields, DerValues.TAG_SET))
        val tstInfo = encapsulatedContent(fields, required(fields, DerValues.TAG_SEQUENCE))
        var certificates: List<ByteArray> = emptyList()
        var transferred = false
        try {
            var candidate = fields.next()
            if (candidate?.tag == DerValues.TAG_CONTEXT_0_CONSTRUCTED) {
                certificates = certificateSet(fields, candidate)
                candidate = fields.next()
            }
            if (candidate?.tag == DerValues.TAG_CONTEXT_1_CONSTRUCTED) {
                requireTlvStream(fields.children(candidate))
                candidate = fields.next()
            }
            if (candidate?.tag != DerValues.TAG_SET || !fields.isAtEnd) {
                throw malformed()
            }
            val signers = fields.children(candidate)
            val signer = signers.next()
            if (signer?.tag != DerValues.TAG_SEQUENCE || !signers.isAtEnd) {
                throw malformed()
            }
            return TimestampCmsLayout(
                digest = digest,
                tstInfo = tstInfo,
                certificates = certificates,
                signerInfo = signers.raw(signer),
            ).also {
                transferred = true
            }
        } finally {
            if (!transferred) {
                clear(tstInfo, certificates)
            }
        }
    }

    private fun requireVersion(reader: DerReader) {
        val version = required(reader, DerValues.TAG_INTEGER)
        if (Rfc3161DerValidation.nonNegativeLong(reader, version) != TIMESTAMP_SIGNED_DATA_VERSION) {
            throw malformed()
        }
    }

    private fun soleDigest(
        source: DerReader,
        set: DerReader.Element,
    ): TimestampCmsDigest {
        val algorithms = source.children(set)
        val identifier = algorithms.next() ?: throw malformed()
        if (!algorithms.isAtEnd) {
            throw malformed()
        }
        val encoded = algorithms.raw(identifier)
        return try {
            TimestampCmsAlgorithmParser.digest(encoded)
        } finally {
            encoded.fill(ZERO_BYTE)
        }
    }

    private fun encapsulatedContent(
        source: DerReader,
        encapsulated: DerReader.Element,
    ): ByteArray {
        val fields = source.children(encapsulated)
        val type = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
        val wrapper = required(fields, DerValues.TAG_CONTEXT_0_CONSTRUCTED)
        if (
            !fields.raw(type).contentEquals(DerEncoder.objectIdentifier(Rfc3161Oids.TST_INFO)) ||
            !fields.isAtEnd
        ) {
            throw malformed()
        }
        val explicit = fields.children(wrapper)
        val content = required(explicit, DerValues.TAG_OCTET_STRING)
        if (!explicit.isAtEnd) {
            throw malformed()
        }
        return explicit.content(content)
    }

    private fun certificateSet(
        source: DerReader,
        set: DerReader.Element,
    ): List<ByteArray> {
        val certificates = mutableListOf<ByteArray>()
        val choices = source.children(set)
        while (!choices.isAtEnd) {
            val choice = choices.next() ?: throw malformedAfterClearing(certificates)
            val raw = choices.raw(choice)
            if (
                choice.tag == DerValues.TAG_SEQUENCE &&
                certificates.none { certificate -> certificate.contentEquals(raw) }
            ) {
                if (certificates.size == MAXIMUM_EMBEDDED_CERTIFICATE_COUNT) {
                    raw.fill(ZERO_BYTE)
                    throw malformedAfterClearing(certificates)
                }
                certificates += raw
            } else {
                raw.fill(ZERO_BYTE)
            }
        }
        return certificates
    }

    private fun requireTlvStream(reader: DerReader) {
        while (!reader.isAtEnd) {
            reader.next() ?: throw malformed()
        }
    }

    private fun clear(
        content: ByteArray,
        certificates: List<ByteArray>,
    ) {
        content.fill(ZERO_BYTE)
        certificates.forEach { certificate -> certificate.fill(ZERO_BYTE) }
    }

    private fun malformedAfterClearing(certificates: List<ByteArray>): TimestampTokenVerificationException {
        certificates.forEach { certificate -> certificate.fill(ZERO_BYTE) }
        return malformed()
    }

    private fun required(
        reader: DerReader,
        tag: Int,
    ): DerReader.Element = reader.next()?.takeIf { element -> element.tag == tag } ?: throw malformed()

    private fun malformed(): TimestampTokenVerificationException =
        TimestampTokenVerificationException(TimestampTokenVerificationFailure.MALFORMED)

    private const val TIMESTAMP_SIGNED_DATA_VERSION = 3L
    private const val MAXIMUM_EMBEDDED_CERTIFICATE_COUNT = 32
    private const val ZERO_BYTE: Byte = 0
}

internal sealed interface TimestampCmsSignerIdentifier : AutoCloseable {
    class IssuerAndSerial(
        val encoded: ByteArray,
    ) : TimestampCmsSignerIdentifier {
        override fun close() = encoded.fill(CLEARED_BYTE)
    }

    class SubjectKeyIdentifier(
        val identifier: ByteArray,
    ) : TimestampCmsSignerIdentifier {
        override fun close() = identifier.fill(CLEARED_BYTE)
    }
}

internal class TimestampCmsSigner(
    val identifier: TimestampCmsSignerIdentifier,
    val digest: TimestampCmsDigest,
    val signedAttributesSet: ByteArray,
    val signatureAlgorithm: TimestampCmsSignatureAlgorithm,
    val signature: ByteArray,
) : AutoCloseable {
    override fun close() {
        identifier.close()
        signedAttributesSet.fill(ZERO_BYTE)
        signature.fill(ZERO_BYTE)
    }

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}

/** One SignerInfo with mandatory signed attributes and version-coupled SID. */
internal object TimestampCmsSignerParser {
    fun parse(encoded: ByteArray): TimestampCmsSigner {
        val outer = DerReader(encoded)
        val sequence = required(outer, DerValues.TAG_SEQUENCE)
        if (!outer.isAtEnd) {
            throw malformed()
        }
        val fields = outer.children(sequence)
        val version = required(fields, DerValues.TAG_INTEGER)
        val versionValue = Rfc3161DerValidation.nonNegativeLong(fields, version) ?: throw malformed()
        val identifier = identifier(fields, fields.next() ?: throw malformed(), versionValue)
        var ownedSignedAttributes: ByteArray? = null
        var ownedSignature: ByteArray? = null
        var identifierTransferred = false
        try {
            val digest = algorithmDigest(fields, required(fields, DerValues.TAG_SEQUENCE))
            val attributes = required(fields, DerValues.TAG_CONTEXT_0_CONSTRUCTED)
            ownedSignedAttributes =
                DerEncoder.retagged(
                    encoded = fields.raw(attributes),
                    tag = DerValues.TAG_SET,
                )
            val signatureAlgorithm =
                algorithmSignature(
                    source = fields,
                    element = required(fields, DerValues.TAG_SEQUENCE),
                    digest = digest,
                )
            ownedSignature = fields.content(required(fields, DerValues.TAG_OCTET_STRING))
            if (ownedSignature.isEmpty()) {
                throw malformed()
            }
            val unsigned = fields.next()
            if (unsigned != null) {
                if (unsigned.tag != DerValues.TAG_CONTEXT_1_CONSTRUCTED) {
                    throw malformed()
                }
                TimestampCmsSignedAttributes.validateAttributeStream(fields.children(unsigned))
            }
            if (!fields.isAtEnd) {
                throw malformed()
            }
            return TimestampCmsSigner(
                identifier = identifier,
                digest = digest,
                signedAttributesSet = ownedSignedAttributes,
                signatureAlgorithm = signatureAlgorithm,
                signature = ownedSignature,
            ).also {
                identifierTransferred = true
            }
        } finally {
            if (!identifierTransferred) {
                identifier.close()
                ownedSignedAttributes?.fill(ZERO_BYTE)
                ownedSignature?.fill(ZERO_BYTE)
            }
        }
    }

    private fun identifier(
        source: DerReader,
        element: DerReader.Element,
        version: Long,
    ): TimestampCmsSignerIdentifier =
        when (element.tag) {
            DerValues.TAG_SEQUENCE -> {
                if (version != ISSUER_AND_SERIAL_SIGNER_VERSION) {
                    throw malformed()
                }
                val fields = source.children(element)
                required(fields, DerValues.TAG_SEQUENCE)
                val serial = required(fields, DerValues.TAG_INTEGER)
                if (
                    !Rfc3161DerValidation.isCanonicalNonNegativeInteger(fields, serial) ||
                    !fields.isAtEnd
                ) {
                    throw malformed()
                }
                TimestampCmsSignerIdentifier.IssuerAndSerial(source.raw(element))
            }

            DerValues.TAG_CONTEXT_0_PRIMITIVE -> {
                if (version != SUBJECT_KEY_IDENTIFIER_SIGNER_VERSION) {
                    throw malformed()
                }
                val identifier = source.content(element)
                if (identifier.isEmpty()) {
                    throw malformed()
                }
                TimestampCmsSignerIdentifier.SubjectKeyIdentifier(identifier)
            }

            else -> {
                throw malformed()
            }
        }

    private fun algorithmDigest(
        source: DerReader,
        element: DerReader.Element,
    ): TimestampCmsDigest {
        val encoded = source.raw(element)
        return try {
            TimestampCmsAlgorithmParser.digest(encoded)
        } finally {
            encoded.fill(ZERO_BYTE)
        }
    }

    private fun algorithmSignature(
        source: DerReader,
        element: DerReader.Element,
        digest: TimestampCmsDigest,
    ): TimestampCmsSignatureAlgorithm {
        val encoded = source.raw(element)
        return try {
            TimestampCmsAlgorithmParser.signature(encoded, digest)
        } finally {
            encoded.fill(ZERO_BYTE)
        }
    }

    private fun required(
        reader: DerReader,
        tag: Int,
    ): DerReader.Element = reader.next()?.takeIf { element -> element.tag == tag } ?: throw malformed()

    private fun malformed(): TimestampTokenVerificationException =
        TimestampTokenVerificationException(TimestampTokenVerificationFailure.MALFORMED)

    private const val ISSUER_AND_SERIAL_SIGNER_VERSION = 1L
    private const val SUBJECT_KEY_IDENTIFIER_SIGNER_VERSION = 3L
    private const val ZERO_BYTE: Byte = 0
}

/** Required CMS signed-attribute checks over their exact DER SET encoding. */
internal object TimestampCmsSignedAttributes {
    fun verify(
        signedAttributesSet: ByteArray,
        digest: TimestampCmsDigest,
        content: ByteArray,
    ) {
        val outer = DerReader(signedAttributesSet)
        val set = required(outer, DerValues.TAG_SET)
        if (!outer.isAtEnd) {
            throw malformed()
        }
        val attributes = outer.children(set)
        var contentTypeCount = EMPTY_COUNT
        var messageDigestCount = EMPTY_COUNT
        var previous: ByteArray? = null
        while (!attributes.isAtEnd) {
            val attribute = attributes.next() ?: throw malformed()
            if (attribute.tag != DerValues.TAG_SEQUENCE) {
                throw malformed()
            }
            val raw = attributes.raw(attribute)
            if (previous != null && DerByteOrder.compare(previous, raw) >= ORDERED_COMPARISON) {
                raw.fill(ZERO_BYTE)
                previous.fill(ZERO_BYTE)
                throw malformed()
            }
            previous?.fill(ZERO_BYTE)
            previous = raw
            when (attributeType(attributes, attribute)) {
                AttributeType.CONTENT_TYPE -> {
                    contentTypeCount += COUNT_STEP
                    requireContentType(attributes, attribute)
                }

                AttributeType.MESSAGE_DIGEST -> {
                    messageDigestCount += COUNT_STEP
                    requireMessageDigest(attributes, attribute, digest, content)
                }

                AttributeType.OTHER -> {
                    // Unrecognized attributes are permitted and carry no checks.
                }
            }
        }
        previous?.fill(ZERO_BYTE)
        if (contentTypeCount != REQUIRED_ATTRIBUTE_COUNT || messageDigestCount != REQUIRED_ATTRIBUTE_COUNT) {
            throw malformed()
        }
    }

    fun validateAttributeStream(reader: DerReader) {
        var count = EMPTY_COUNT
        var previous: ByteArray? = null
        while (!reader.isAtEnd) {
            val attribute = reader.next() ?: throw malformed()
            if (attribute.tag != DerValues.TAG_SEQUENCE) {
                throw malformed()
            }
            val raw = reader.raw(attribute)
            if (previous != null && DerByteOrder.compare(previous, raw) >= ORDERED_COMPARISON) {
                raw.fill(ZERO_BYTE)
                previous.fill(ZERO_BYTE)
                throw malformed()
            }
            previous?.fill(ZERO_BYTE)
            previous = raw
            val fields = reader.children(attribute)
            val identifier = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
            if (!Rfc3161DerValidation.isCanonicalObjectIdentifier(fields, identifier)) {
                previous.fill(ZERO_BYTE)
                throw malformed()
            }
            val values = required(fields, DerValues.TAG_SET)
            if (!fields.isAtEnd) {
                previous.fill(ZERO_BYTE)
                throw malformed()
            }
            validateValues(fields.children(values))
            count += COUNT_STEP
        }
        previous?.fill(ZERO_BYTE)
        if (count == EMPTY_COUNT) {
            throw malformed()
        }
    }

    private fun attributeType(
        source: DerReader,
        attribute: DerReader.Element,
    ): AttributeType {
        val fields = source.children(attribute)
        val identifier = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
        if (!Rfc3161DerValidation.isCanonicalObjectIdentifier(fields, identifier)) {
            throw malformed()
        }
        val values = required(fields, DerValues.TAG_SET)
        if (!fields.isAtEnd) {
            throw malformed()
        }
        validateValues(fields.children(values))
        val encoded = fields.raw(identifier)
        return try {
            when {
                encoded.contentEquals(DerEncoder.objectIdentifier(QualifiedCmsOids.CONTENT_TYPE)) -> {
                    AttributeType.CONTENT_TYPE
                }

                encoded.contentEquals(DerEncoder.objectIdentifier(QualifiedCmsOids.MESSAGE_DIGEST)) -> {
                    AttributeType.MESSAGE_DIGEST
                }

                else -> {
                    AttributeType.OTHER
                }
            }
        } finally {
            encoded.fill(ZERO_BYTE)
        }
    }

    private fun requireContentType(
        source: DerReader,
        attribute: DerReader.Element,
    ) {
        val values = attributeValues(source, attribute)
        val value = required(values, DerValues.TAG_OBJECT_IDENTIFIER)
        if (
            !values.raw(value).contentEquals(DerEncoder.objectIdentifier(Rfc3161Oids.TST_INFO)) ||
            !values.isAtEnd
        ) {
            throw malformed()
        }
    }

    private fun requireMessageDigest(
        source: DerReader,
        attribute: DerReader.Element,
        digest: TimestampCmsDigest,
        content: ByteArray,
    ) {
        val values = attributeValues(source, attribute)
        val value = required(values, DerValues.TAG_OCTET_STRING)
        val actual = values.content(value)
        val expected = digest.digest(content)
        try {
            if (
                actual.size != digest.byteCount ||
                !MessageDigest.isEqual(actual, expected) ||
                !values.isAtEnd
            ) {
                throw failure(TimestampTokenVerificationFailure.INVALID_SIGNATURE)
            }
        } finally {
            actual.fill(ZERO_BYTE)
            expected.fill(ZERO_BYTE)
        }
    }

    private fun attributeValues(
        source: DerReader,
        attribute: DerReader.Element,
    ): DerReader {
        val fields = source.children(attribute)
        required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
        val values = required(fields, DerValues.TAG_SET)
        if (!fields.isAtEnd) {
            throw malformed()
        }
        return fields.children(values)
    }

    private fun validateValues(reader: DerReader) {
        var count = EMPTY_COUNT
        var previous: ByteArray? = null
        while (!reader.isAtEnd) {
            val value = reader.next() ?: throw malformed()
            val raw = reader.raw(value)
            if (previous != null && DerByteOrder.compare(previous, raw) > ORDERED_COMPARISON) {
                raw.fill(ZERO_BYTE)
                previous.fill(ZERO_BYTE)
                throw malformed()
            }
            previous?.fill(ZERO_BYTE)
            previous = raw
            count += COUNT_STEP
        }
        previous?.fill(ZERO_BYTE)
        if (count == EMPTY_COUNT) {
            throw malformed()
        }
    }

    private fun required(
        reader: DerReader,
        tag: Int,
    ): DerReader.Element = reader.next()?.takeIf { element -> element.tag == tag } ?: throw malformed()

    private fun malformed(): TimestampTokenVerificationException = failure(TimestampTokenVerificationFailure.MALFORMED)

    private fun failure(kind: TimestampTokenVerificationFailure): TimestampTokenVerificationException =
        TimestampTokenVerificationException(kind)

    private enum class AttributeType {
        CONTENT_TYPE,
        MESSAGE_DIGEST,
        OTHER,
    }

    private const val EMPTY_COUNT = 0
    private const val COUNT_STEP = 1
    private const val REQUIRED_ATTRIBUTE_COUNT = 1
    private const val ORDERED_COMPARISON = 0
    private const val ZERO_BYTE: Byte = 0
}

/** Exact unsigned-byte DER ordering shared by SET validation. */
internal object DerByteOrder {
    fun compare(
        left: ByteArray,
        right: ByteArray,
    ): Int {
        val sharedLength = minOf(left.size, right.size)
        for (index in FIRST_INDEX until sharedLength) {
            val comparison = left[index].toUByte().compareTo(right[index].toUByte())
            if (comparison != EQUAL_COMPARISON) {
                return comparison
            }
        }
        return left.size.compareTo(right.size)
    }

    private const val FIRST_INDEX = 0
    private const val EQUAL_COMPARISON = 0
}

internal data class TimestampCmsSelectedCertificate(
    val encoded: ByteArray,
    val certificate: X509Certificate,
)

/** Selects exactly one distinct parseable embedded certificate by CMS SID. */
internal object TimestampCmsCertificateSelector {
    fun select(
        certificates: List<ByteArray>,
        identifier: TimestampCmsSignerIdentifier,
    ): TimestampCmsSelectedCertificate {
        val matches = mutableListOf<TimestampCmsSelectedCertificate>()
        for (encoded in certificates) {
            val certificate = parseCertificate(encoded) ?: continue
            if (matches(identifier, encoded, certificate)) {
                matches += TimestampCmsSelectedCertificate(encoded.copyOf(), certificate)
            }
        }
        return when (matches.size) {
            NO_MATCHING_CERTIFICATES -> {
                throw failure(TimestampTokenVerificationFailure.SIGNER_CERTIFICATE_MISSING)
            }

            ONE_MATCHING_CERTIFICATE -> {
                matches.single()
            }

            else -> {
                matches.forEach { match -> match.encoded.fill(ZERO_BYTE) }
                throw failure(TimestampTokenVerificationFailure.AMBIGUOUS_SIGNER)
            }
        }
    }

    private fun matches(
        identifier: TimestampCmsSignerIdentifier,
        encoded: ByteArray,
        certificate: X509Certificate,
    ): Boolean =
        when (identifier) {
            is TimestampCmsSignerIdentifier.IssuerAndSerial -> {
                val actual =
                    try {
                        QualifiedDocumentCmsValidation.issuerAndSerial(encoded)
                    } catch (_: QualifiedDocumentCmsException) {
                        return false
                    }
                try {
                    MessageDigest.isEqual(identifier.encoded, actual)
                } finally {
                    actual.fill(ZERO_BYTE)
                }
            }

            is TimestampCmsSignerIdentifier.SubjectKeyIdentifier -> {
                val actual = subjectKeyIdentifier(certificate) ?: return false
                try {
                    MessageDigest.isEqual(identifier.identifier, actual)
                } finally {
                    actual.fill(ZERO_BYTE)
                }
            }
        }

    private fun subjectKeyIdentifier(certificate: X509Certificate): ByteArray? {
        val extension = certificate.getExtensionValue(TimestampCmsOids.SUBJECT_KEY_IDENTIFIER) ?: return null
        val outer = DerReader(extension)
        val wrapped = outer.next() ?: return null
        if (wrapped.tag != DerValues.TAG_OCTET_STRING || !outer.isAtEnd) {
            return null
        }
        val innerEncoding = outer.content(wrapped)
        return try {
            val inner = DerReader(innerEncoding)
            val identifier = inner.next() ?: return null
            if (identifier.tag != DerValues.TAG_OCTET_STRING || !inner.isAtEnd) {
                return null
            }
            inner.content(identifier)
        } finally {
            innerEncoding.fill(ZERO_BYTE)
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

    private fun failure(kind: TimestampTokenVerificationFailure): TimestampTokenVerificationException =
        TimestampTokenVerificationException(kind)

    private const val X509_CERTIFICATE_TYPE = "X.509"
    private const val NO_MATCHING_CERTIFICATES = 0
    private const val ONE_MATCHING_CERTIFICATE = 1
    private const val ZERO_BYTE: Byte = 0
}
