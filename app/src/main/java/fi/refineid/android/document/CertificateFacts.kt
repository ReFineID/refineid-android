// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.MessageDigest

/** Exact X.509 fields needed for path construction and revocation requests. */
internal class CertificateFacts private constructor(
    private val identity: CertificateIdentity,
    private val locations: ExtensionLocations,
) : AutoCloseable {
    private var isClosed = false

    val issuerCertificateUrls: List<String>
        get() = locations.issuerCertificates

    val ocspUrls: List<String>
        get() = locations.ocspResponders

    val revocationListUrls: List<String>
        get() = locations.revocationLists

    val isSelfIssued: Boolean
        get() {
            requireOpen()
            return MessageDigest.isEqual(identity.issuerName, identity.subjectName)
        }

    fun <T> useOcspIdentity(operation: (ByteArray, ByteArray) -> T): T {
        requireOpen()
        val issuerName = identity.issuerName.copyOf()
        val serialNumber = identity.serialNumber.copyOf()
        return try {
            operation(issuerName, serialNumber)
        } finally {
            issuerName.fill(ZERO_BYTE)
            serialNumber.fill(ZERO_BYTE)
        }
    }

    fun <T> usePublicKeyBits(operation: (ByteArray) -> T): T {
        requireOpen()
        val publicKeyBits = identity.publicKeyBits.copyOf()
        return try {
            operation(publicKeyBits)
        } finally {
            publicKeyBits.fill(ZERO_BYTE)
        }
    }

    fun <T> useSubjectName(operation: (ByteArray) -> T): T {
        requireOpen()
        val subjectName = identity.subjectName.copyOf()
        return try {
            operation(subjectName)
        } finally {
            subjectName.fill(ZERO_BYTE)
        }
    }

    internal fun issuerNameMatches(issuer: CertificateFacts): Boolean {
        requireOpen()
        issuer.requireOpen()
        return MessageDigest.isEqual(identity.issuerName, issuer.identity.subjectName)
    }

    override fun close() {
        if (!isClosed) {
            identity.close()
            isClosed = true
        }
    }

    override fun toString(): String =
        "CertificateFacts(issuerLocations=" + issuerCertificateUrls.size +
            ", ocspLocations=" + ocspUrls.size +
            ", revocationListLocations=" + revocationListUrls.size +
            ", closed=" + isClosed + ")"

    private fun requireOpen() {
        check(!isClosed) {
            "certificate facts are closed"
        }
    }

    companion object {
        fun parse(encoded: ByteArray): CertificateFacts? =
            try {
                parseCertificate(encoded)
            } catch (_: RuntimeException) {
                null
            }

        private fun parseCertificate(encoded: ByteArray): CertificateFacts? {
            if (encoded.isEmpty() || encoded.size > PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES) {
                return null
            }
            val outer = DerReader(encoded)
            val certificate = outer.next() ?: return null
            if (certificate.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
                return null
            }
            val certificateFields = outer.children(certificate)
            val tbs = certificateFields.next() ?: return null
            val outerAlgorithm = certificateFields.next() ?: return null
            val signature = certificateFields.next() ?: return null
            val signatureContent = certificateFields.content(signature)
            val signatureIsValid =
                try {
                    hasZeroUnusedBits(signatureContent)
                } finally {
                    signatureContent.fill(ZERO_BYTE)
                }
            val requiredTagsArePresent =
                tbs.tag == DerValues.TAG_SEQUENCE &&
                    outerAlgorithm.tag == DerValues.TAG_SEQUENCE &&
                    signature.tag == DerValues.TAG_BIT_STRING
            val certificateIsComplete = certificateFields.isAtEnd && signatureIsValid
            if (!requiredTagsArePresent || !certificateIsComplete) {
                return null
            }
            return parseTbs(
                encoded = encoded,
                tbs = tbs,
                outerAlgorithm = certificateFields.raw(outerAlgorithm),
            )
        }

        private fun parseTbs(
            encoded: ByteArray,
            tbs: DerReader.Element,
            outerAlgorithm: ByteArray,
        ): CertificateFacts? {
            try {
                val fields = DerReader(encoded).children(tbs)
                val prefix = tbsPrefix(fields) ?: return null
                prefix.use { parsedPrefix ->
                    val fixedFields = fixedTbsFields(fields, outerAlgorithm) ?: return null
                    fixedFields.use { parsedFields ->
                        val extensions = trailingExtensions(fields, parsedPrefix.version) ?: return null
                        return CertificateFacts(
                            identity =
                                CertificateIdentity.copyOf(
                                    issuerName = parsedFields.issuerName,
                                    subjectName = parsedFields.subjectName,
                                    serialNumber = parsedPrefix.serialNumber,
                                    publicKeyBits = parsedFields.publicKeyBits,
                                ),
                            locations = extensions,
                        )
                    }
                }
            } finally {
                outerAlgorithm.fill(ZERO_BYTE)
            }
        }

        private fun tbsPrefix(fields: DerReader): TbsPrefix? {
            var serial = fields.next() ?: return null
            val version =
                if (serial.tag == DerValues.TAG_CONTEXT_0_CONSTRUCTED) {
                    val parsedVersion = certificateVersion(fields.raw(serial)) ?: return null
                    serial = fields.next() ?: return null
                    parsedVersion
                } else {
                    CERTIFICATE_VERSION_ONE
                }
            if (serial.tag != DerValues.TAG_INTEGER || !isPermittedSerial(fields, serial)) {
                return null
            }
            return TbsPrefix(version, fields.content(serial))
        }

        private fun fixedTbsFields(
            fields: DerReader,
            outerAlgorithm: ByteArray,
        ): FixedTbsFields? {
            val innerAlgorithm = fields.next() ?: return null
            val issuer = fields.next() ?: return null
            val validity = fields.next() ?: return null
            val subject = fields.next() ?: return null
            val publicKeyInfo = fields.next() ?: return null
            val fixedTagsAreValid =
                innerAlgorithm.tag == DerValues.TAG_SEQUENCE &&
                    issuer.tag == DerValues.TAG_SEQUENCE &&
                    validity.tag == DerValues.TAG_SEQUENCE
            val remainingTagsAreValid =
                subject.tag == DerValues.TAG_SEQUENCE &&
                    publicKeyInfo.tag == DerValues.TAG_SEQUENCE
            if (!fixedTagsAreValid || !remainingTagsAreValid) {
                return null
            }
            val innerAlgorithmEncoding = fields.raw(innerAlgorithm)
            val algorithmsMatch =
                try {
                    innerAlgorithmEncoding.contentEquals(outerAlgorithm)
                } finally {
                    innerAlgorithmEncoding.fill(ZERO_BYTE)
                }
            if (!algorithmsMatch) {
                return null
            }
            val key = subjectPublicKeyBits(fields.raw(publicKeyInfo)) ?: return null
            return FixedTbsFields(
                issuerName = fields.raw(issuer),
                subjectName = fields.raw(subject),
                publicKeyBits = key,
            )
        }

        private fun certificateVersion(encoded: ByteArray): Int? =
            try {
                val wrapper = DerReader(encoded)
                val explicit = wrapper.next() ?: return null
                if (explicit.tag != DerValues.TAG_CONTEXT_0_CONSTRUCTED || !wrapper.isAtEnd) {
                    return null
                }
                val fields = wrapper.children(explicit)
                val integer = fields.next() ?: return null
                val version = Rfc3161DerValidation.nonNegativeLong(fields, integer) ?: return null
                val permittedVersions =
                    CERTIFICATE_VERSION_TWO.toLong()..CERTIFICATE_VERSION_THREE.toLong()
                if (!fields.isAtEnd || version !in permittedVersions) {
                    return null
                }
                version.toInt()
            } finally {
                encoded.fill(ZERO_BYTE)
            }

        private fun isPermittedSerial(
            reader: DerReader,
            element: DerReader.Element,
        ): Boolean {
            if (!Rfc3161DerValidation.isCanonicalNonNegativeInteger(reader, element)) {
                return false
            }
            val serial = reader.content(element)
            return try {
                serial.size <= MAXIMUM_SERIAL_NUMBER_BYTES && serial.any { byte -> byte != ZERO_BYTE }
            } finally {
                serial.fill(ZERO_BYTE)
            }
        }

        private fun subjectPublicKeyBits(encoded: ByteArray): ByteArray? =
            try {
                val outer = DerReader(encoded)
                val publicKeyInfo = outer.next() ?: return null
                if (publicKeyInfo.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
                    return null
                }
                val fields = outer.children(publicKeyInfo)
                val algorithm = fields.next() ?: return null
                val key = fields.next() ?: return null
                if (
                    algorithm.tag != DerValues.TAG_SEQUENCE ||
                    key.tag != DerValues.TAG_BIT_STRING ||
                    !fields.isAtEnd
                ) {
                    return null
                }
                val content = fields.content(key)
                try {
                    if (!hasZeroUnusedBits(content)) {
                        return null
                    }
                    content.copyOfRange(BIT_STRING_PREFIX_BYTES, content.size)
                } finally {
                    content.fill(ZERO_BYTE)
                }
            } finally {
                encoded.fill(ZERO_BYTE)
            }

        private fun hasZeroUnusedBits(content: ByteArray): Boolean =
            content.size > BIT_STRING_PREFIX_BYTES && content[UNUSED_BITS_OFFSET] == NO_UNUSED_BITS

        private fun trailingExtensions(
            fields: DerReader,
            version: Int,
        ): ExtensionLocations? {
            var extensionLocations = ExtensionLocations.EMPTY
            var extensionsSeen = false
            while (!fields.isAtEnd) {
                val trailing = fields.next() ?: return null
                when (trailing.tag) {
                    DerValues.TAG_CONTEXT_1_PRIMITIVE,
                    DerValues.TAG_CONTEXT_2_PRIMITIVE,
                    -> {
                        if (version == CERTIFICATE_VERSION_ONE) {
                            return null
                        }
                    }

                    DerValues.TAG_CONTEXT_3_CONSTRUCTED -> {
                        if (version != CERTIFICATE_VERSION_THREE || extensionsSeen) {
                            return null
                        }
                        extensionLocations = extensionLocations(fields.raw(trailing)) ?: return null
                        extensionsSeen = true
                    }

                    else -> {
                        return null
                    }
                }
            }
            return extensionLocations
        }

        private fun extensionLocations(encoded: ByteArray): ExtensionLocations? =
            try {
                val wrapper = DerReader(encoded)
                val explicit = wrapper.next() ?: return null
                if (explicit.tag != DerValues.TAG_CONTEXT_3_CONSTRUCTED || !wrapper.isAtEnd) {
                    return null
                }
                val wrapped = wrapper.children(explicit)
                val sequence = wrapped.next() ?: return null
                if (sequence.tag != DerValues.TAG_SEQUENCE || !wrapped.isAtEnd) {
                    return null
                }
                val entries = wrapped.children(sequence)
                if (entries.isAtEnd) {
                    return null
                }
                val identifiers = mutableSetOf<EncodedValue>()
                val issuers = mutableListOf<String>()
                val responders = mutableListOf<String>()
                val revocationLists = mutableListOf<String>()
                while (!entries.isAtEnd) {
                    val entry = entries.next() ?: return null
                    val extension = parseExtension(entries.raw(entry)) ?: return null
                    extension.use { parsed ->
                        if (!identifiers.add(EncodedValue(parsed.identifier.copyOf()))) {
                            return null
                        }
                        when {
                            parsed.identifier.contentEquals(AUTHORITY_INFORMATION_ACCESS_IDENTIFIER) -> {
                                val locations =
                                    CertificateAccessLocationParser.authorityInformation(parsed.value)
                                        ?: return null
                                issuers += locations.issuerCertificates
                                responders += locations.ocspResponders
                            }

                            parsed.identifier.contentEquals(CRL_DISTRIBUTION_POINTS_IDENTIFIER) -> {
                                revocationLists +=
                                    CertificateAccessLocationParser.revocationLists(parsed.value)
                                        ?: return null
                            }
                        }
                    }
                }
                ExtensionLocations(
                    issuerCertificates = issuers,
                    ocspResponders = responders,
                    revocationLists = revocationLists,
                )
            } finally {
                encoded.fill(ZERO_BYTE)
            }

        private fun parseExtension(encoded: ByteArray): ParsedExtension? =
            try {
                val outer = DerReader(encoded)
                val sequence = outer.next() ?: return null
                if (sequence.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
                    return null
                }
                val fields = outer.children(sequence)
                val identifier = fields.next() ?: return null
                if (
                    identifier.tag != DerValues.TAG_OBJECT_IDENTIFIER ||
                    !Rfc3161DerValidation.isCanonicalObjectIdentifier(fields, identifier)
                ) {
                    return null
                }
                var value = fields.next() ?: return null
                if (value.tag == DerValues.TAG_BOOLEAN) {
                    val critical = fields.content(value)
                    try {
                        if (!critical.contentEquals(DER_TRUE_CONTENT)) {
                            return null
                        }
                    } finally {
                        critical.fill(ZERO_BYTE)
                    }
                    value = fields.next() ?: return null
                }
                if (value.tag != DerValues.TAG_OCTET_STRING || !fields.isAtEnd) {
                    return null
                }
                ParsedExtension(
                    identifier = fields.raw(identifier),
                    value = fields.content(value),
                )
            } finally {
                encoded.fill(ZERO_BYTE)
            }

        private const val CERTIFICATE_VERSION_ONE = 0
        private const val CERTIFICATE_VERSION_TWO = 1
        private const val CERTIFICATE_VERSION_THREE = 2
        private const val MAXIMUM_SERIAL_NUMBER_BYTES = 20
        private const val BIT_STRING_PREFIX_BYTES = 1
        private const val UNUSED_BITS_OFFSET = 0
        private const val NO_UNUSED_BITS: Byte = 0
        private const val ZERO_BYTE: Byte = 0

        private val DER_TRUE_CONTENT = byteArrayOf(DerValues.DER_TRUE_BYTE)
        private val AUTHORITY_INFORMATION_ACCESS_IDENTIFIER =
            DerEncoder.objectIdentifier(CertificateOids.AUTHORITY_INFORMATION_ACCESS)
        private val CRL_DISTRIBUTION_POINTS_IDENTIFIER =
            DerEncoder.objectIdentifier(CertificateOids.CRL_DISTRIBUTION_POINTS)
    }

    private class CertificateIdentity private constructor(
        val issuerName: ByteArray,
        val subjectName: ByteArray,
        val serialNumber: ByteArray,
        val publicKeyBits: ByteArray,
    ) : AutoCloseable {
        override fun close() {
            issuerName.fill(ZERO_BYTE)
            subjectName.fill(ZERO_BYTE)
            serialNumber.fill(ZERO_BYTE)
            publicKeyBits.fill(ZERO_BYTE)
        }

        companion object {
            fun copyOf(
                issuerName: ByteArray,
                subjectName: ByteArray,
                serialNumber: ByteArray,
                publicKeyBits: ByteArray,
            ): CertificateIdentity =
                CertificateIdentity(
                    issuerName = issuerName.copyOf(),
                    subjectName = subjectName.copyOf(),
                    serialNumber = serialNumber.copyOf(),
                    publicKeyBits = publicKeyBits.copyOf(),
                )
        }
    }

    private class TbsPrefix(
        val version: Int,
        val serialNumber: ByteArray,
    ) : AutoCloseable {
        override fun close() {
            serialNumber.fill(ZERO_BYTE)
        }
    }

    private class FixedTbsFields(
        val issuerName: ByteArray,
        val subjectName: ByteArray,
        val publicKeyBits: ByteArray,
    ) : AutoCloseable {
        override fun close() {
            issuerName.fill(ZERO_BYTE)
            subjectName.fill(ZERO_BYTE)
            publicKeyBits.fill(ZERO_BYTE)
        }
    }

    private class ParsedExtension(
        val identifier: ByteArray,
        val value: ByteArray,
    ) : AutoCloseable {
        override fun close() {
            identifier.fill(ZERO_BYTE)
            value.fill(ZERO_BYTE)
        }
    }

    private class EncodedValue(
        private val value: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean = other is EncodedValue && value.contentEquals(other.value)

        override fun hashCode(): Int = value.contentHashCode()
    }

    private data class ExtensionLocations(
        val issuerCertificates: List<String>,
        val ocspResponders: List<String>,
        val revocationLists: List<String>,
    ) {
        companion object {
            val EMPTY = ExtensionLocations(emptyList(), emptyList(), emptyList())
        }
    }
}

internal object CertificateOids {
    const val AUTHORITY_INFORMATION_ACCESS = "1.3.6.1.5.5.7.1.1"
    const val CA_ISSUERS_ACCESS_METHOD = "1.3.6.1.5.5.7.48.2"
    const val OCSP_ACCESS_METHOD = "1.3.6.1.5.5.7.48.1"
    const val CRL_DISTRIBUTION_POINTS = "2.5.29.31"
    const val OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2"
    const val SHA1 = "1.3.14.3.2.26"
}
