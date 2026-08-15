// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.MessageDigest

/** RFC 2634/RFC 5035 ESS binding from signed attributes to the actual CMS signer. */
internal object TimestampSigningCertificateVerifier {
    fun verify(
        signedAttributesSet: ByteArray,
        signerCertificateDer: ByteArray,
    ) {
        try {
            val attribute = signingCertificateAttribute(signedAttributesSet)
            try {
                val references = references(attribute.values, attribute.versionTwo)
                try {
                    val first = references.firstOrNull() ?: throw mismatch()
                    val actual = first.algorithm.digest(signerCertificateDer)
                    try {
                        if (!MessageDigest.isEqual(first.certificateHash, actual)) {
                            throw mismatch()
                        }
                    } finally {
                        actual.fill(ZERO_BYTE)
                    }
                    first.issuerSerial?.let { issuerSerial ->
                        if (!issuerSerialMatches(issuerSerial, signerCertificateDer)) {
                            throw mismatch()
                        }
                    }
                } finally {
                    references.forEach(EssCertificateReference::close)
                }
            } finally {
                attribute.close()
            }
        } catch (failure: TimestampTokenVerificationException) {
            if (failure.kind == TimestampTokenVerificationFailure.SIGNING_CERTIFICATE_MISMATCH) {
                throw failure
            }
            throw mismatch()
        } catch (_: RuntimeException) {
            throw mismatch()
        }
    }

    private fun signingCertificateAttribute(signedAttributesSet: ByteArray): EssAttribute {
        val outer = DerReader(signedAttributesSet)
        val set = required(outer, DerValues.TAG_SET)
        if (!outer.isAtEnd) {
            throw mismatch()
        }
        val attributes = outer.children(set)
        var versionOne: ByteArray? = null
        var versionTwo: ByteArray? = null
        var transferred = false
        try {
            while (!attributes.isAtEnd) {
                val attribute = required(attributes, DerValues.TAG_SEQUENCE)
                val fields = attributes.children(attribute)
                val identifier = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
                val values = required(fields, DerValues.TAG_SET)
                if (!fields.isAtEnd) {
                    throw mismatch()
                }
                val encodedIdentifier = fields.raw(identifier)
                try {
                    when {
                        encodedIdentifier.contentEquals(
                            DerEncoder.objectIdentifier(TimestampCmsOids.SIGNING_CERTIFICATE),
                        ) -> {
                            if (versionOne != null) {
                                throw mismatch()
                            }
                            versionOne = fields.raw(values)
                        }

                        encodedIdentifier.contentEquals(
                            DerEncoder.objectIdentifier(QualifiedCmsOids.SIGNING_CERTIFICATE_V2),
                        ) -> {
                            if (versionTwo != null) {
                                throw mismatch()
                            }
                            versionTwo = fields.raw(values)
                        }
                    }
                } finally {
                    encodedIdentifier.fill(ZERO_BYTE)
                }
            }
            val result =
                when {
                    versionOne != null && versionTwo == null -> {
                        EssAttribute(versionOne, versionTwo = false)
                    }

                    versionOne == null && versionTwo != null -> {
                        EssAttribute(versionTwo, versionTwo = true)
                    }

                    else -> {
                        throw mismatch()
                    }
                }
            transferred = true
            return result
        } finally {
            if (!transferred) {
                clear(versionOne, versionTwo)
            }
        }
    }

    private fun references(
        encodedValues: ByteArray,
        versionTwo: Boolean,
    ): List<EssCertificateReference> {
        val values = DerReader(encodedValues)
        val set = required(values, DerValues.TAG_SET)
        if (!values.isAtEnd) {
            throw mismatch()
        }
        val valueSet = values.children(set)
        val signingCertificate = required(valueSet, DerValues.TAG_SEQUENCE)
        if (!valueSet.isAtEnd) {
            throw mismatch()
        }
        val fields = valueSet.children(signingCertificate)
        val certificates = required(fields, DerValues.TAG_SEQUENCE)
        val references = mutableListOf<EssCertificateReference>()
        val list = fields.children(certificates)
        var referencesTransferred = false
        try {
            while (!list.isAtEnd) {
                val reference = required(list, DerValues.TAG_SEQUENCE)
                references += reference(list.raw(reference), versionTwo)
            }
            if (references.isEmpty()) {
                throw mismatch()
            }
            val policies = fields.next()
            if (policies != null) {
                if (policies.tag != DerValues.TAG_SEQUENCE) {
                    throw mismatch()
                }
                validatePolicies(fields.children(policies))
            }
            if (!fields.isAtEnd) {
                throw mismatch()
            }
            return references.also {
                referencesTransferred = true
            }
        } finally {
            if (!referencesTransferred) {
                references.forEach(EssCertificateReference::close)
            }
        }
    }

    private fun reference(
        encoded: ByteArray,
        versionTwo: Boolean,
    ): EssCertificateReference {
        try {
            val outer = DerReader(encoded)
            val sequence = required(outer, DerValues.TAG_SEQUENCE)
            if (!outer.isAtEnd) {
                throw mismatch()
            }
            val fields = outer.children(sequence)
            var candidate = fields.next() ?: throw mismatch()
            val algorithm =
                if (versionTwo && candidate.tag == DerValues.TAG_SEQUENCE) {
                    val parsed = essDigest(fields.raw(candidate))
                    candidate = fields.next() ?: throw mismatch()
                    parsed
                } else if (versionTwo) {
                    EssDigest.SHA256
                } else {
                    EssDigest.SHA1
                }
            if (candidate.tag != DerValues.TAG_OCTET_STRING) {
                throw mismatch()
            }
            val certificateHash = fields.content(candidate)
            if (certificateHash.size != algorithm.byteCount) {
                certificateHash.fill(ZERO_BYTE)
                throw mismatch()
            }
            val issuerSerial = fields.next()
            val issuerSerialEncoding =
                issuerSerial?.let { element ->
                    if (element.tag != DerValues.TAG_SEQUENCE) {
                        certificateHash.fill(ZERO_BYTE)
                        throw mismatch()
                    }
                    val issuerSerialBytes = fields.raw(element)
                    try {
                        validateIssuerSerial(issuerSerialBytes)
                        issuerSerialBytes
                    } catch (failure: TimestampTokenVerificationException) {
                        issuerSerialBytes.fill(ZERO_BYTE)
                        throw failure
                    }
                }
            if (!fields.isAtEnd) {
                certificateHash.fill(ZERO_BYTE)
                issuerSerialEncoding?.fill(ZERO_BYTE)
                throw mismatch()
            }
            return EssCertificateReference(
                algorithm = algorithm,
                certificateHash = certificateHash,
                issuerSerial = issuerSerialEncoding,
            )
        } finally {
            encoded.fill(ZERO_BYTE)
        }
    }

    private fun essDigest(encoded: ByteArray): EssDigest =
        try {
            val outer = DerReader(encoded)
            val sequence = required(outer, DerValues.TAG_SEQUENCE)
            if (!outer.isAtEnd) {
                throw mismatch()
            }
            val fields = outer.children(sequence)
            val identifier = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
            val parameters = fields.next()
            if (parameters != null) {
                val encodedParameters = fields.raw(parameters)
                try {
                    if (!isNull(encodedParameters)) {
                        throw mismatch()
                    }
                } finally {
                    encodedParameters.fill(ZERO_BYTE)
                }
            }
            if (!fields.isAtEnd) {
                throw mismatch()
            }
            val encodedIdentifier = fields.raw(identifier)
            try {
                EssDigest.entries.firstOrNull { digest ->
                    encodedIdentifier.contentEquals(DerEncoder.objectIdentifier(digest.objectIdentifier))
                } ?: throw mismatch()
            } finally {
                encodedIdentifier.fill(ZERO_BYTE)
            }
        } finally {
            encoded.fill(ZERO_BYTE)
        }

    private fun validateIssuerSerial(encoded: ByteArray) {
        val outer = DerReader(encoded)
        val sequence = required(outer, DerValues.TAG_SEQUENCE)
        if (!outer.isAtEnd) {
            throw mismatch()
        }
        val fields = outer.children(sequence)
        val names = required(fields, DerValues.TAG_SEQUENCE)
        val serial = required(fields, DerValues.TAG_INTEGER)
        if (
            !Rfc3161DerValidation.isCanonicalNonNegativeInteger(fields, serial) ||
            !fields.isAtEnd
        ) {
            throw mismatch()
        }
        validateGeneralNames(fields.children(names))
    }

    private fun issuerSerialMatches(
        encoded: ByteArray,
        certificateDer: ByteArray,
    ): Boolean {
        val certificateIdentity =
            try {
                QualifiedDocumentCmsValidation.issuerAndSerial(certificateDer)
            } catch (_: QualifiedDocumentCmsException) {
                return false
            }
        return try {
            matchesCertificateIdentity(encoded, certificateIdentity)
        } finally {
            certificateIdentity.fill(ZERO_BYTE)
        }
    }

    private fun matchesCertificateIdentity(
        encoded: ByteArray,
        certificateIdentity: ByteArray,
    ): Boolean {
        val expected = issuerSerialParts(encoded) ?: return false
        val actual =
            issuerSerialParts(certificateIdentity) ?: run {
                expected.close()
                return false
            }
        return try {
            MessageDigest.isEqual(expected.serial, actual.serial) &&
                hasMatchingDirectoryName(expected.name, actual.name)
        } finally {
            expected.close()
            actual.close()
        }
    }

    private fun issuerSerialParts(encoded: ByteArray): IssuerSerialParts? {
        val outer = DerReader(encoded)
        val sequence = outer.next() ?: return null
        if (sequence.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
            return null
        }
        val fields = outer.children(sequence)
        val names = fields.next() ?: return null
        val serial = fields.next() ?: return null
        if (
            names.tag != DerValues.TAG_SEQUENCE ||
            serial.tag != DerValues.TAG_INTEGER ||
            !fields.isAtEnd
        ) {
            return null
        }
        return IssuerSerialParts(
            name = fields.raw(names),
            serial = fields.content(serial),
        )
    }

    private fun hasMatchingDirectoryName(
        encodedNames: ByteArray,
        encodedIssuer: ByteArray,
    ): Boolean {
        val outer = DerReader(encodedNames)
        val names = outer.next() ?: return false
        if (names.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
            return false
        }
        val generalNames = outer.children(names)
        var match = false
        while (!generalNames.isAtEnd) {
            val name = generalNames.next() ?: return false
            if (name.tag == DerValues.TAG_CONTEXT_4_CONSTRUCTED) {
                val candidate = generalNames.content(name)
                try {
                    match = match || MessageDigest.isEqual(candidate, encodedIssuer)
                } finally {
                    candidate.fill(ZERO_BYTE)
                }
            }
        }
        return match
    }

    private fun validateGeneralNames(reader: DerReader) {
        var count = EMPTY_COUNT
        while (!reader.isAtEnd) {
            val name = reader.next() ?: throw mismatch()
            if (name.tag == DerValues.TAG_CONTEXT_4_CONSTRUCTED) {
                val encodedName = reader.content(name)
                try {
                    if (DerReader.single(encodedName)?.tag != DerValues.TAG_SEQUENCE) {
                        throw mismatch()
                    }
                } finally {
                    encodedName.fill(ZERO_BYTE)
                }
            }
            count += COUNT_STEP
        }
        if (count == EMPTY_COUNT) {
            throw mismatch()
        }
    }

    private fun validatePolicies(reader: DerReader) {
        var count = EMPTY_COUNT
        while (!reader.isAtEnd) {
            required(reader, DerValues.TAG_SEQUENCE)
            count += COUNT_STEP
        }
        if (count == EMPTY_COUNT) {
            throw mismatch()
        }
    }

    private fun isNull(encoded: ByteArray): Boolean {
        val element = DerReader.single(encoded)
        return element?.tag == DerValues.TAG_NULL && element.contentStart == element.contentEnd
    }

    private fun clear(
        first: ByteArray?,
        second: ByteArray?,
    ) {
        first?.fill(ZERO_BYTE)
        second?.fill(ZERO_BYTE)
    }

    private fun required(
        reader: DerReader,
        tag: Int,
    ): DerReader.Element = reader.next()?.takeIf { element -> element.tag == tag } ?: throw mismatch()

    private fun mismatch(): TimestampTokenVerificationException =
        TimestampTokenVerificationException(TimestampTokenVerificationFailure.SIGNING_CERTIFICATE_MISMATCH)

    private enum class EssDigest(
        val objectIdentifier: String,
        val javaName: String,
        val byteCount: Int,
    ) {
        SHA1(
            objectIdentifier = TimestampCmsOids.SHA1,
            javaName = "SHA-1",
            byteCount = SHA1_DIGEST_BYTE_COUNT,
        ),
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
    }

    private class EssAttribute(
        val values: ByteArray,
        val versionTwo: Boolean,
    ) : AutoCloseable {
        override fun close() = values.fill(ZERO_BYTE)
    }

    private class EssCertificateReference(
        val algorithm: EssDigest,
        val certificateHash: ByteArray,
        val issuerSerial: ByteArray?,
    ) : AutoCloseable {
        override fun close() {
            certificateHash.fill(ZERO_BYTE)
            issuerSerial?.fill(ZERO_BYTE)
        }
    }

    private class IssuerSerialParts(
        val name: ByteArray,
        val serial: ByteArray,
    ) : AutoCloseable {
        override fun close() {
            name.fill(ZERO_BYTE)
            serial.fill(ZERO_BYTE)
        }
    }

    private const val SHA1_DIGEST_BYTE_COUNT = 20
    private const val SHA256_DIGEST_BYTE_COUNT = 32
    private const val SHA384_DIGEST_BYTE_COUNT = 48
    private const val SHA512_DIGEST_BYTE_COUNT = 64
    private const val EMPTY_COUNT = 0
    private const val COUNT_STEP = 1
    private const val ZERO_BYTE: Byte = 0
}
