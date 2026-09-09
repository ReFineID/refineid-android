// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** Reads one unique X.509 extnValue from the exact signed certificate encoding. */
internal object CertificateExtensionReader {
    fun value(
        certificate: ByteArray,
        identifier: String,
    ): ByteArray? =
        try {
            val outer = DerReader(certificate)
            val sequence = required(outer, DerValues.TAG_SEQUENCE) ?: return null
            if (!outer.isAtEnd) {
                return null
            }
            val certificateFields = outer.children(sequence)
            val tbs = required(certificateFields, DerValues.TAG_SEQUENCE) ?: return null
            if (
                required(certificateFields, DerValues.TAG_SEQUENCE) == null ||
                required(certificateFields, DerValues.TAG_BIT_STRING) == null ||
                !certificateFields.isAtEnd
            ) {
                return null
            }
            extensionValue(certificateFields.children(tbs), DerEncoder.objectIdentifier(identifier))
        } catch (_: RuntimeException) {
            null
        }

    private fun extensionValue(
        fields: DerReader,
        expectedIdentifier: ByteArray,
    ): ByteArray? {
        var serial = fields.next() ?: return null
        if (serial.tag == DerValues.TAG_CONTEXT_0_CONSTRUCTED) {
            serial = fields.next() ?: return null
        }
        if (serial.tag != DerValues.TAG_INTEGER) {
            return null
        }
        repeat(FIXED_SEQUENCE_COUNT_AFTER_SERIAL) {
            if (required(fields, DerValues.TAG_SEQUENCE) == null) {
                return null
            }
        }
        var found: ByteArray? = null
        var extensionsSeen = false
        while (!fields.isAtEnd) {
            val trailing = fields.next() ?: return null
            when (trailing.tag) {
                DerValues.TAG_CONTEXT_1_PRIMITIVE,
                DerValues.TAG_CONTEXT_2_PRIMITIVE,
                -> {
                    // Primitive context tags carry no nested extension content.
                }

                DerValues.TAG_CONTEXT_3_CONSTRUCTED -> {
                    if (extensionsSeen) {
                        found?.fill(ZERO_BYTE)
                        return null
                    }
                    found = extensionValue(fields, trailing, expectedIdentifier)
                    extensionsSeen = true
                }

                else -> {
                    return null
                }
            }
        }
        return found
    }

    private fun extensionValue(
        parent: DerReader,
        wrapper: DerReader.Element,
        expectedIdentifier: ByteArray,
    ): ByteArray? {
        val wrapped = parent.children(wrapper)
        val sequence = required(wrapped, DerValues.TAG_SEQUENCE) ?: return null
        if (!wrapped.isAtEnd) {
            return null
        }
        val entries = wrapped.children(sequence)
        var found: ByteArray? = null
        val identifiers = mutableSetOf<EncodedIdentifier>()
        while (!entries.isAtEnd) {
            val entry = required(entries, DerValues.TAG_SEQUENCE) ?: return null
            val extension = parsedExtension(entries, entry)
            if (extension == null) {
                found?.fill(ZERO_BYTE)
                return null
            }
            extension.use { parsed ->
                if (!identifiers.add(EncodedIdentifier(parsed.identifier.copyOf()))) {
                    found?.fill(ZERO_BYTE)
                    return null
                }
                if (parsed.identifier.contentEquals(expectedIdentifier)) {
                    if (found != null) {
                        found.fill(ZERO_BYTE)
                        return null
                    }
                    found = parsed.value.copyOf()
                }
            }
        }
        return found
    }

    private fun parsedExtension(
        parent: DerReader,
        element: DerReader.Element,
    ): ParsedCertificateExtension? {
        val fields = parent.children(element)
        val identifier = required(fields, DerValues.TAG_OBJECT_IDENTIFIER) ?: return null
        var value = fields.next() ?: return null
        if (value.tag == DerValues.TAG_BOOLEAN) {
            val critical = fields.content(value)
            val valid = critical.contentEquals(DER_TRUE_CONTENT)
            critical.fill(ZERO_BYTE)
            if (!valid) {
                return null
            }
            value = fields.next() ?: return null
        }
        if (value.tag != DerValues.TAG_OCTET_STRING || !fields.isAtEnd) {
            return null
        }
        return ParsedCertificateExtension(
            identifier = fields.raw(identifier),
            value = fields.content(value),
        )
    }

    private fun required(
        reader: DerReader,
        tag: Int,
    ): DerReader.Element? {
        val element = reader.next() ?: return null
        return element.takeIf { value -> value.tag == tag }
    }

    private class EncodedIdentifier(
        private val value: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean = other is EncodedIdentifier && value.contentEquals(other.value)

        override fun hashCode(): Int = value.contentHashCode()
    }

    private class ParsedCertificateExtension(
        val identifier: ByteArray,
        val value: ByteArray,
    ) : AutoCloseable {
        override fun close() {
            identifier.fill(ZERO_BYTE)
            value.fill(ZERO_BYTE)
        }
    }

    private const val FIXED_SEQUENCE_COUNT_AFTER_SERIAL = 5
    private const val ZERO_BYTE: Byte = 0
    private val DER_TRUE_CONTENT = byteArrayOf(DerValues.DER_TRUE_BYTE)
}
