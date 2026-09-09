// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.MessageDigest

internal class ParsedOcspExtension(
    val critical: Boolean,
    val identifier: ByteArray,
    val value: ByteArray,
) : AutoCloseable {
    override fun close() {
        identifier.fill(ZERO_BYTE)
        value.fill(ZERO_BYTE)
    }

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}

/** Strict OCSP extension parsing, nonce binding, and critical-extension policy. */
internal object OcspResponseExtensions {
    fun requireResponseNonce(
        parent: DerReader,
        wrapper: DerReader.Element,
        expectedNonce: ByteArray,
    ) {
        val extensions = parse(parent, wrapper)
        try {
            var echoedNonce: ByteArray? = null
            for (extension in extensions) {
                if (extension.identifier.contentEquals(NONCE_IDENTIFIER)) {
                    if (echoedNonce != null) {
                        throw malformed()
                    }
                    echoedNonce = nonce(extension.value)
                } else if (extension.critical) {
                    throw failure(OcspResponseValidationFailure.UNSUPPORTED_CRITICAL_EXTENSION)
                }
            }
            try {
                if (echoedNonce != null && !MessageDigest.isEqual(echoedNonce, expectedNonce)) {
                    throw failure(OcspResponseValidationFailure.NONCE_MISMATCH)
                }
            } finally {
                echoedNonce?.fill(ZERO_BYTE)
            }
        } finally {
            extensions.forEach(ParsedOcspExtension::close)
        }
    }

    fun rejectCritical(
        parent: DerReader,
        wrapper: DerReader.Element,
    ) {
        val extensions = parse(parent, wrapper)
        try {
            if (extensions.any(ParsedOcspExtension::critical)) {
                throw failure(OcspResponseValidationFailure.UNSUPPORTED_CRITICAL_EXTENSION)
            }
        } finally {
            extensions.forEach(ParsedOcspExtension::close)
        }
    }

    private fun parse(
        parent: DerReader,
        wrapper: DerReader.Element,
    ): List<ParsedOcspExtension> {
        val wrapped = parent.children(wrapper)
        val sequence = required(wrapped, DerValues.TAG_SEQUENCE)
        if (!wrapped.isAtEnd) {
            throw malformed()
        }
        val entries = wrapped.children(sequence)
        val extensions = mutableListOf<ParsedOcspExtension>()
        val identifiers = mutableSetOf<EncodedIdentifier>()
        var transferred = false
        try {
            while (!entries.isAtEnd) {
                val entry = required(entries, DerValues.TAG_SEQUENCE)
                val extension = extension(entries, entry)
                if (!identifiers.add(EncodedIdentifier(extension.identifier.copyOf()))) {
                    extension.close()
                    throw malformed()
                }
                extensions += extension
            }
            if (extensions.isEmpty()) {
                throw malformed()
            }
            return extensions.also {
                transferred = true
            }
        } finally {
            if (!transferred) {
                extensions.forEach(ParsedOcspExtension::close)
            }
        }
    }

    private fun extension(
        parent: DerReader,
        element: DerReader.Element,
    ): ParsedOcspExtension {
        val fields = parent.children(element)
        val identifier = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
        if (!Rfc3161DerValidation.isCanonicalObjectIdentifier(fields, identifier)) {
            throw malformed()
        }
        var value = fields.next() ?: throw malformed()
        var critical = false
        if (value.tag == DerValues.TAG_BOOLEAN) {
            val boolean = fields.content(value)
            try {
                if (!boolean.contentEquals(DER_TRUE_CONTENT)) {
                    throw malformed()
                }
            } finally {
                boolean.fill(ZERO_BYTE)
            }
            critical = true
            value = fields.next() ?: throw malformed()
        }
        if (value.tag != DerValues.TAG_OCTET_STRING || !fields.isAtEnd) {
            throw malformed()
        }
        return ParsedOcspExtension(
            critical = critical,
            identifier = fields.raw(identifier),
            value = fields.content(value),
        )
    }

    private fun nonce(encoded: ByteArray): ByteArray {
        val reader = DerReader(encoded)
        val octetString = required(reader, DerValues.TAG_OCTET_STRING)
        if (!reader.isAtEnd) {
            throw malformed()
        }
        return reader.content(octetString)
    }

    private fun required(
        reader: DerReader,
        tag: Int,
    ): DerReader.Element {
        val element = reader.next() ?: throw malformed()
        if (element.tag != tag) {
            throw malformed()
        }
        return element
    }

    private fun malformed(): OcspResponseValidationException = failure(OcspResponseValidationFailure.MALFORMED)

    private fun failure(kind: OcspResponseValidationFailure): OcspResponseValidationException =
        OcspResponseValidationException(kind)

    private class EncodedIdentifier(
        private val value: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean = other is EncodedIdentifier && value.contentEquals(other.value)

        override fun hashCode(): Int = value.contentHashCode()
    }

    private const val ZERO_BYTE: Byte = 0
    private val DER_TRUE_CONTENT = byteArrayOf(DerValues.DER_TRUE_BYTE)
    private val NONCE_IDENTIFIER = DerEncoder.objectIdentifier(CertificateOids.OCSP_NONCE)
}
