// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** Canonical DER primitives shared by the timestamp response parsers. */
internal object Rfc3161DerValidation {
    fun nonNegativeLong(
        reader: DerReader,
        element: DerReader.Element,
    ): Long? {
        if (element.tag != DerValues.TAG_INTEGER) {
            return null
        }
        return nonNegativeLongContent(reader.content(element))
    }

    fun implicitNonNegativeLong(
        reader: DerReader,
        element: DerReader.Element,
    ): Long? = nonNegativeLongContent(reader.content(element))

    fun isCanonicalNonNegativeInteger(
        reader: DerReader,
        element: DerReader.Element,
    ): Boolean {
        if (element.tag != DerValues.TAG_INTEGER) {
            return false
        }
        val content = reader.content(element)
        return try {
            isCanonicalNonNegativeInteger(content)
        } finally {
            content.fill(ZERO_BYTE)
        }
    }

    fun isCanonicalObjectIdentifier(
        reader: DerReader,
        element: DerReader.Element,
    ): Boolean {
        if (element.tag != DerValues.TAG_OBJECT_IDENTIFIER) {
            return false
        }
        val content = reader.content(element)
        return try {
            isCanonicalObjectIdentifier(content)
        } finally {
            content.fill(ZERO_BYTE)
        }
    }

    private fun nonNegativeLongContent(content: ByteArray): Long? {
        return try {
            if (!isCanonicalNonNegativeInteger(content)) {
                return null
            }
            var value = INITIAL_INTEGER_VALUE
            for (byte in content) {
                val digit = byte.toUnsignedInt()
                if (value > (Long.MAX_VALUE - digit) / UNSIGNED_BYTE_RADIX) {
                    return null
                }
                value = value * UNSIGNED_BYTE_RADIX + digit
            }
            value
        } finally {
            content.fill(ZERO_BYTE)
        }
    }

    private fun isCanonicalNonNegativeInteger(content: ByteArray): Boolean {
        if (content.isEmpty()) {
            return false
        }
        if (content[FIRST_CONTENT_OFFSET].toUnsignedInt() and DerValues.SIGN_BIT_MASK != 0) {
            return false
        }
        if (content.size == SINGLE_BYTE_COUNT || content[FIRST_CONTENT_OFFSET] != ZERO_BYTE) {
            return true
        }
        return content[SECOND_CONTENT_OFFSET].toUnsignedInt() and DerValues.SIGN_BIT_MASK != 0
    }

    private fun isCanonicalObjectIdentifier(content: ByteArray): Boolean {
        if (content.isEmpty()) {
            return false
        }
        var startsSubIdentifier = true
        for (byte in content) {
            val value = byte.toUnsignedInt()
            if (startsSubIdentifier && value == OID_NON_MINIMAL_LEADING_GROUP) {
                return false
            }
            startsSubIdentifier = value and OID_CONTINUATION_MASK == NO_CONTINUATION_BIT
        }
        return startsSubIdentifier
    }

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private const val FIRST_CONTENT_OFFSET = 0
    private const val SECOND_CONTENT_OFFSET = 1
    private const val SINGLE_BYTE_COUNT = 1
    private const val INITIAL_INTEGER_VALUE = 0L
    private const val UNSIGNED_BYTE_RADIX = 256L
    private const val OID_NON_MINIMAL_LEADING_GROUP = 0x80
    private const val OID_CONTINUATION_MASK = 0x80
    private const val NO_CONTINUATION_BIT = 0
    private const val ZERO_BYTE: Byte = 0
}
