// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** Minimal definite-length DER support for the document-signing structures. */
internal object DerEncoder {
    fun tlv(
        tag: Int,
        content: ByteArray,
    ): ByteArray {
        requireSingleByteTag(tag)
        val length = lengthOctets(content.size)
        return ByteArray(TAG_BYTE_COUNT + length.size + content.size).also { encoded ->
            encoded[TAG_OFFSET] = tag.toByte()
            length.copyInto(encoded, destinationOffset = TAG_BYTE_COUNT)
            content.copyInto(
                encoded,
                destinationOffset = TAG_BYTE_COUNT + length.size,
            )
        }
    }

    fun sequence(elements: List<ByteArray>): ByteArray = tlv(DerValues.TAG_SEQUENCE, concatenate(elements))

    fun setOf(elements: List<ByteArray>): ByteArray =
        tlv(
            DerValues.TAG_SET,
            concatenate(elements.sortedWith(DER_LEXICOGRAPHIC_ORDER)),
        )

    fun integer(value: Int): ByteArray {
        require(value >= MINIMUM_SUPPORTED_INTEGER) {
            "DER helper accepts only non-negative integers"
        }
        var remaining = value
        val magnitude = ArrayDeque<Byte>()
        do {
            magnitude.addFirst((remaining and UNSIGNED_BYTE_MASK).toByte())
            remaining = remaining ushr Byte.SIZE_BITS
        } while (remaining > MINIMUM_SUPPORTED_INTEGER)
        return unsignedInteger(magnitude.toByteArray())
    }

    fun unsignedInteger(magnitude: ByteArray): ByteArray {
        var first = magnitude.indexOfFirst { byte -> byte != ZERO_BYTE }
        if (first == MISSING_INDEX) {
            first = magnitude.size
        }
        val hasMagnitude = first < magnitude.size
        val requiresPositivePrefix =
            hasMagnitude && magnitude[first].toUnsignedInt() and DerValues.SIGN_BIT_MASK != 0
        val valueLength =
            when {
                !hasMagnitude -> ZERO_INTEGER_LENGTH
                requiresPositivePrefix -> magnitude.size - first + POSITIVE_PREFIX_LENGTH
                else -> magnitude.size - first
            }
        val value = ByteArray(valueLength)
        if (hasMagnitude) {
            magnitude.copyInto(
                destination = value,
                destinationOffset =
                    if (requiresPositivePrefix) {
                        POSITIVE_PREFIX_LENGTH
                    } else {
                        NO_POSITIVE_PREFIX_LENGTH
                    },
                startIndex = first,
            )
        }
        return tlv(DerValues.TAG_INTEGER, value)
    }

    fun octetString(content: ByteArray): ByteArray = tlv(DerValues.TAG_OCTET_STRING, content)

    fun booleanTrue(): ByteArray = tlv(DerValues.TAG_BOOLEAN, byteArrayOf(DerValues.DER_TRUE_BYTE))

    fun nullValue(): ByteArray = tlv(DerValues.TAG_NULL, byteArrayOf())

    fun objectIdentifier(dotted: String): ByteArray {
        val parts = dotted.split(OID_SEPARATOR)
        require(parts.size >= MINIMUM_OID_ARC_COUNT && parts.none(String::isEmpty)) {
            "object identifier has too few arcs"
        }
        val arcs =
            parts.map { part ->
                require(part.all(Char::isDigit)) {
                    "object identifier contains a non-decimal arc"
                }
                part.toLongOrNull() ?: throw IllegalArgumentException("object identifier arc is too large")
            }
        val first = arcs[FIRST_OID_ARC_OFFSET]
        val second = arcs[SECOND_OID_ARC_OFFSET]
        require(first in MINIMUM_FIRST_OID_ARC..MAXIMUM_FIRST_OID_ARC) {
            "object identifier first arc is invalid"
        }
        require(
            first == MAXIMUM_FIRST_OID_ARC ||
                second <= MAXIMUM_SECOND_OID_ARC_BEFORE_THIRD_ROOT,
        ) {
            "object identifier second arc is invalid"
        }
        val combined =
            Math.addExact(
                Math.multiplyExact(first, OID_FIRST_ARC_MULTIPLIER),
                second,
            )
        val content = ArrayList<Byte>()
        content.addAll(encodeOidArc(combined).asList())
        for (arc in arcs.drop(OID_SHARED_ARC_COUNT)) {
            content.addAll(encodeOidArc(arc).asList())
        }
        return tlv(DerValues.TAG_OBJECT_IDENTIFIER, content.toByteArray())
    }

    fun retagged(
        encoded: ByteArray,
        tag: Int,
    ): ByteArray {
        requireSingleByteTag(tag)
        require(DerReader.single(encoded) != null) {
            "only one complete DER value can be retagged"
        }
        return encoded.copyOf().also { copy -> copy[TAG_OFFSET] = tag.toByte() }
    }

    private fun requireSingleByteTag(tag: Int) {
        require(tag in MINIMUM_SINGLE_BYTE_TAG..MAXIMUM_SINGLE_BYTE_TAG) {
            "DER tag is not a supported single-byte identifier"
        }
        require(tag and HIGH_TAG_NUMBER_MASK != HIGH_TAG_NUMBER_MASK) {
            "DER high-tag-number form is unsupported"
        }
    }

    private fun lengthOctets(length: Int): ByteArray {
        require(length >= MINIMUM_DER_LENGTH) {
            "DER length cannot be negative"
        }
        if (length <= SHORT_FORM_MAXIMUM) {
            return byteArrayOf(length.toByte())
        }
        var remaining = length
        val magnitude = ArrayDeque<Byte>()
        while (remaining > MINIMUM_DER_LENGTH) {
            magnitude.addFirst((remaining and UNSIGNED_BYTE_MASK).toByte())
            remaining = remaining ushr Byte.SIZE_BITS
        }
        require(magnitude.size <= MAXIMUM_LENGTH_OCTET_COUNT) {
            "DER length exceeds the supported long form"
        }
        return byteArrayOf((LONG_FORM_MASK or magnitude.size).toByte()) + magnitude.toByteArray()
    }

    private fun encodeOidArc(arc: Long): ByteArray {
        require(arc >= MINIMUM_OID_ARC) {
            "object identifier arc cannot be negative"
        }
        var remaining = arc
        val septets = ArrayDeque<Byte>()
        septets.addFirst((remaining and OID_ARC_VALUE_MASK).toByte())
        remaining = remaining ushr OID_ARC_BIT_COUNT
        while (remaining > MINIMUM_OID_ARC) {
            septets.addFirst(
                (OID_CONTINUATION_BIT or (remaining and OID_ARC_VALUE_MASK)).toByte(),
            )
            remaining = remaining ushr OID_ARC_BIT_COUNT
        }
        return septets.toByteArray()
    }

    private fun concatenate(elements: List<ByteArray>): ByteArray {
        val size =
            elements.fold(INITIAL_COMBINED_LENGTH) { total, element ->
                Math.addExact(total, element.size)
            }
        return ByteArray(size).also { combined ->
            var offset = INITIAL_COMBINED_OFFSET
            for (element in elements) {
                element.copyInto(combined, destinationOffset = offset)
                offset += element.size
            }
        }
    }

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private val DER_LEXICOGRAPHIC_ORDER =
        Comparator<ByteArray> { left, right ->
            val sharedLength = minOf(left.size, right.size)
            for (index in FIRST_COLLECTION_INDEX until sharedLength) {
                val comparison =
                    left[index].toUnsignedInt().compareTo(right[index].toUnsignedInt())
                if (comparison != EQUAL_COMPARISON) {
                    return@Comparator comparison
                }
            }
            left.size.compareTo(right.size)
        }

    private const val MINIMUM_SINGLE_BYTE_TAG = 0
    private const val MAXIMUM_SINGLE_BYTE_TAG = 0xFF
    private const val HIGH_TAG_NUMBER_MASK = 0x1F
    private const val TAG_OFFSET = 0
    private const val TAG_BYTE_COUNT = 1
    private const val MINIMUM_SUPPORTED_INTEGER = 0
    private const val ZERO_INTEGER_LENGTH = 1
    private const val POSITIVE_PREFIX_LENGTH = 1
    private const val NO_POSITIVE_PREFIX_LENGTH = 0
    private const val MISSING_INDEX = -1
    private const val UNSIGNED_BYTE_MASK = 0xFF
    private const val OID_SEPARATOR = "."
    private const val MINIMUM_OID_ARC_COUNT = 2
    private const val FIRST_OID_ARC_OFFSET = 0
    private const val SECOND_OID_ARC_OFFSET = 1
    private const val OID_SHARED_ARC_COUNT = 2
    private const val MINIMUM_FIRST_OID_ARC = 0L
    private const val MAXIMUM_FIRST_OID_ARC = 2L
    private const val MAXIMUM_SECOND_OID_ARC_BEFORE_THIRD_ROOT = 39L
    private const val OID_FIRST_ARC_MULTIPLIER = 40L
    private const val MINIMUM_OID_ARC = 0L
    private const val OID_CONTINUATION_BIT = 0x80L
    private const val OID_ARC_BIT_COUNT = 7
    private const val OID_ARC_VALUE_MASK = 0x7FL
    private const val MINIMUM_DER_LENGTH = 0
    private const val SHORT_FORM_MAXIMUM = 127
    private const val LONG_FORM_MASK = 0x80
    private const val MAXIMUM_LENGTH_OCTET_COUNT = Int.SIZE_BYTES
    private const val INITIAL_COMBINED_LENGTH = 0
    private const val INITIAL_COMBINED_OFFSET = 0
    private const val FIRST_COLLECTION_INDEX = 0
    private const val EQUAL_COMPARISON = 0
    private const val ZERO_BYTE: Byte = 0
}

/** One bounded, strict DER walk retaining raw ranges for CMS identity fields. */
internal class DerReader private constructor(
    private val bytes: ByteArray,
    private var offset: Int,
    private val limit: Int,
) {
    data class Element(
        val tag: Int,
        val rawStart: Int,
        val rawEnd: Int,
        val contentStart: Int,
        val contentEnd: Int,
    )

    constructor(bytes: ByteArray) : this(
        bytes = bytes,
        offset = INITIAL_OFFSET,
        limit = bytes.size,
    )

    val isAtEnd: Boolean
        get() = offset == limit

    fun next(): Element? {
        if (limit - offset < MINIMUM_ELEMENT_LENGTH) {
            return null
        }
        val start = offset
        val tag = bytes[offset].toUnsignedInt()
        if (tag and HIGH_TAG_NUMBER_MASK == HIGH_TAG_NUMBER_MASK) {
            return null
        }
        var cursor = offset + TAG_BYTE_COUNT
        val firstLength = bytes[cursor].toUnsignedInt()
        cursor += LENGTH_PREFIX_BYTE_COUNT
        val contentLength =
            if (firstLength and LONG_FORM_MASK == SHORT_FORM_MARKER) {
                firstLength
            } else {
                val count = firstLength and LENGTH_COUNT_MASK
                if (
                    count !in MINIMUM_LONG_FORM_OCTET_COUNT..MAXIMUM_LONG_FORM_OCTET_COUNT ||
                    limit - cursor < count ||
                    bytes[cursor] == ZERO_BYTE
                ) {
                    return null
                }
                var decoded = INITIAL_DECODED_LENGTH
                repeat(count) {
                    decoded =
                        (decoded shl Byte.SIZE_BITS) or
                        bytes[cursor].toUnsignedInt().toLong()
                    cursor += LENGTH_VALUE_BYTE_COUNT
                }
                if (decoded <= SHORT_FORM_MAXIMUM || decoded > Int.MAX_VALUE) {
                    return null
                }
                decoded.toInt()
            }
        if (contentLength > limit - cursor) {
            return null
        }
        val end = cursor + contentLength
        offset = end
        return Element(
            tag = tag,
            rawStart = start,
            rawEnd = end,
            contentStart = cursor,
            contentEnd = end,
        )
    }

    fun children(element: Element): DerReader =
        DerReader(
            bytes = bytes,
            offset = element.contentStart,
            limit = element.contentEnd,
        )

    fun raw(element: Element): ByteArray = bytes.copyOfRange(element.rawStart, element.rawEnd)

    fun content(element: Element): ByteArray = bytes.copyOfRange(element.contentStart, element.contentEnd)

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    companion object {
        fun single(encoded: ByteArray): Element? {
            val reader = DerReader(encoded)
            val element = reader.next() ?: return null
            return element.takeIf { reader.isAtEnd }
        }

        private const val INITIAL_OFFSET = 0
        private const val MINIMUM_ELEMENT_LENGTH = 2
        private const val TAG_BYTE_COUNT = 1
        private const val LENGTH_PREFIX_BYTE_COUNT = 1
        private const val LENGTH_VALUE_BYTE_COUNT = 1
        private const val HIGH_TAG_NUMBER_MASK = 0x1F
        private const val LONG_FORM_MASK = 0x80
        private const val SHORT_FORM_MARKER = 0
        private const val LENGTH_COUNT_MASK = 0x7F
        private const val MINIMUM_LONG_FORM_OCTET_COUNT = 1
        private const val MAXIMUM_LONG_FORM_OCTET_COUNT = Int.SIZE_BYTES
        private const val SHORT_FORM_MAXIMUM = 127L
        private const val INITIAL_DECODED_LENGTH = 0L
        private const val ZERO_BYTE: Byte = 0
    }
}

internal object DerValues {
    const val TAG_BOOLEAN = 0x01
    const val TAG_INTEGER = 0x02
    const val TAG_BIT_STRING = 0x03
    const val TAG_OCTET_STRING = 0x04
    const val TAG_NULL = 0x05
    const val TAG_OBJECT_IDENTIFIER = 0x06
    const val TAG_UTF8_STRING = 0x0C
    const val TAG_GENERALIZED_TIME = 0x18
    const val TAG_SEQUENCE = 0x30
    const val TAG_SET = 0x31
    const val TAG_CONTEXT_0_PRIMITIVE = 0x80
    const val TAG_CONTEXT_1_PRIMITIVE = 0x81
    const val TAG_CONTEXT_0_CONSTRUCTED = 0xA0
    const val TAG_CONTEXT_1_CONSTRUCTED = 0xA1
    const val TAG_CONTEXT_2_CONSTRUCTED = 0xA2
    const val TAG_CONTEXT_3_CONSTRUCTED = 0xA3
    const val TAG_CONTEXT_4_CONSTRUCTED = 0xA4
    const val SIGN_BIT_MASK = 0x80
    const val DER_TRUE_BYTE: Byte = -1
    const val DER_FALSE_BYTE: Byte = 0
}
