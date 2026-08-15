// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** PDF bytes addressed by byte offset, never by decoded character position. */
internal class PdfBytes(
    private val bytes: ByteArray,
) {
    data class Range(
        val start: Int,
        val endExclusive: Int,
    ) {
        init {
            require(start >= FIRST_BYTE_OFFSET && endExclusive >= start)
        }

        val length: Int
            get() = endExclusive - start

        private companion object {
            const val FIRST_BYTE_OFFSET = 0
        }
    }

    data class DecimalToken(
        val value: Int,
        val endExclusive: Int,
    )

    val size: Int
        get() = bytes.size

    fun startsWith(prefix: String): Boolean {
        val expected = prefix.encodeToByteArray()
        return bytes.size >= expected.size &&
            expected.indices.all { index -> bytes[index] == expected[index] }
    }

    fun hasKeyword(
        keyword: String,
        at: Int,
    ): Boolean {
        val expected = keyword.encodeToByteArray()
        if (at < FIRST_BYTE_OFFSET || expected.size > bytes.size - at) {
            return false
        }
        return expected.indices.all { index -> bytes[at + index] == expected[index] }
    }

    fun hasToken(
        token: String,
        at: Int,
    ): Boolean {
        if (!hasKeyword(token, at)) {
            return false
        }
        val end = at + token.length
        return end == bytes.size || isBoundary(bytes[end])
    }

    fun firstRange(
        keyword: String,
        from: Int,
    ): Range? {
        val expected = keyword.encodeToByteArray()
        if (expected.isEmpty() || expected.size > bytes.size) {
            return null
        }
        var cursor = from.coerceAtLeast(FIRST_BYTE_OFFSET)
        while (cursor <= bytes.size - expected.size) {
            if (expected.indices.all { index -> bytes[cursor + index] == expected[index] }) {
                return Range(cursor, cursor + expected.size)
            }
            cursor += BYTE_OFFSET_STEP
        }
        return null
    }

    fun lastRange(keyword: String): Range? {
        val expected = keyword.encodeToByteArray()
        if (expected.isEmpty() || expected.size > bytes.size) {
            return null
        }
        var cursor = bytes.size - expected.size
        while (cursor >= FIRST_BYTE_OFFSET) {
            if (expected.indices.all { index -> bytes[cursor + index] == expected[index] }) {
                return Range(cursor, cursor + expected.size)
            }
            cursor -= BYTE_OFFSET_STEP
        }
        return null
    }

    fun skippingWhitespace(from: Int): Int {
        var cursor = from.coerceAtLeast(FIRST_BYTE_OFFSET)
        while (cursor < bytes.size && bytes[cursor] in PdfFormat.WHITESPACE_BYTES) {
            cursor += BYTE_OFFSET_STEP
        }
        return cursor
    }

    fun decimal(at: Int): Int? = decimalToken(at)?.value

    fun decimalToken(at: Int): DecimalToken? {
        var cursor = at
        var value = INITIAL_DECIMAL_VALUE
        var sawDigit = false
        while (cursor in bytes.indices && bytes[cursor] in ASCII_ZERO..ASCII_NINE) {
            val digit = bytes[cursor] - ASCII_ZERO
            value =
                try {
                    Math.addExact(
                        Math.multiplyExact(value, PdfFormat.DECIMAL_RADIX),
                        digit,
                    )
                } catch (_: ArithmeticException) {
                    return null
                }
            cursor += BYTE_OFFSET_STEP
            sawDigit = true
        }
        return if (sawDigit) DecimalToken(value, cursor) else null
    }

    fun text(range: Range): String {
        val bounded = bounded(range)
        return String(
            bytes = bytes,
            offset = bounded.start,
            length = bounded.length,
            charset = Charsets.ISO_8859_1,
        )
    }

    fun data(range: Range): ByteArray {
        val bounded = bounded(range)
        return bytes.copyOfRange(bounded.start, bounded.endExclusive)
    }

    fun balancedDictionary(from: Int): Pair<String, Int>? {
        val opening = firstRange(PdfFormat.DICTIONARY_OPEN, from) ?: return null
        var depth = INITIAL_DICTIONARY_DEPTH
        var cursor = opening.start
        while (cursor < size) {
            when {
                hasKeyword(PdfFormat.DICTIONARY_OPEN, cursor) -> {
                    depth += DICTIONARY_DEPTH_STEP
                    cursor += PdfFormat.DICTIONARY_MARKER_LENGTH
                }

                hasKeyword(PdfFormat.DICTIONARY_CLOSE, cursor) -> {
                    depth -= DICTIONARY_DEPTH_STEP
                    cursor += PdfFormat.DICTIONARY_MARKER_LENGTH
                    if (depth == INITIAL_DICTIONARY_DEPTH) {
                        return text(Range(opening.start, cursor)) to cursor
                    }
                }

                else -> {
                    cursor += BYTE_OFFSET_STEP
                }
            }
        }
        return null
    }

    private fun bounded(range: Range): Range =
        Range(
            start = range.start.coerceIn(FIRST_BYTE_OFFSET, bytes.size),
            endExclusive = range.endExclusive.coerceIn(FIRST_BYTE_OFFSET, bytes.size),
        )

    private fun isBoundary(byte: Byte): Boolean =
        byte in PdfFormat.WHITESPACE_BYTES || byte in PdfFormat.DELIMITER_BYTES

    private companion object {
        const val FIRST_BYTE_OFFSET = 0
        const val BYTE_OFFSET_STEP = 1
        const val INITIAL_DECIMAL_VALUE = 0
        const val INITIAL_DICTIONARY_DEPTH = 0
        const val DICTIONARY_DEPTH_STEP = 1
        val ASCII_ZERO = '0'.code.toByte()
        val ASCII_NINE = '9'.code.toByte()
    }
}
