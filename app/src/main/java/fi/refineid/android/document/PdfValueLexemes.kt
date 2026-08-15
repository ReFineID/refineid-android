// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** Numeric tokens, escaped names, and byte classification shared by PDF value parsing. */
internal object PdfValueLexemes {
    fun decodedName(
        bytes: ByteArray,
        range: PdfBytes.Range,
    ): String? {
        val decoded = mutableListOf<Byte>()
        var cursor = range.start + NAME_PREFIX_LENGTH
        while (cursor < range.endExclusive) {
            if (bytes[cursor] == NAME_ESCAPE_BYTE) {
                if (cursor + NAME_ESCAPE_DIGIT_COUNT >= range.endExclusive) {
                    return null
                }
                val high = hex(bytes[cursor + FIRST_ESCAPE_DIGIT_OFFSET]) ?: return null
                val low = hex(bytes[cursor + SECOND_ESCAPE_DIGIT_OFFSET]) ?: return null
                decoded.add((high * HEX_RADIX + low).toByte())
                cursor += NAME_ESCAPE_LENGTH
            } else {
                decoded.add(bytes[cursor])
                cursor += BYTE_OFFSET_STEP
            }
        }
        return String(decoded.toByteArray(), Charsets.ISO_8859_1)
    }

    fun unsignedInteger(
        bytes: ByteArray,
        range: PdfBytes.Range,
    ): Int? {
        if (range.length == EMPTY_TOKEN_LENGTH) {
            return null
        }
        var value = INITIAL_UNSIGNED_INTEGER
        for (index in range.start until range.endExclusive) {
            val byte = bytes[index]
            if (byte !in ASCII_ZERO_BYTE..ASCII_NINE_BYTE) {
                return null
            }
            value =
                try {
                    Math.addExact(
                        Math.multiplyExact(value, PdfFormat.DECIMAL_RADIX),
                        byte - ASCII_ZERO_BYTE,
                    )
                } catch (_: ArithmeticException) {
                    return null
                }
        }
        return value
    }

    fun text(
        bytes: ByteArray,
        range: PdfBytes.Range,
    ): String =
        String(
            bytes = bytes,
            offset = range.start,
            length = range.length,
            charset = Charsets.ISO_8859_1,
        )

    fun isPlainName(name: String): Boolean {
        val encoded = strictLatin1(name) ?: return false
        return encoded.isNotEmpty() && encoded.none(::isDelimiter)
    }

    fun strictLatin1(text: String): ByteArray? =
        text
            .takeIf { value ->
                value.all { character -> character.code <= MAXIMUM_LATIN1_CODE_POINT }
            }?.toByteArray(Charsets.ISO_8859_1)

    fun isDelimiter(byte: Byte): Boolean = isWhitespace(byte) || byte in PdfFormat.DELIMITER_BYTES

    fun isWhitespace(byte: Byte): Boolean = byte in PdfFormat.WHITESPACE_BYTES

    private fun hex(byte: Byte): Int? =
        when (byte) {
            in ASCII_ZERO_BYTE..ASCII_NINE_BYTE -> {
                byte - ASCII_ZERO_BYTE
            }

            in ASCII_UPPER_A_BYTE..ASCII_UPPER_F_BYTE -> {
                byte - ASCII_UPPER_A_BYTE + DECIMAL_DIGIT_COUNT
            }

            in ASCII_LOWER_A_BYTE..ASCII_LOWER_F_BYTE -> {
                byte - ASCII_LOWER_A_BYTE + DECIMAL_DIGIT_COUNT
            }

            else -> {
                null
            }
        }

    private const val NAME_PREFIX_LENGTH = 1
    private const val NAME_ESCAPE_DIGIT_COUNT = 2
    private const val FIRST_ESCAPE_DIGIT_OFFSET = 1
    private const val SECOND_ESCAPE_DIGIT_OFFSET = 2
    private const val NAME_ESCAPE_LENGTH = 3
    private const val HEX_RADIX = 16
    private const val DECIMAL_DIGIT_COUNT = 10
    private const val EMPTY_TOKEN_LENGTH = 0
    private const val INITIAL_UNSIGNED_INTEGER = 0
    private const val MAXIMUM_LATIN1_CODE_POINT = 0xFF
    private const val BYTE_OFFSET_STEP = 1
    private val NAME_ESCAPE_BYTE = '#'.code.toByte()
    private val ASCII_ZERO_BYTE = '0'.code.toByte()
    private val ASCII_NINE_BYTE = '9'.code.toByte()
    private val ASCII_UPPER_A_BYTE = 'A'.code.toByte()
    private val ASCII_UPPER_F_BYTE = 'F'.code.toByte()
    private val ASCII_LOWER_A_BYTE = 'a'.code.toByte()
    private val ASCII_LOWER_F_BYTE = 'f'.code.toByte()
}
