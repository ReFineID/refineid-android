package fi.refineid.android.document

/**
 * Locates every signature in a signed PDF by its `/ByteRange` and reads
 * the CMS blob from the exact gap the range brackets, so the signature
 * bytes cannot be mismatched to another dictionary (PDF 32000-1 section 12.8).
 */
internal object PdfSignatureLocator {
    private val BYTE_RANGE_TOKEN = "/ByteRange".encodeToByteArray()
    private const val ARRAY_OPEN = '['.code.toByte()
    private const val ARRAY_CLOSE = ']'.code.toByte()
    private const val HEX_OPEN = '<'.code.toByte()
    private const val HEX_CLOSE = '>'.code.toByte()
    private const val BYTE_RANGE_FIELD_COUNT = 4
    private const val FIELD_START = 0
    private const val FIELD_FIRST_LENGTH = 1
    private const val FIELD_SECOND_START = 2
    private const val FIELD_SECOND_LENGTH = 3

    fun locate(pdf: ByteArray): List<PdfSignatureLocation> {
        val locations = mutableListOf<PdfSignatureLocation>()
        var searchFrom = 0
        while (true) {
            val tokenAt = indexOf(pdf, BYTE_RANGE_TOKEN, searchFrom)
            if (tokenAt < 0) {
                break
            }
            searchFrom = tokenAt + BYTE_RANGE_TOKEN.size
            locationAt(pdf, searchFrom)?.let(locations::add)
        }
        return locations
    }

    private fun locationAt(
        pdf: ByteArray,
        from: Int,
    ): PdfSignatureLocation? {
        val range = parseByteRange(pdf, from) ?: return null
        val cms = readContents(pdf, range) ?: return null
        return PdfSignatureLocation(
            rangeStart = range[FIELD_START],
            rangeFirstLength = range[FIELD_FIRST_LENGTH],
            rangeSecondStart = range[FIELD_SECOND_START],
            rangeSecondLength = range[FIELD_SECOND_LENGTH],
            cms = cms,
        )
    }

    private fun parseByteRange(
        pdf: ByteArray,
        from: Int,
    ): IntArray? {
        var cursor = skipWhitespace(pdf, from)
        if (cursor >= pdf.size || pdf[cursor] != ARRAY_OPEN) {
            return null
        }
        cursor += 1
        val values = IntArray(BYTE_RANGE_FIELD_COUNT)
        for (index in 0 until BYTE_RANGE_FIELD_COUNT) {
            cursor = skipWhitespace(pdf, cursor)
            var value = 0L
            var digits = 0
            while (cursor < pdf.size && pdf[cursor] in DIGIT_ZERO..DIGIT_NINE) {
                value = value * DECIMAL_BASE + (pdf[cursor] - DIGIT_ZERO)
                if (value > Int.MAX_VALUE) {
                    return null
                }
                cursor += 1
                digits += 1
            }
            if (digits == 0) {
                return null
            }
            values[index] = value.toInt()
        }
        cursor = skipWhitespace(pdf, cursor)
        if (cursor >= pdf.size || pdf[cursor] != ARRAY_CLOSE) {
            return null
        }
        return values
    }

    /** The Contents hex string sits inside the range's signed gap. */
    private fun readContents(
        pdf: ByteArray,
        range: IntArray,
    ): ByteArray? {
        val gapStart = range[FIELD_START].toLong() + range[FIELD_FIRST_LENGTH]
        val gapEnd = range[FIELD_SECOND_START].toLong()
        if (gapStart < 0 || gapEnd > pdf.size || gapStart >= gapEnd) {
            return null
        }
        val open = indexOfByte(pdf, HEX_OPEN, gapStart.toInt(), gapEnd.toInt())
        if (open < 0) {
            return null
        }
        val close = indexOfByte(pdf, HEX_CLOSE, open + 1, gapEnd.toInt())
        if (close < 0) {
            return null
        }
        return decodeHex(pdf, open + 1, close)
    }

    private fun decodeHex(
        pdf: ByteArray,
        start: Int,
        end: Int,
    ): ByteArray? {
        val digits = ArrayList<Int>(end - start)
        for (index in start until end) {
            val byte = pdf[index]
            if (isWhitespace(byte)) {
                continue
            }
            val digit = hexDigit(byte) ?: return null
            digits.add(digit)
        }
        if (digits.isEmpty() || digits.size % 2 != 0) {
            return null
        }
        val decoded = ByteArray(digits.size / 2)
        for (index in decoded.indices) {
            decoded[index] = ((digits[index * 2] shl HEX_NIBBLE_SHIFT) or digits[index * 2 + 1]).toByte()
        }
        return decoded
    }

    private fun hexDigit(byte: Byte): Int? =
        when (byte) {
            in DIGIT_ZERO..DIGIT_NINE -> byte - DIGIT_ZERO
            in HEX_LOWER_A..HEX_LOWER_F -> byte - HEX_LOWER_A + DECIMAL_TEN
            in HEX_UPPER_A..HEX_UPPER_F -> byte - HEX_UPPER_A + DECIMAL_TEN
            else -> null
        }

    private fun skipWhitespace(
        pdf: ByteArray,
        from: Int,
    ): Int {
        var cursor = from
        while (cursor < pdf.size && isWhitespace(pdf[cursor])) {
            cursor += 1
        }
        return cursor
    }

    private fun isWhitespace(byte: Byte): Boolean =
        byte == SPACE ||
            byte == NEWLINE ||
            byte == CARRIAGE_RETURN ||
            byte == TAB ||
            byte == NUL ||
            byte == FORM_FEED

    private fun indexOf(
        haystack: ByteArray,
        needle: ByteArray,
        from: Int,
    ): Int {
        val last = haystack.size - needle.size
        var start = from
        while (start <= last) {
            var matched = true
            for (offset in needle.indices) {
                if (haystack[start + offset] != needle[offset]) {
                    matched = false
                    break
                }
            }
            if (matched) {
                return start
            }
            start += 1
        }
        return -1
    }

    private fun indexOfByte(
        haystack: ByteArray,
        needle: Byte,
        from: Int,
        limit: Int,
    ): Int {
        var cursor = from
        while (cursor < limit) {
            if (haystack[cursor] == needle) {
                return cursor
            }
            cursor += 1
        }
        return -1
    }

    private const val DIGIT_ZERO = '0'.code.toByte()
    private const val DIGIT_NINE = '9'.code.toByte()
    private const val HEX_LOWER_A = 'a'.code.toByte()
    private const val HEX_LOWER_F = 'f'.code.toByte()
    private const val HEX_UPPER_A = 'A'.code.toByte()
    private const val HEX_UPPER_F = 'F'.code.toByte()
    private const val DECIMAL_BASE = 10L
    private const val DECIMAL_TEN = 10
    private const val HEX_NIBBLE_SHIFT = 4
    private const val SPACE = ' '.code.toByte()
    private const val NEWLINE = '\n'.code.toByte()
    private const val CARRIAGE_RETURN = '\r'.code.toByte()
    private const val TAB = '\t'.code.toByte()
    private const val NUL: Byte = 0
    private const val FORM_FEED: Byte = 12
}
