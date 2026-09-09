package fi.refineid.android.document

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PdfBytesTest {
    @Test
    fun addressesLatin1ContentByByteOffset() {
        val document = PdfTestDocuments.latin1(LATIN1_PREFIX + LATIN1_MARKER + LATIN1_SUFFIX)
        val bytes = PdfBytes(document)
        val markerStart = PdfTestDocuments.latin1(LATIN1_PREFIX).size
        val marker =
            PdfBytes.Range(
                start = markerStart,
                endExclusive = markerStart + LATIN1_MARKER_BYTE_COUNT,
            )

        assertEquals(markerStart, marker.start)
        assertEquals(LATIN1_MARKER, bytes.text(marker))
        assertTrue(bytes.hasKeyword(LATIN1_SUFFIX, marker.endExclusive))
        assertFalse(bytes.hasKeyword(LATIN1_MARKER, OUT_OF_RANGE_OFFSET))
    }

    @Test
    fun parsesBoundedDecimalsAndRefusesIntegerOverflow() {
        val bytes = PdfBytes((WHITESPACE_PREFIX + MAXIMUM_INT_TEXT + TRAILING_TEXT).encodeToByteArray())
        val start = bytes.skippingWhitespace(FIRST_BYTE_OFFSET)
        val token = checkNotNull(bytes.decimalToken(start))

        assertEquals(Int.MAX_VALUE, token.value)
        assertEquals(TRAILING_TEXT_OFFSET, token.endExclusive)

        val overflow = PdfBytes(OVERFLOWING_INT_TEXT.encodeToByteArray())
        assertNull(overflow.decimal(FIRST_BYTE_OFFSET))
    }

    @Test
    fun findsTheLastKeywordAndBalancesNestedDictionaries() {
        val bytes = PdfBytes(NESTED_DICTIONARY_DOCUMENT.encodeToByteArray())
        val last = checkNotNull(bytes.lastRange(REPEATED_KEYWORD))
        val dictionary = checkNotNull(bytes.balancedDictionary(FIRST_BYTE_OFFSET))

        assertEquals(LAST_KEYWORD_OFFSET, last.start)
        assertEquals(NESTED_DICTIONARY, dictionary.first)
        assertEquals(NESTED_DICTIONARY.length, dictionary.second)
    }

    private companion object {
        const val FIRST_BYTE_OFFSET = 0
        const val OUT_OF_RANGE_OFFSET = Int.MAX_VALUE
        const val LATIN1_PREFIX = "prefix-"
        const val LATIN1_MARKER = "\u00E9"
        const val LATIN1_MARKER_BYTE_COUNT = 1
        const val LATIN1_SUFFIX = "-suffix"
        const val WHITESPACE_PREFIX = " \r\n"
        const val MAXIMUM_INT_TEXT = "2147483647"
        const val OVERFLOWING_INT_TEXT = "2147483648"
        const val TRAILING_TEXT = "x"
        const val TRAILING_TEXT_OFFSET = WHITESPACE_PREFIX.length + MAXIMUM_INT_TEXT.length
        const val REPEATED_KEYWORD = "xref"
        const val NESTED_DICTIONARY = "<< /A << /B 1 >> >>"
        const val NESTED_DICTIONARY_DOCUMENT = "$NESTED_DICTIONARY xref xref"
        const val LAST_KEYWORD_OFFSET = NESTED_DICTIONARY.length + 6
    }
}
