package fi.refineid.android.document

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PdfDictionarySyntaxTest {
    @Test
    fun retainsTokenBoundariesEscapedNamesAndNestedValues() {
        val syntax = PdfDictionarySyntax(COMPLEX_DICTIONARY)
        val size = checkNotNull(syntax.entry(SIZE_NAME))
        val identifier = checkNotNull(syntax.entry(IDENTIFIER_NAME))
        val text = checkNotNull(syntax.entry(TEXT_NAME))
        val nested = checkNotNull(syntax.entry(NESTED_NAME))

        assertEquals(ESCAPED_SIZE_NAME, size.rawName)
        assertEquals(SIZE_VALUE, syntax.value(size))
        assertEquals(IDENTIFIER_VALUE, syntax.value(identifier))
        assertEquals(LITERAL_VALUE_WITH_DICTIONARY_MARKER, syntax.value(text))
        assertEquals(NESTED_VALUE, syntax.value(nested))
    }

    @Test
    fun replacesOrInsertsOnlyOneTopLevelValue() {
        val syntax = PdfDictionarySyntax(COMPLEX_DICTIONARY)

        val replaced = syntax.replacing(IDENTIFIER_NAME, REPLACEMENT_IDENTIFIER_VALUE)
        val replacedSyntax = PdfDictionarySyntax(replaced)
        assertEquals(
            REPLACEMENT_IDENTIFIER_VALUE,
            replacedSyntax.value(checkNotNull(replacedSyntax.entry(IDENTIFIER_NAME))),
        )
        assertEquals(
            LITERAL_VALUE_WITH_DICTIONARY_MARKER,
            replacedSyntax.value(checkNotNull(replacedSyntax.entry(TEXT_NAME))),
        )

        val inserted = replacedSyntax.replacing(NEW_ENTRY_NAME, NEW_ENTRY_VALUE)
        val insertedSyntax = PdfDictionarySyntax(inserted)
        assertEquals(
            NEW_ENTRY_VALUE,
            insertedSyntax.value(checkNotNull(insertedSyntax.entry(NEW_ENTRY_NAME))),
        )
    }

    @Test
    fun parsesOnlyCompleteUnsignedIntegersAndReferences() {
        assertEquals(MAXIMUM_INTEGER_VALUE, PdfValueParser.unsignedInteger(MAXIMUM_INTEGER_TEXT))
        assertNull(PdfValueParser.unsignedInteger(OVERFLOWING_INTEGER_TEXT))
        assertNull(PdfValueParser.unsignedInteger(SIGNED_INTEGER_TEXT))
        assertEquals(
            PdfDocumentIndex.Reference(REFERENCE_OBJECT_NUMBER, REFERENCE_GENERATION),
            PdfValueParser.reference(REFERENCE_WITH_COMMENT),
        )
        assertNull(PdfValueParser.reference(REFERENCE_WITH_TRAILING_TOKEN))
        assertNull(PdfValueParser.reference(REFERENCE_WITH_OVERSIZED_GENERATION))
    }

    @Test
    fun rejectsMalformedDuplicateAndOverNestedValues() {
        val overNested =
            DICTIONARY_WITH_ARRAY_PREFIX +
                ARRAY_OPEN.repeat(OVER_NESTED_ARRAY_DEPTH) +
                ZERO_VALUE +
                ARRAY_CLOSE.repeat(OVER_NESTED_ARRAY_DEPTH) +
                DICTIONARY_CLOSE
        val malformed =
            listOf(
                DUPLICATE_ESCAPED_NAME_DICTIONARY,
                UNTERMINATED_LITERAL_DICTIONARY,
                UNTERMINATED_ARRAY_DICTIONARY,
                INVALID_NAME_ESCAPE_DICTIONARY,
                overNested,
            )

        for (dictionary in malformed) {
            val failure =
                assertThrows(PdfSigningException::class.java) {
                    PdfDictionarySyntax(dictionary)
                }
            assertEquals(PdfSigningFailure.STRUCTURE_UNREADABLE, failure.kind)
        }
    }

    @Test
    fun refusesUnsafeGeneratedNamesAndNonLatin1Values() {
        val syntax = PdfDictionarySyntax(EMPTY_DICTIONARY)

        for (name in INVALID_GENERATED_NAMES) {
            assertThrows(PdfSigningException::class.java) {
                syntax.replacing(name, NEW_ENTRY_VALUE)
            }
        }
        val failure =
            assertThrows(PdfSigningException::class.java) {
                syntax.replacing(NEW_ENTRY_NAME, NON_LATIN1_VALUE)
            }
        assertEquals(PdfSigningFailure.STRUCTURE_UNREADABLE, failure.kind)
        assertTrue(PdfValueParser.isPlainName(NEW_ENTRY_NAME))
    }

    private companion object {
        const val SIZE_NAME = "Size"
        const val IDENTIFIER_NAME = "ID"
        const val TEXT_NAME = "Text"
        const val NESTED_NAME = "Nested"
        const val NEW_ENTRY_NAME = "Info"
        const val ESCAPED_SIZE_NAME = "/Si#7Ae"
        const val SIZE_VALUE = "4"
        const val IDENTIFIER_VALUE = "[<0011> <2233>]"
        const val REPLACEMENT_IDENTIFIER_VALUE = "[<AABB> <CCDD>]"
        const val LITERAL_VALUE_WITH_DICTIONARY_MARKER = "(keeps \\) and >>)"
        const val NESTED_VALUE = "<< /A [1 0 R] >>"
        const val NEW_ENTRY_VALUE = "7 0 R"
        const val COMPLEX_DICTIONARY =
            "<< $ESCAPED_SIZE_NAME $SIZE_VALUE /ID $IDENTIFIER_VALUE " +
                "/Text $LITERAL_VALUE_WITH_DICTIONARY_MARKER /Nested $NESTED_VALUE >>"
        const val EMPTY_DICTIONARY = "<< >>"
        const val DUPLICATE_ESCAPED_NAME_DICTIONARY = "<< /Size 4 /Si#7Ae 5 >>"
        const val UNTERMINATED_LITERAL_DICTIONARY = "<< /Text (unfinished >>"
        const val UNTERMINATED_ARRAY_DICTIONARY = "<< /A [1 2 >>"
        const val INVALID_NAME_ESCAPE_DICTIONARY = "<< /Bad#G0 1 >>"
        const val DICTIONARY_WITH_ARRAY_PREFIX = "<< /A "
        const val DICTIONARY_CLOSE = " >>"
        const val ARRAY_OPEN = "["
        const val ARRAY_CLOSE = "]"
        const val ZERO_VALUE = "0"
        const val OVER_NESTED_ARRAY_DEPTH = 66
        const val MAXIMUM_INTEGER_VALUE = Int.MAX_VALUE
        const val MAXIMUM_INTEGER_TEXT = "2147483647"
        const val OVERFLOWING_INTEGER_TEXT = "2147483648"
        const val SIGNED_INTEGER_TEXT = "-1"
        const val REFERENCE_OBJECT_NUMBER = 17
        const val REFERENCE_GENERATION = 3
        const val REFERENCE_WITH_COMMENT = "17 % object\n 3 R"
        const val REFERENCE_WITH_TRAILING_TOKEN = "17 3 R extra"
        const val REFERENCE_WITH_OVERSIZED_GENERATION = "17 65536 R"
        const val NON_LATIN1_VALUE = "\u20AC"
        val INVALID_GENERATED_NAMES = listOf("", "bad name", "/bad")
    }
}
