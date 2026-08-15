package fi.refineid.android.document

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.MessageDigest

class PdfSignaturePlaceholderTest {
    @Test
    fun digestCoversExactlyTheTwoDeclaredByteRanges() {
        val fixture = fixture()
        val expected = sha384(FIXTURE_PREFIX + FIXTURE_SUFFIX)

        assertArrayEquals(expected, fixture.placeholder.digest())
        assertArrayEquals(
            FIXTURE_PREFIX + FIXTURE_SUFFIX,
            fixture.placeholder.copySignedOctets(),
        )
        assertEquals(expected.size, fixture.placeholder.digest().size)
    }

    @Test
    fun fillUppercasesDerAndMovesNoByte() {
        val fixture = fixture()
        val prepared = fixture.placeholder.copyDocument()

        val filled = fixture.placeholder.filledWith(SYNTHETIC_DER)

        assertEquals(prepared.size, filled.size)
        assertArrayEquals(
            prepared.copyOfRange(FIRST_DOCUMENT_OFFSET, fixture.contentsOpen),
            filled.copyOfRange(FIRST_DOCUMENT_OFFSET, fixture.contentsOpen),
        )
        assertArrayEquals(
            prepared.copyOfRange(fixture.secondSpanStart, prepared.size),
            filled.copyOfRange(fixture.secondSpanStart, filled.size),
        )
        val hole =
            filled.copyOfRange(
                fixture.contentsOpen + HEX_OPEN_DELIMITER_LENGTH,
                fixture.secondSpanStart - HEX_CLOSE_DELIMITER_DISTANCE,
            )
        assertArrayEquals(EXPECTED_FILLED_HOLE, hole)
        assertArrayEquals(fixture.document, fixture.placeholder.copyDocument())
    }

    @Test
    fun oversizedDerIsRefusedWithoutChangingThePreparedDocument() {
        val fixture = fixture()
        val oversized = ByteArray(FIXTURE_CAPACITY + OVERSIZE_BYTE_COUNT)

        val failure =
            assertThrows(PdfSigningException::class.java) {
                fixture.placeholder.filledWith(oversized)
            }

        assertEquals(PdfSigningFailure.SIGNATURE_TOO_LARGE, failure.kind)
        assertEquals(oversized.size, failure.needed)
        assertEquals(FIXTURE_CAPACITY, failure.reserved)
        assertArrayEquals(fixture.document, fixture.placeholder.copyDocument())
    }

    @Test
    fun callerMutationCannotChangeThePreparedByteRanges() {
        val fixture = fixture()
        val retained = fixture.placeholder.copyDocument()

        fixture.document[FIRST_DOCUMENT_OFFSET] = ALTERNATE_DOCUMENT_BYTE

        assertArrayEquals(retained, fixture.placeholder.copyDocument())
        assertArrayEquals(
            retained.copyOfRange(FIRST_DOCUMENT_OFFSET, fixture.contentsOpen) +
                retained.copyOfRange(fixture.secondSpanStart, retained.size),
            fixture.placeholder.copySignedOctets(),
        )
    }

    @Test
    fun malformedHoleBoundsDelimitersAndPaddingAreRefused() {
        val fixture = fixture()
        val wrongPadding = fixture.document.copyOf()
        wrongPadding[fixture.contentsOpen + HEX_OPEN_DELIMITER_LENGTH] =
            NONZERO_HEX_DIGIT
        val wrongDelimiter = fixture.document.copyOf()
        wrongDelimiter[fixture.contentsOpen] = ALTERNATE_DELIMITER

        val malformed =
            listOf(
                PlaceholderInput(
                    document = fixture.document,
                    contentsOpen = NEGATIVE_OFFSET,
                    secondSpanStart = fixture.secondSpanStart,
                    capacity = FIXTURE_CAPACITY,
                ),
                PlaceholderInput(
                    document = fixture.document,
                    contentsOpen = fixture.contentsOpen,
                    secondSpanStart = fixture.secondSpanStart - OFFSET_DELTA,
                    capacity = FIXTURE_CAPACITY,
                ),
                PlaceholderInput(
                    document = wrongPadding,
                    contentsOpen = fixture.contentsOpen,
                    secondSpanStart = fixture.secondSpanStart,
                    capacity = FIXTURE_CAPACITY,
                ),
                PlaceholderInput(
                    document = wrongDelimiter,
                    contentsOpen = fixture.contentsOpen,
                    secondSpanStart = fixture.secondSpanStart,
                    capacity = FIXTURE_CAPACITY,
                ),
                PlaceholderInput(
                    document = fixture.document,
                    contentsOpen = fixture.contentsOpen,
                    secondSpanStart = fixture.secondSpanStart,
                    capacity = NEGATIVE_CAPACITY,
                ),
                PlaceholderInput(
                    document = fixture.document,
                    contentsOpen = fixture.contentsOpen,
                    secondSpanStart = fixture.secondSpanStart,
                    capacity = OVERFLOWING_CAPACITY,
                ),
            )

        for (input in malformed) {
            val failure =
                assertThrows(PdfSigningException::class.java) {
                    PdfSignaturePlaceholder(
                        document = input.document,
                        contentsOpen = input.contentsOpen,
                        secondSpanStart = input.secondSpanStart,
                        capacity = input.capacity,
                    )
                }
            assertEquals(PdfSigningFailure.PLACEHOLDER_MALFORMED, failure.kind)
        }
    }

    private fun fixture(): PlaceholderFixture {
        val hole =
            byteArrayOf(HEX_OPEN_DELIMITER) +
                ByteArray(FIXTURE_CAPACITY * HEX_CHARACTERS_PER_BYTE) {
                    ZERO_HEX_DIGIT
                } +
                byteArrayOf(HEX_CLOSE_DELIMITER)
        val document = FIXTURE_PREFIX + hole + FIXTURE_SUFFIX
        val contentsOpen = FIXTURE_PREFIX.size
        val secondSpanStart = contentsOpen + hole.size
        return PlaceholderFixture(
            document = document,
            contentsOpen = contentsOpen,
            secondSpanStart = secondSpanStart,
            placeholder =
                PdfSignaturePlaceholder(
                    document = document,
                    contentsOpen = contentsOpen,
                    secondSpanStart = secondSpanStart,
                    capacity = FIXTURE_CAPACITY,
                ),
        )
    }

    private fun sha384(bytes: ByteArray): ByteArray = MessageDigest.getInstance(SHA384_DIGEST_ALGORITHM).digest(bytes)

    private data class PlaceholderFixture(
        val document: ByteArray,
        val contentsOpen: Int,
        val secondSpanStart: Int,
        val placeholder: PdfSignaturePlaceholder,
    )

    private data class PlaceholderInput(
        val document: ByteArray,
        val contentsOpen: Int,
        val secondSpanStart: Int,
        val capacity: Int,
    )

    private companion object {
        const val SHA384_DIGEST_ALGORITHM = "SHA-384"
        const val FIXTURE_CAPACITY = 8
        const val HEX_CHARACTERS_PER_BYTE = 2
        const val HEX_OPEN_DELIMITER_LENGTH = 1
        const val HEX_CLOSE_DELIMITER_DISTANCE = 1
        const val FIRST_DOCUMENT_OFFSET = 0
        const val OVERSIZE_BYTE_COUNT = 1
        const val OFFSET_DELTA = 1
        const val NEGATIVE_OFFSET = -1
        const val NEGATIVE_CAPACITY = -1
        const val OVERFLOWING_CAPACITY = Int.MAX_VALUE
        const val HEX_OPEN_DELIMITER: Byte = 0x3C
        const val HEX_CLOSE_DELIMITER: Byte = 0x3E
        const val ZERO_HEX_DIGIT: Byte = 0x30
        const val NONZERO_HEX_DIGIT: Byte = 0x31
        const val ALTERNATE_DELIMITER: Byte = 0x5B
        const val ALTERNATE_DOCUMENT_BYTE: Byte = 0x21
        val FIXTURE_PREFIX = "%PDF-1.7\n/Contents ".encodeToByteArray()
        val FIXTURE_SUFFIX = "\n%%EOF\n".encodeToByteArray()
        val SYNTHETIC_DER = byteArrayOf(0x30, 0x03, 0x01, 0x01, 0xFF.toByte())
        val EXPECTED_FILLED_HOLE = "30030101FF000000".encodeToByteArray()
    }
}
