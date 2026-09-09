package fi.refineid.android.document

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class DerCodecTest {
    @Test
    fun writesEverySupportedLengthFormMinimally() {
        val short = DerEncoder.octetString(ByteArray(SHORT_FORM_CONTENT_LENGTH))
        val oneLong = DerEncoder.octetString(ByteArray(ONE_OCTET_LONG_FORM_CONTENT_LENGTH))
        val twoLong = DerEncoder.octetString(ByteArray(TWO_OCTET_LONG_FORM_CONTENT_LENGTH))

        assertArrayEquals(
            SHORT_FORM_HEADER,
            short.copyOfRange(FIRST_BYTE_OFFSET, SHORT_FORM_HEADER.size),
        )
        assertArrayEquals(
            ONE_OCTET_LONG_FORM_HEADER,
            oneLong.copyOfRange(FIRST_BYTE_OFFSET, ONE_OCTET_LONG_FORM_HEADER.size),
        )
        assertArrayEquals(
            TWO_OCTET_LONG_FORM_HEADER,
            twoLong.copyOfRange(FIRST_BYTE_OFFSET, TWO_OCTET_LONG_FORM_HEADER.size),
        )
    }

    @Test
    fun writesCanonicalUnsignedIntegersAndKnownObjectIdentifiers() {
        assertArrayEquals(DER_INTEGER_ZERO, DerEncoder.integer(ZERO_INTEGER_VALUE))
        assertArrayEquals(
            DER_INTEGER_WITH_POSITIVE_PREFIX,
            DerEncoder.unsignedInteger(byteArrayOf(INTEGER_SIGN_BIT_VALUE.toByte())),
        )
        assertArrayEquals(
            DER_DATA_OBJECT_IDENTIFIER,
            DerEncoder.objectIdentifier(DATA_OBJECT_IDENTIFIER),
        )
        assertArrayEquals(
            DER_SHA384_OBJECT_IDENTIFIER,
            DerEncoder.objectIdentifier(SHA384_OBJECT_IDENTIFIER),
        )
    }

    @Test
    fun sortsSetMembersAndRetagsOneCompleteValue() {
        val first = DerEncoder.octetString(byteArrayOf(FIRST_SET_VALUE))
        val second = DerEncoder.octetString(byteArrayOf(SECOND_SET_VALUE))
        val sorted = DerEncoder.setOf(listOf(second, first))

        assertArrayEquals(DER_SORTED_SET, sorted)
        val retagged =
            DerEncoder.retagged(
                encoded = sorted,
                tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
            )
        assertEquals(DerValues.TAG_CONTEXT_0_CONSTRUCTED, retagged[FIRST_BYTE_OFFSET].toUnsignedInt())
        assertArrayEquals(
            sorted.copyOfRange(TAG_BYTE_COUNT, sorted.size),
            retagged.copyOfRange(TAG_BYTE_COUNT, retagged.size),
        )
        assertThrows(IllegalArgumentException::class.java) {
            DerEncoder.retagged(
                encoded = first + second,
                tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
            )
        }
        for (unsupportedTag in UNSUPPORTED_SINGLE_BYTE_TAGS) {
            assertThrows(IllegalArgumentException::class.java) {
                DerEncoder.retagged(
                    encoded = sorted,
                    tag = unsupportedTag,
                )
            }
        }
    }

    @Test
    fun readerRetainsRawRangesAndRejectsNonCanonicalLengths() {
        val child = DerEncoder.octetString(SYNTHETIC_CONTENT)
        val sequence = DerEncoder.sequence(listOf(child))
        val outer = DerReader(sequence)
        val sequenceElement = checkNotNull(outer.next())
        assertTrue(outer.isAtEnd)
        val children = outer.children(sequenceElement)
        val childElement = checkNotNull(children.next())

        assertEquals(DerValues.TAG_OCTET_STRING, childElement.tag)
        assertArrayEquals(child, children.raw(childElement))
        assertArrayEquals(SYNTHETIC_CONTENT, children.content(childElement))
        assertTrue(children.isAtEnd)

        for (malformed in MALFORMED_DER_VALUES) {
            assertNull(DerReader.single(malformed))
        }
    }

    @Test
    fun refusesInvalidObjectIdentifierArcs() {
        for (dotted in INVALID_OBJECT_IDENTIFIERS) {
            assertThrows(IllegalArgumentException::class.java) {
                DerEncoder.objectIdentifier(dotted)
            }
        }
    }

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private companion object {
        const val SHORT_FORM_CONTENT_LENGTH = 127
        const val ONE_OCTET_LONG_FORM_CONTENT_LENGTH = 128
        const val TWO_OCTET_LONG_FORM_CONTENT_LENGTH = 256
        const val FIRST_BYTE_OFFSET = 0
        const val TAG_BYTE_COUNT = 1
        const val ZERO_INTEGER_VALUE = 0
        const val INTEGER_SIGN_BIT_VALUE = 0x80
        const val FIRST_SET_VALUE: Byte = 1
        const val SECOND_SET_VALUE: Byte = 2
        const val DATA_OBJECT_IDENTIFIER = "1.2.840.113549.1.7.1"
        const val SHA384_OBJECT_IDENTIFIER = "2.16.840.1.101.3.4.2.2"

        val SYNTHETIC_CONTENT = "DER content".encodeToByteArray()
        val SHORT_FORM_HEADER = byteArrayOf(DerValues.TAG_OCTET_STRING.toByte(), 0x7F)
        val ONE_OCTET_LONG_FORM_HEADER =
            byteArrayOf(DerValues.TAG_OCTET_STRING.toByte(), 0x81.toByte(), 0x80.toByte())
        val TWO_OCTET_LONG_FORM_HEADER =
            byteArrayOf(DerValues.TAG_OCTET_STRING.toByte(), 0x82.toByte(), 0x01, 0x00)
        val DER_INTEGER_ZERO = byteArrayOf(DerValues.TAG_INTEGER.toByte(), 0x01, 0x00)
        val DER_INTEGER_WITH_POSITIVE_PREFIX =
            byteArrayOf(DerValues.TAG_INTEGER.toByte(), 0x02, 0x00, 0x80.toByte())
        val DER_DATA_OBJECT_IDENTIFIER =
            byteArrayOf(
                DerValues.TAG_OBJECT_IDENTIFIER.toByte(),
                0x09,
                0x2A,
                0x86.toByte(),
                0x48,
                0x86.toByte(),
                0xF7.toByte(),
                0x0D,
                0x01,
                0x07,
                0x01,
            )
        val DER_SHA384_OBJECT_IDENTIFIER =
            byteArrayOf(
                DerValues.TAG_OBJECT_IDENTIFIER.toByte(),
                0x09,
                0x60,
                0x86.toByte(),
                0x48,
                0x01,
                0x65,
                0x03,
                0x04,
                0x02,
                0x02,
            )
        val DER_SORTED_SET =
            byteArrayOf(
                DerValues.TAG_SET.toByte(),
                0x06,
                DerValues.TAG_OCTET_STRING.toByte(),
                0x01,
                FIRST_SET_VALUE,
                DerValues.TAG_OCTET_STRING.toByte(),
                0x01,
                SECOND_SET_VALUE,
            )
        val MALFORMED_DER_VALUES =
            listOf(
                byteArrayOf(DerValues.TAG_SEQUENCE.toByte()),
                byteArrayOf(DerValues.TAG_SEQUENCE.toByte(), 0x80.toByte(), 0x00, 0x00),
                byteArrayOf(DerValues.TAG_OCTET_STRING.toByte(), 0x81.toByte(), 0x01, 0x00),
                byteArrayOf(DerValues.TAG_OCTET_STRING.toByte(), 0x82.toByte(), 0x00, 0x80.toByte()),
                byteArrayOf(DerValues.TAG_OCTET_STRING.toByte(), 0x02, 0x00),
            )
        val INVALID_OBJECT_IDENTIFIERS =
            listOf(
                "1",
                "3.1.1",
                "1.40.1",
                "1..2",
                "1.two.3",
            )
        val UNSUPPORTED_SINGLE_BYTE_TAGS =
            listOf(
                HIGH_TAG_NUMBER_IDENTIFIER,
                TAG_ABOVE_SINGLE_BYTE_RANGE,
            )

        const val HIGH_TAG_NUMBER_IDENTIFIER = 0x1F
        const val TAG_ABOVE_SINGLE_BYTE_RANGE = 0x100
    }
}
