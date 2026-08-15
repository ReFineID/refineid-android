package fi.refineid.android.document

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.zip.Deflater

class PdfFlateDecoderTest {
    @Test
    fun decodesWrappedBareAndEmptyDeflateStreams() {
        listOf(false, true).forEach { nowrap ->
            val compressed = deflate(SYNTHETIC_PAYLOAD, nowrap)
            assertArrayEquals(
                SYNTHETIC_PAYLOAD,
                PdfFlateDecoder.decode(compressed, SYNTHETIC_PAYLOAD.size),
            )
        }
        val compressedEmpty = deflate(byteArrayOf(), nowrap = false)
        assertArrayEquals(byteArrayOf(), PdfFlateDecoder.decode(compressedEmpty, EMPTY_OUTPUT_LIMIT))
    }

    @Test
    fun rejectsExpansionPastTheBoundAndTrailingCompressedBytes() {
        val compressed = deflate(SYNTHETIC_PAYLOAD, nowrap = false)

        assertNull(
            PdfFlateDecoder.decode(
                compressed,
                SYNTHETIC_PAYLOAD.size - MISSING_OUTPUT_BYTE_COUNT,
            ),
        )
        assertNull(
            PdfFlateDecoder.decode(
                compressed + TRAILING_COMPRESSED_BYTE,
                SYNTHETIC_PAYLOAD.size,
            ),
        )
    }

    private fun deflate(
        input: ByteArray,
        nowrap: Boolean,
    ): ByteArray {
        val deflater = Deflater(Deflater.DEFAULT_COMPRESSION, nowrap)
        return try {
            deflater.setInput(input)
            deflater.finish()
            val output = ByteArrayOutputStream()
            val chunk = ByteArray(DEFLATE_CHUNK_LENGTH_BYTES)
            while (!deflater.finished()) {
                val produced = deflater.deflate(chunk)
                check(produced > NO_BYTES_PRODUCED)
                output.write(chunk, FIRST_BYTE_OFFSET, produced)
            }
            output.toByteArray()
        } finally {
            deflater.end()
        }
    }

    private companion object {
        const val SYNTHETIC_PAYLOAD_PART = "synthetic-xref-row"
        const val SYNTHETIC_PAYLOAD_REPETITIONS = 64
        const val MISSING_OUTPUT_BYTE_COUNT = 1
        const val EMPTY_OUTPUT_LIMIT = 0
        const val DEFLATE_CHUNK_LENGTH_BYTES = 1_024
        const val NO_BYTES_PRODUCED = 0
        const val FIRST_BYTE_OFFSET = 0
        const val TRAILING_COMPRESSED_BYTE: Byte = 0x31
        val SYNTHETIC_PAYLOAD =
            SYNTHETIC_PAYLOAD_PART
                .repeat(SYNTHETIC_PAYLOAD_REPETITIONS)
                .encodeToByteArray()
    }
}
