package fi.refineid.android.ui

import android.net.Uri
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException

internal class SelectedPdfDocumentTest {
    @Test
    fun acceptsBoundedPdfAndClearsItsOwnedBytes() {
        val sourceBytes = SYNTHETIC_PDF.encodeToByteArray()
        val selected =
            ByteArrayInputStream(sourceBytes).use { input ->
                SelectedPdfDocument.read(
                    source = SYNTHETIC_SOURCE,
                    input = input,
                    maximumBytes = sourceBytes.size,
                )
            }
        var ownedBytes: ByteArray? = null

        selected.useBytes { bytes ->
            ownedBytes = bytes
            assertArrayEquals(sourceBytes, bytes)
        }
        assertFalse(selected.toString().contains(SYNTHETIC_PDF))
        assertFalse(selected.toString().contains(SYNTHETIC_SOURCE.toString()))

        selected.close()

        assertTrue(checkNotNull(ownedBytes).all { byte -> byte == ZERO_BYTE })
        assertThrows(IllegalStateException::class.java) {
            selected.useBytes(ByteArray::size)
        }
    }

    @Test
    fun rejectsNonPdfAndInputBeyondTheExplicitLimit() {
        assertReadFailure(
            bytes = NOT_A_PDF.encodeToByteArray(),
            maximumBytes = ACCEPTED_TEST_INPUT_LIMIT,
        )
        assertReadFailure(
            bytes = SYNTHETIC_PDF.encodeToByteArray(),
            maximumBytes = SYNTHETIC_PDF.length - SINGLE_EXCESS_BYTE_COUNT,
        )
    }

    private fun assertReadFailure(
        bytes: ByteArray,
        maximumBytes: Int,
    ) {
        assertThrows(IOException::class.java) {
            ByteArrayInputStream(bytes).use { input ->
                SelectedPdfDocument.read(
                    source = SYNTHETIC_SOURCE,
                    input = input,
                    maximumBytes = maximumBytes,
                )
            }
        }
    }

    private companion object {
        const val SYNTHETIC_PDF = "%PDF-1.7\n%%EOF\n"
        const val NOT_A_PDF = "not a PDF"
        const val ACCEPTED_TEST_INPUT_LIMIT = 64
        const val SINGLE_EXCESS_BYTE_COUNT = 1
        const val ZERO_BYTE: Byte = 0
        val SYNTHETIC_SOURCE: Uri = Uri.parse("content://synthetic/pdf")
    }
}
