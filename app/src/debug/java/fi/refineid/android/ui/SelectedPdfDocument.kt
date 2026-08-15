package fi.refineid.android.ui

import android.content.ContentResolver
import android.net.Uri
import fi.refineid.android.document.PdfFormat
import java.io.IOException
import java.io.InputStream

/** Debug-harness input with a bounded read and explicit in-memory lifetime. */
internal class SelectedPdfDocument private constructor(
    val source: Uri,
    private val ownedBytes: ByteArray,
) : AutoCloseable {
    private var isClosed = false

    val length: Int
        get() = ownedBytes.size

    fun <T> useBytes(operation: (ByteArray) -> T): T {
        check(!isClosed) {
            "selected PDF is closed"
        }
        return operation(ownedBytes)
    }

    override fun close() {
        if (!isClosed) {
            ownedBytes.fill(ZERO_BYTE)
            isClosed = true
        }
    }

    override fun toString(): String = "SelectedPdfDocument(length=" + length + ", closed=" + isClosed + ")"

    companion object {
        fun read(
            contentResolver: ContentResolver,
            source: Uri,
        ): SelectedPdfDocument =
            contentResolver.openInputStream(source)?.use { input ->
                read(
                    source = source,
                    input = input,
                    maximumBytes = MAXIMUM_PDF_INPUT_BYTES,
                )
            } ?: throw IOException("selected PDF cannot be opened")

        internal fun read(
            source: Uri,
            input: InputStream,
            maximumBytes: Int,
        ): SelectedPdfDocument {
            require(maximumBytes in PdfFormat.FILE_PREFIX.length until Int.MAX_VALUE) {
                "PDF input limit is invalid"
            }
            val readLimit = Math.addExact(maximumBytes, INPUT_LIMIT_SENTINEL_BYTE_COUNT)
            val bytes = input.readNBytes(readLimit)
            if (bytes.size > maximumBytes || !hasPdfPrefix(bytes)) {
                bytes.fill(ZERO_BYTE)
                throw IOException("selected input is not an accepted PDF")
            }
            return SelectedPdfDocument(source = source, ownedBytes = bytes)
        }

        private fun hasPdfPrefix(bytes: ByteArray): Boolean {
            val prefix = PdfFormat.FILE_PREFIX.encodeToByteArray()
            return bytes.size >= prefix.size && prefix.indices.all { index -> bytes[index] == prefix[index] }
        }

        private const val MEBIBYTE_BYTES = 1_024 * 1_024
        private const val MAXIMUM_PDF_INPUT_MEBIBYTES = 64
        private const val MAXIMUM_PDF_INPUT_BYTES =
            MAXIMUM_PDF_INPUT_MEBIBYTES * MEBIBYTE_BYTES
        private const val INPUT_LIMIT_SENTINEL_BYTE_COUNT = 1
        private const val ZERO_BYTE: Byte = 0
    }
}
