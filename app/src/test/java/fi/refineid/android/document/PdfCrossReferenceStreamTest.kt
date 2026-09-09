package fi.refineid.android.document

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.zip.Deflater

class PdfCrossReferenceStreamTest {
    @Test
    fun signsCompressedObjectsAndContinuesWithACrossReferenceStream() {
        val original = streamPdf()
        val originalIndex = PdfDocumentIndex.parse(original)

        assertTrue(originalIndex.newestSectionIsStream)
        assertEquals(CATALOG_BODY, originalIndex.body(CATALOG_OBJECT_NUMBER, original))
        assertEquals(PAGE_TREE_BODY, originalIndex.body(PAGE_TREE_OBJECT_NUMBER, original))
        assertEquals(PAGE_BODY, originalIndex.body(PAGE_OBJECT_NUMBER, original))

        val placeholder =
            PdfIncrementalSigner.prepare(
                document = original,
                revision = PdfSignatureRevision.Signature(SYNTHETIC_CLAIM),
            )
        val signed = placeholder.filledWith(SYNTHETIC_DER)
        val signedIndex = PdfDocumentIndex.parse(signed)
        val update = latin1(signed.copyOfRange(original.size, signed.size))

        assertArrayEquals(original, signed.copyOfRange(FIRST_BYTE_OFFSET, original.size))
        assertTrue(signedIndex.newestSectionIsStream)
        assertTrue(checkNotNull(signedIndex.body(CATALOG_OBJECT_NUMBER, signed)).contains(ACRO_FORM_ENTRY))
        assertTrue(update.contains("${PdfFormat.TYPE_KEY} /${PdfFormat.XREF_STREAM_TYPE_NAME}"))
        assertTrue(update.contains("${PdfFormat.PREVIOUS_XREF_KEY} ${originalIndex.previousStartXref}"))
        assertFalse(update.contains("\n${PdfFormat.TRAILER_KEYWORD}\n"))
    }

    @Test
    fun decodesFlateBehindEveryPngRowFilter() {
        PNG_FILTERS.forEach { filter ->
            val document = streamPdf(encoded = true, pngFilter = filter)
            val index = PdfDocumentIndex.parse(document)

            assertEquals(
                "synthetic PNG filter $filter",
                CATALOG_BODY,
                index.body(CATALOG_OBJECT_NUMBER, document),
            )
            PdfIncrementalSigner.prepare(
                document = document,
                revision = PdfSignatureRevision.DocumentTimestamp,
            )
        }
    }

    @Test
    fun decodesSingletonFilterAndParameterArrays() {
        val document =
            streamPdf(
                encoded = true,
                filterAsArray = true,
                decodeParametersAsArray = true,
            )
        val index = PdfDocumentIndex.parse(document)

        assertEquals(CATALOG_BODY, index.body(CATALOG_OBJECT_NUMBER, document))
    }

    @Test
    fun hybridStreamRecordsOverrideTheirClassicFallback() {
        val document = hybridPdf()
        val index = PdfDocumentIndex.parse(document)

        assertFalse(index.newestSectionIsStream)
        assertEquals(CATALOG_BODY, index.body(CATALOG_OBJECT_NUMBER, document))

        val updated =
            PdfIncrementalSigner
                .prepare(
                    document = document,
                    revision = PdfSignatureRevision.DocumentTimestamp,
                ).copyDocument()
        val update = latin1(updated.copyOfRange(document.size, updated.size))
        assertTrue(update.contains("\n${PdfFormat.TRAILER_KEYWORD}\n"))
        assertFalse(update.contains("${PdfFormat.TYPE_KEY} /${PdfFormat.XREF_STREAM_TYPE_NAME}"))
    }

    @Test
    fun validationStorePreservesTheStreamShape() {
        val original = streamPdf()
        val material =
            PdfValidationMaterial.copyOf(
                certificates = listOf(SYNTHETIC_CERTIFICATE),
                ocspResponses = emptyList(),
                revocationLists = emptyList(),
            )
        val updated = material.use { owned -> PdfValidationStore.append(original, owned) }
        val index = PdfDocumentIndex.parse(updated)
        val catalog = checkNotNull(index.body(CATALOG_OBJECT_NUMBER, updated))

        assertArrayEquals(original, updated.copyOfRange(FIRST_BYTE_OFFSET, original.size))
        assertTrue(index.newestSectionIsStream)
        assertTrue(catalog.contains(DOCUMENT_SECURITY_STORE_ENTRY))
    }

    @Test
    fun refusesUnsupportedStreamEncodingsAndMalformedWidths() {
        assertIndexFailure(
            expected = PdfSigningFailure.STREAM_ENCODING_UNSUPPORTED,
            document = streamPdf(filterName = UNSUPPORTED_FILTER_NAME),
        )
        assertIndexFailure(
            expected = PdfSigningFailure.STREAM_ENCODING_UNSUPPORTED,
            document =
                streamPdf(
                    encoded = true,
                    predictor = UNSUPPORTED_TIFF_PREDICTOR,
                ),
        )
        assertIndexFailure(
            expected = PdfSigningFailure.STREAM_ENCODING_UNSUPPORTED,
            document =
                streamPdf(
                    encoded = true,
                    predictor = UNSUPPORTED_HIGH_PREDICTOR,
                ),
        )
        assertIndexFailure(
            expected = PdfSigningFailure.STRUCTURE_UNREADABLE,
            document = streamPdf(widths = MALFORMED_FIELD_WIDTHS),
        )
    }

    @Test
    fun qpdfGeneratedObjectStreamSurvivesSigningWhenAvailable() {
        val qpdf = executable(QPDF_EXECUTABLE_NAME)
        assumeTrue("qpdf is not installed", qpdf != null)
        val directory = Files.createTempDirectory(TEMPORARY_DIRECTORY_PREFIX)
        try {
            val classic = directory.resolve(CLASSIC_PDF_FILE_NAME)
            val modern = directory.resolve(MODERN_PDF_FILE_NAME)
            val signed = directory.resolve(SIGNED_PDF_FILE_NAME)
            Files.write(classic, PdfTestDocuments.minimalClassic().document)
            run(
                executable = checkNotNull(qpdf),
                arguments =
                    listOf(
                        QPDF_OBJECT_STREAMS_ARGUMENT,
                        QPDF_COMPRESS_STREAMS_ARGUMENT,
                        classic.toString(),
                        modern.toString(),
                    ),
            )
            val modernBytes = Files.readAllBytes(modern)
            assertTrue(PdfDocumentIndex.parse(modernBytes).newestSectionIsStream)
            val signedBytes =
                PdfIncrementalSigner
                    .prepare(
                        document = modernBytes,
                        revision = PdfSignatureRevision.Signature(SYNTHETIC_CLAIM),
                    ).filledWith(SYNTHETIC_DER)
            Files.write(signed, signedBytes)
            run(
                executable = checkNotNull(qpdf),
                arguments = listOf(QPDF_CHECK_ARGUMENT, signed.toString()),
            )
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private fun streamPdf(
        encoded: Boolean = false,
        pngFilter: Int = PdfFormat.STREAM_PNG_FILTER_UP,
        predictor: Int = PdfFormat.STREAM_PNG_PREDICTOR_FLOOR + pngFilter,
        filterName: String? = null,
        widths: String = SUPPORTED_FIELD_WIDTHS,
        filterAsArray: Boolean = false,
        decodeParametersAsArray: Boolean = false,
    ): ByteArray {
        val prefix =
            streamObjectsPrefix(
                encoded = encoded,
                pngFilter = pngFilter,
                predictor = predictor,
                filterName = filterName,
                widths = widths,
                filterAsArray = filterAsArray,
                decodeParametersAsArray = decodeParametersAsArray,
            )
        val output = ByteArrayOutputStream()
        output.write(prefix.bytes)
        output.writeLatin1(
            "${PdfFormat.START_XREF_KEYWORD}\n${prefix.xrefOffset}\n" +
                "${PdfFormat.END_OF_FILE_MARKER}\n",
        )
        return output.toByteArray()
    }

    private fun hybridPdf(): ByteArray {
        val prefix =
            streamObjectsPrefix(
                encoded = false,
                pngFilter = PdfFormat.STREAM_PNG_FILTER_UP,
                predictor = PdfFormat.STREAM_PNG_PREDICTOR_FLOOR + PdfFormat.STREAM_PNG_FILTER_UP,
                filterName = null,
                widths = SUPPORTED_FIELD_WIDTHS,
                filterAsArray = false,
                decodeParametersAsArray = false,
            )
        val output = ByteArrayOutputStream()
        output.write(prefix.bytes)
        val tableOffset = output.size()
        output.writeLatin1(
            "${PdfFormat.XREF_KEYWORD}\n" +
                "$FREE_SUBSECTION_FIRST_OBJECT $FREE_SUBSECTION_ENTRY_COUNT\n" +
                xrefEntry(FREE_XREF_OFFSET, FREE_XREF_GENERATION, PdfFormat.XREF_FREE_FLAG) +
                xrefEntry(FREE_XREF_OFFSET, NORMAL_OBJECT_GENERATION, PdfFormat.XREF_FREE_FLAG) +
                "$OBJECT_STREAM_NUMBER $DIRECT_SUBSECTION_ENTRY_COUNT\n" +
                xrefEntry(prefix.objectStreamOffset, NORMAL_OBJECT_GENERATION, PdfFormat.XREF_IN_USE_FLAG) +
                xrefEntry(prefix.xrefOffset, NORMAL_OBJECT_GENERATION, PdfFormat.XREF_IN_USE_FLAG) +
                "${PdfFormat.TRAILER_KEYWORD}\n" +
                "<< ${PdfFormat.SIZE_KEY} $FIXTURE_OBJECT_COUNT " +
                "${PdfFormat.ROOT_KEY} $CATALOG_OBJECT_NUMBER $NORMAL_OBJECT_GENERATION R " +
                "${PdfFormat.XREF_STREAM_KEY} ${prefix.xrefOffset} >>\n" +
                "${PdfFormat.START_XREF_KEYWORD}\n$tableOffset\n" +
                "${PdfFormat.END_OF_FILE_MARKER}\n",
        )
        return output.toByteArray()
    }

    private fun streamObjectsPrefix(
        encoded: Boolean,
        pngFilter: Int,
        predictor: Int,
        filterName: String?,
        widths: String,
        filterAsArray: Boolean,
        decodeParametersAsArray: Boolean,
    ): StreamPrefix {
        val output = ByteArrayOutputStream()
        output.writeLatin1("${PdfFormat.FILE_PREFIX}$PDF_VERSION\n")
        val objectStreamOffset = output.size()
        output.write(objectStream())
        val xrefOffset = output.size()
        var rows = entryRows(objectStreamOffset, xrefOffset)
        val effectiveFilter = filterName ?: PdfFormat.FLATE_DECODE_FILTER_NAME.takeIf { encoded }
        val parameters =
            if (encoded) {
                rows = deflate(predicted(rows, XREF_ROW_LENGTH_BYTES, pngFilter))
                val filterValue =
                    if (filterAsArray) {
                        "[ /$effectiveFilter ]"
                    } else {
                        "/$effectiveFilter"
                    }
                val parameterDictionary =
                    "<< ${PdfFormat.STREAM_PREDICTOR_KEY} $predictor " +
                        "${PdfFormat.STREAM_COLUMNS_KEY} $XREF_ROW_LENGTH_BYTES >>"
                val parameterValue =
                    if (decodeParametersAsArray) {
                        "[ $parameterDictionary ]"
                    } else {
                        parameterDictionary
                    }
                " ${PdfFormat.STREAM_FILTER_KEY} $filterValue" +
                    " ${PdfFormat.STREAM_DECODE_PARAMETERS_KEY} $parameterValue"
            } else if (effectiveFilter != null) {
                " ${PdfFormat.STREAM_FILTER_KEY} /$effectiveFilter"
            } else {
                ""
            }
        output.writeLatin1(
            "$XREF_STREAM_OBJECT_NUMBER $NORMAL_OBJECT_GENERATION ${PdfFormat.OBJECT_KEYWORD}\n" +
                "<< ${PdfFormat.TYPE_KEY} /${PdfFormat.XREF_STREAM_TYPE_NAME} " +
                "${PdfFormat.SIZE_KEY} $FIXTURE_OBJECT_COUNT " +
                "${PdfFormat.ROOT_KEY} $CATALOG_OBJECT_NUMBER $NORMAL_OBJECT_GENERATION R " +
                "${PdfFormat.XREF_STREAM_WIDTHS_KEY} $widths$parameters " +
                "${PdfFormat.STREAM_LENGTH_KEY} ${rows.size} >>\n" +
                "${PdfFormat.STREAM_KEYWORD}\n",
        )
        output.write(rows)
        output.writeLatin1(
            "\n${PdfFormat.END_STREAM_KEYWORD}\n${PdfFormat.END_OBJECT_KEYWORD}\n",
        )
        return StreamPrefix(
            bytes = output.toByteArray(),
            objectStreamOffset = objectStreamOffset,
            xrefOffset = xrefOffset,
        )
    }

    private fun objectStream(): ByteArray {
        val header = StringBuilder()
        val bodies = StringBuilder()
        COMPRESSED_BODIES.forEachIndexed { index, body ->
            header
                .append(index + FIRST_COMPRESSED_OBJECT_NUMBER)
                .append(' ')
                .append(latin1(bodies.toString()).size)
                .append(' ')
            bodies.append(body).append('\n')
        }
        val payload = header.toString() + bodies
        val output = ByteArrayOutputStream()
        output.writeLatin1(
            "$OBJECT_STREAM_NUMBER $NORMAL_OBJECT_GENERATION ${PdfFormat.OBJECT_KEYWORD}\n" +
                "<< ${PdfFormat.TYPE_KEY} /${PdfFormat.OBJECT_STREAM_TYPE_NAME} " +
                "${PdfFormat.OBJECT_STREAM_COUNT_KEY} ${COMPRESSED_BODIES.size} " +
                "${PdfFormat.OBJECT_STREAM_FIRST_KEY} ${latin1(header.toString()).size} " +
                "${PdfFormat.STREAM_LENGTH_KEY} ${latin1(payload).size} >>\n" +
                "${PdfFormat.STREAM_KEYWORD}\n$payload" +
                "${PdfFormat.END_STREAM_KEYWORD}\n${PdfFormat.END_OBJECT_KEYWORD}\n",
        )
        return output.toByteArray()
    }

    private fun entryRows(
        objectStreamOffset: Int,
        xrefOffset: Int,
    ): ByteArray {
        val output = ByteArrayOutputStream()
        writeXrefRow(output, PdfFormat.XREF_STREAM_FREE_ENTRY_TYPE, FREE_XREF_OFFSET, FREE_XREF_GENERATION)
        COMPRESSED_BODIES.indices.forEach { position ->
            writeXrefRow(
                output,
                PdfFormat.XREF_STREAM_COMPRESSED_ENTRY_TYPE,
                OBJECT_STREAM_NUMBER,
                position,
            )
        }
        writeXrefRow(
            output,
            PdfFormat.XREF_STREAM_DIRECT_ENTRY_TYPE,
            objectStreamOffset,
            NORMAL_OBJECT_GENERATION,
        )
        writeXrefRow(
            output,
            PdfFormat.XREF_STREAM_DIRECT_ENTRY_TYPE,
            xrefOffset,
            NORMAL_OBJECT_GENERATION,
        )
        return output.toByteArray()
    }

    private fun writeXrefRow(
        output: ByteArrayOutputStream,
        type: Int,
        first: Int,
        second: Int,
    ) {
        output.write(type)
        writeWide(output, first)
        writeWide(output, second)
    }

    private fun writeWide(
        output: ByteArrayOutputStream,
        value: Int,
    ) {
        repeat(FIXTURE_FIELD_WIDTH_BYTES) { byteIndex ->
            val shift =
                (FIXTURE_FIELD_WIDTH_BYTES - byteIndex - MOST_SIGNIFICANT_BYTE_OFFSET) * Byte.SIZE_BITS
            output.write((value ushr shift) and PdfFormat.UNSIGNED_BYTE_MASK)
        }
    }

    private fun predicted(
        rows: ByteArray,
        columns: Int,
        filter: Int,
    ): ByteArray {
        require(rows.size % columns == COMPLETE_ROW_REMAINDER)
        val output = ByteArrayOutputStream()
        val above = ByteArray(columns)
        var cursor = FIRST_BYTE_OFFSET
        while (cursor < rows.size) {
            output.write(filter)
            val currentRow = rows.copyOfRange(cursor, cursor + columns)
            repeat(columns) { column ->
                val current = currentRow[column].toUByte().toInt()
                val left =
                    if (column == FIRST_COLUMN) {
                        ZERO_PREDICTION
                    } else {
                        currentRow[column - BYTE_OFFSET_STEP].toUByte().toInt()
                    }
                val upper = above[column].toUByte().toInt()
                val upperLeft =
                    if (column == FIRST_COLUMN) {
                        ZERO_PREDICTION
                    } else {
                        above[column - BYTE_OFFSET_STEP].toUByte().toInt()
                    }
                val prediction = predictor(filter, left, upper, upperLeft)
                output.write((current - prediction) and PdfFormat.UNSIGNED_BYTE_MASK)
            }
            currentRow.copyInto(above)
            cursor += columns
        }
        return output.toByteArray()
    }

    private fun predictor(
        filter: Int,
        left: Int,
        above: Int,
        upperLeft: Int,
    ): Int =
        when (filter) {
            PdfFormat.STREAM_PNG_FILTER_NONE -> ZERO_PREDICTION
            PdfFormat.STREAM_PNG_FILTER_SUB -> left
            PdfFormat.STREAM_PNG_FILTER_UP -> above
            PdfFormat.STREAM_PNG_FILTER_AVERAGE -> (left + above) / AVERAGE_DIVISOR
            PdfFormat.STREAM_PNG_FILTER_PAETH -> paeth(left, above, upperLeft)
            else -> error("unsupported synthetic PNG filter")
        }

    private fun paeth(
        left: Int,
        above: Int,
        upperLeft: Int,
    ): Int {
        val estimate = left + above - upperLeft
        val distanceLeft = kotlin.math.abs(estimate - left)
        val distanceAbove = kotlin.math.abs(estimate - above)
        val distanceUpperLeft = kotlin.math.abs(estimate - upperLeft)
        return when {
            distanceLeft <= distanceAbove && distanceLeft <= distanceUpperLeft -> left
            distanceAbove <= distanceUpperLeft -> above
            else -> upperLeft
        }
    }

    private fun deflate(input: ByteArray): ByteArray {
        val deflater = Deflater()
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

    private fun assertIndexFailure(
        expected: PdfSigningFailure,
        document: ByteArray,
    ) {
        val exception =
            assertThrows(PdfSigningException::class.java) {
                PdfDocumentIndex.parse(document)
            }
        assertEquals(expected, exception.kind)
    }

    private fun xrefEntry(
        offset: Int,
        generation: Int,
        flag: String,
    ): String = String.format(Locale.ROOT, "%010d %05d %s \n", offset, generation, flag)

    private fun ByteArrayOutputStream.writeLatin1(text: String) {
        write(latin1(text))
    }

    private fun latin1(text: String): ByteArray = text.toByteArray(Charsets.ISO_8859_1)

    private fun latin1(bytes: ByteArray): String = String(bytes, Charsets.ISO_8859_1)

    private fun executable(name: String): Path? =
        System
            .getenv(PATH_ENVIRONMENT_VARIABLE)
            ?.split(File.pathSeparator)
            ?.asSequence()
            ?.map { directory -> Path.of(directory, name) }
            ?.firstOrNull(Files::isExecutable)

    private fun run(
        executable: Path,
        arguments: List<String>,
    ) {
        val process =
            ProcessBuilder(listOf(executable.toString()) + arguments)
                .redirectErrorStream(true)
                .start()
        val completed = process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        if (!completed) {
            process.destroyForcibly()
        }
        val output = process.inputStream.bufferedReader().use { reader -> reader.readText() }
        assertTrue(output, completed)
        assertEquals(output, SUCCESSFUL_PROCESS_EXIT_CODE, process.exitValue())
    }

    private data class StreamPrefix(
        val bytes: ByteArray,
        val objectStreamOffset: Int,
        val xrefOffset: Int,
    )

    private companion object {
        const val PDF_VERSION = "1.7"
        const val CATALOG_OBJECT_NUMBER = 1
        const val PAGE_TREE_OBJECT_NUMBER = 2
        const val PAGE_OBJECT_NUMBER = 3
        const val OBJECT_STREAM_NUMBER = 4
        const val XREF_STREAM_OBJECT_NUMBER = 5
        const val FIXTURE_OBJECT_COUNT = 6
        const val FIRST_COMPRESSED_OBJECT_NUMBER = CATALOG_OBJECT_NUMBER
        const val NORMAL_OBJECT_GENERATION = 0
        const val FREE_XREF_GENERATION = 65_535
        const val FREE_XREF_OFFSET = 0
        const val FIXTURE_FIELD_WIDTH_BYTES = 2
        const val XREF_ROW_LENGTH_BYTES =
            PdfFormat.XREF_STREAM_TYPE_WIDTH_BYTES +
                FIXTURE_FIELD_WIDTH_BYTES +
                FIXTURE_FIELD_WIDTH_BYTES
        const val SUPPORTED_FIELD_WIDTHS = "[1 2 2]"
        const val MALFORMED_FIELD_WIDTHS = "[1 9 2]"
        const val UNSUPPORTED_FILTER_NAME = "ASCIIHexDecode"
        const val UNSUPPORTED_TIFF_PREDICTOR = 2
        const val UNSUPPORTED_HIGH_PREDICTOR = PdfFormat.STREAM_PNG_PREDICTOR_CEILING + 1
        const val PAGE_WIDTH_POINTS = 612
        const val PAGE_HEIGHT_POINTS = 792
        const val ACRO_FORM_ENTRY = "/AcroForm"
        const val DOCUMENT_SECURITY_STORE_ENTRY = "/DSS"
        const val FIRST_BYTE_OFFSET = 0
        const val BYTE_OFFSET_STEP = 1
        const val FIRST_COLUMN = 0
        const val ZERO_PREDICTION = 0
        const val AVERAGE_DIVISOR = 2
        const val COMPLETE_ROW_REMAINDER = 0
        const val MOST_SIGNIFICANT_BYTE_OFFSET = 1
        const val DEFLATE_CHUNK_LENGTH_BYTES = 1_024
        const val NO_BYTES_PRODUCED = 0
        const val FREE_SUBSECTION_FIRST_OBJECT = 0
        const val FREE_SUBSECTION_ENTRY_COUNT = 2
        const val DIRECT_SUBSECTION_ENTRY_COUNT = 2
        const val TEMPORARY_DIRECTORY_PREFIX = "refineid-xref-stream-"
        const val CLASSIC_PDF_FILE_NAME = "classic.pdf"
        const val MODERN_PDF_FILE_NAME = "modern.pdf"
        const val SIGNED_PDF_FILE_NAME = "signed.pdf"
        const val PATH_ENVIRONMENT_VARIABLE = "PATH"
        const val QPDF_EXECUTABLE_NAME = "qpdf"
        const val QPDF_OBJECT_STREAMS_ARGUMENT = "--object-streams=generate"
        const val QPDF_COMPRESS_STREAMS_ARGUMENT = "--stream-data=compress"
        const val QPDF_CHECK_ARGUMENT = "--check"
        const val PROCESS_TIMEOUT_SECONDS = 10L
        const val SUCCESSFUL_PROCESS_EXIT_CODE = 0
        const val DER_SEQUENCE_TAG: Byte = 0x30
        const val DER_SEQUENCE_CONTENT_LENGTH: Byte = 0x03
        const val DER_BOOLEAN_TAG: Byte = 0x01
        const val DER_BOOLEAN_CONTENT_LENGTH: Byte = 0x01
        const val DER_TRUE_VALUE: Byte = -0x01
        const val CATALOG_BODY = "<< /Type /Catalog /Pages 2 0 R >>"
        const val PAGE_TREE_BODY = "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
        const val PAGE_BODY =
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 $PAGE_WIDTH_POINTS $PAGE_HEIGHT_POINTS] >>"
        val COMPRESSED_BODIES = listOf(CATALOG_BODY, PAGE_TREE_BODY, PAGE_BODY)
        val PNG_FILTERS =
            listOf(
                PdfFormat.STREAM_PNG_FILTER_NONE,
                PdfFormat.STREAM_PNG_FILTER_SUB,
                PdfFormat.STREAM_PNG_FILTER_UP,
                PdfFormat.STREAM_PNG_FILTER_AVERAGE,
                PdfFormat.STREAM_PNG_FILTER_PAETH,
            )
        val SYNTHETIC_CLAIM =
            PdfSignatureClaim(
                signedAt = Instant.EPOCH,
                reason = null,
                location = null,
            )
        val SYNTHETIC_CERTIFICATE = "synthetic-certificate".encodeToByteArray()
        val SYNTHETIC_DER =
            byteArrayOf(
                DER_SEQUENCE_TAG,
                DER_SEQUENCE_CONTENT_LENGTH,
                DER_BOOLEAN_TAG,
                DER_BOOLEAN_CONTENT_LENGTH,
                DER_TRUE_VALUE,
            )
    }
}
