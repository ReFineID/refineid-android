package fi.refineid.android.document

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.Locale

class PdfDocumentIndexTest {
    @Test
    fun parsesClassicObjectsAtByteOffsetsWithCrlfAndLatin1() {
        val document =
            PdfTestDocuments.minimalClassic(
                catalog = LATIN1_CATALOG,
                lineEnding = CARRIAGE_RETURN_LINE_FEED,
            )
        val index = PdfDocumentIndex.parse(document.document)

        assertEquals(document.xrefOffset, index.previousStartXref)
        assertEquals(FIXTURE_OBJECT_COUNT, PdfDocumentIndex.integer(PdfFormat.SIZE_KEY, index.trailer))
        assertEquals(
            PdfDocumentIndex.Reference(
                number = PdfTestDocuments.CATALOG_OBJECT_NUMBER,
                generation = PdfTestDocuments.OBJECT_GENERATION,
            ),
            PdfDocumentIndex.reference(PdfFormat.ROOT_KEY, index.trailer),
        )
        assertEquals(
            LATIN1_CATALOG,
            index.body(PdfTestDocuments.CATALOG_OBJECT_NUMBER, document.document),
        )
        assertEquals(
            PdfTestDocuments.DEFAULT_PAGE,
            index.body(PdfTestDocuments.PAGE_OBJECT_NUMBER, document.document),
        )
    }

    @Test
    fun newestRecordsWinAndFreeRecordsShadowOlderObjects() {
        val original = PdfTestDocuments.minimalClassic()
        val revised = appendRevision(original)
        val index = PdfDocumentIndex.parse(revised)

        assertEquals(UPDATED_CATALOG, index.body(PdfTestDocuments.CATALOG_OBJECT_NUMBER, revised))
        assertEquals(
            PdfTestDocuments.DEFAULT_PAGE_TREE,
            index.body(PdfTestDocuments.PAGE_TREE_OBJECT_NUMBER, revised),
        )
        assertNull(index.body(PdfTestDocuments.PAGE_OBJECT_NUMBER, revised))
    }

    @Test
    fun refusesNonPdfEncryptedStreamCyclicAndMalformedInputs() {
        assertIndexFailure(PdfSigningFailure.NOT_A_PDF, NOT_A_PDF.encodeToByteArray())
        assertIndexFailure(
            PdfSigningFailure.ENCRYPTED,
            PdfTestDocuments
                .minimalClassic(trailerExtra = ENCRYPTED_TRAILER_ENTRY)
                .document,
        )
        assertIndexFailure(
            PdfSigningFailure.CROSS_REFERENCE_STREAM_UNSUPPORTED,
            crossReferenceStreamShape(),
        )
        assertIndexFailure(PdfSigningFailure.STRUCTURE_UNREADABLE, cyclicRevision())
        assertIndexFailure(
            PdfSigningFailure.STRUCTURE_UNREADABLE,
            PdfTestDocuments.minimalClassic(trailerExtra = MALFORMED_PREVIOUS_ENTRY).document,
        )
        assertIndexFailure(PdfSigningFailure.STRUCTURE_UNREADABLE, truncatedHugeSubsection())
        assertIndexFailure(PdfSigningFailure.STRUCTURE_UNREADABLE, malformedGeneration())
        assertIndexFailure(PdfSigningFailure.STRUCTURE_UNREADABLE, duplicateObjectRecord())
    }

    @Test
    fun refusesAReferenceWithoutItsGenerationAndMarker() {
        assertNull(PdfDocumentIndex.reference(PdfFormat.ROOT_KEY, "<< /Root 1 >>"))
        assertNull(PdfDocumentIndex.reference(PdfFormat.ROOT_KEY, "<< /Root 1 0 >>"))
        assertNull(PdfDocumentIndex.reference(PdfFormat.ROOT_KEY, "<< /Root 1 0 Rubbish >>"))
        assertEquals(
            PdfDocumentIndex.Reference(
                number = PdfTestDocuments.CATALOG_OBJECT_NUMBER,
                generation = PdfTestDocuments.OBJECT_GENERATION,
            ),
            PdfDocumentIndex.reference(PdfFormat.ROOT_KEY, "<< /Root 1 0 R >>"),
        )
        assertEquals(
            FIXTURE_OBJECT_COUNT,
            PdfDocumentIndex.integer(
                PdfFormat.SIZE_KEY,
                "<< /SizeExtra 99 /Size $FIXTURE_OBJECT_COUNT >>",
            ),
        )
        PdfDocumentIndex.parse(
            PdfTestDocuments.minimalClassic(trailerExtra = NON_ENCRYPTION_NAME_ENTRY).document,
        )
    }

    private fun appendRevision(original: PdfTestDocuments.Classic): ByteArray {
        var update = LINE_FEED
        val catalogOffset = original.document.size + PdfTestDocuments.latin1(update).size
        update +=
            "${PdfTestDocuments.CATALOG_OBJECT_NUMBER} ${PdfTestDocuments.OBJECT_GENERATION} " +
            "${PdfFormat.OBJECT_KEYWORD}$LINE_FEED$UPDATED_CATALOG$LINE_FEED" +
            "${PdfFormat.END_OBJECT_KEYWORD}$LINE_FEED"
        val xrefOffset = original.document.size + PdfTestDocuments.latin1(update).size
        update += PdfFormat.XREF_KEYWORD + LINE_FEED
        update += "${PdfTestDocuments.CATALOG_OBJECT_NUMBER} $SINGLE_XREF_ENTRY$LINE_FEED"
        update += xrefEntry(catalogOffset, PdfFormat.XREF_IN_USE_FLAG)
        update += "${PdfTestDocuments.PAGE_OBJECT_NUMBER} $SINGLE_XREF_ENTRY$LINE_FEED"
        update += xrefEntry(FREE_ENTRY_OFFSET, PdfFormat.XREF_FREE_FLAG)
        update += PdfFormat.TRAILER_KEYWORD + LINE_FEED
        update +=
            "<< ${PdfFormat.SIZE_KEY} $FIXTURE_OBJECT_COUNT " +
            "${PdfFormat.ROOT_KEY} ${PdfTestDocuments.CATALOG_OBJECT_NUMBER} " +
            "${PdfTestDocuments.OBJECT_GENERATION} R ${PdfFormat.PREVIOUS_XREF_KEY} " +
            "${original.xrefOffset} >>$LINE_FEED"
        update += PdfFormat.START_XREF_KEYWORD + LINE_FEED
        update += "$xrefOffset$LINE_FEED${PdfFormat.END_OF_FILE_MARKER}$LINE_FEED"
        return original.document + PdfTestDocuments.latin1(update)
    }

    private fun cyclicRevision(): ByteArray {
        val original = PdfTestDocuments.minimalClassic()
        val marker = " >>$LINE_FEED${PdfFormat.START_XREF_KEYWORD}"
        val replacement =
            " ${PdfFormat.PREVIOUS_XREF_KEY} ${original.xrefOffset} >>" +
                "$LINE_FEED${PdfFormat.START_XREF_KEYWORD}"
        val text = String(original.document, Charsets.ISO_8859_1).replace(marker, replacement)
        return PdfTestDocuments.latin1(text)
    }

    private fun crossReferenceStreamShape(): ByteArray {
        val prefix = "%PDF-1.7$LINE_FEED"
        val objectOffset = PdfTestDocuments.latin1(prefix).size
        return PdfTestDocuments.latin1(
            prefix +
                "1 0 ${PdfFormat.OBJECT_KEYWORD}$LINE_FEED" +
                "<< /Type /XRef /Size 2 >>$LINE_FEED" +
                "${PdfFormat.END_OBJECT_KEYWORD}$LINE_FEED" +
                "${PdfFormat.START_XREF_KEYWORD}$LINE_FEED$objectOffset$LINE_FEED" +
                "${PdfFormat.END_OF_FILE_MARKER}$LINE_FEED",
        )
    }

    private fun truncatedHugeSubsection(): ByteArray = malformedXref("0 $HUGE_SUBSECTION_COUNT$LINE_FEED")

    private fun malformedGeneration(): ByteArray =
        malformedXref("0 $SINGLE_XREF_ENTRY$LINE_FEED$ZERO_OFFSET invalid f$LINE_FEED")

    private fun duplicateObjectRecord(): ByteArray =
        malformedXref(
            "0 $SINGLE_XREF_ENTRY$LINE_FEED$ZERO_OFFSET $FREE_OBJECT_GENERATION f$LINE_FEED" +
                "0 $SINGLE_XREF_ENTRY$LINE_FEED$ZERO_OFFSET $FREE_OBJECT_GENERATION f$LINE_FEED",
        )

    private fun malformedXref(entries: String): ByteArray {
        val prefix = "%PDF-1.7$LINE_FEED"
        val xrefOffset = PdfTestDocuments.latin1(prefix).size
        return PdfTestDocuments.latin1(
            prefix +
                "${PdfFormat.XREF_KEYWORD}$LINE_FEED$entries" +
                "${PdfFormat.TRAILER_KEYWORD}$LINE_FEED" +
                "<< ${PdfFormat.SIZE_KEY} $SINGLE_XREF_ENTRY " +
                "${PdfFormat.ROOT_KEY} 0 0 R >>$LINE_FEED" +
                "${PdfFormat.START_XREF_KEYWORD}$LINE_FEED$xrefOffset$LINE_FEED" +
                "${PdfFormat.END_OF_FILE_MARKER}$LINE_FEED",
        )
    }

    private fun xrefEntry(
        offset: Int,
        flag: String,
    ): String =
        String.format(
            Locale.ROOT,
            XREF_ENTRY_FORMAT + LINE_FEED,
            offset,
            if (flag == PdfFormat.XREF_FREE_FLAG) FREE_OBJECT_GENERATION else LIVE_OBJECT_GENERATION,
            flag,
        )

    private fun assertIndexFailure(
        expected: PdfSigningFailure,
        document: ByteArray,
    ) {
        val failure =
            assertThrows(PdfSigningException::class.java) {
                PdfDocumentIndex.parse(document)
            }
        assertEquals(expected, failure.kind)
    }

    private companion object {
        const val LINE_FEED = "\n"
        const val CARRIAGE_RETURN_LINE_FEED = "\r\n"
        const val LATIN1_CATALOG = "<< /Type /Catalog /Pages 2 0 R /Note (\u00E9) >>"
        const val UPDATED_CATALOG = "<< /Type /Catalog /Pages 2 0 R /Updated true >>"
        const val ENCRYPTED_TRAILER_ENTRY = " /Encrypt 9 0 R"
        const val NON_ENCRYPTION_NAME_ENTRY = " /EncryptNote 9 0 R"
        const val MALFORMED_PREVIOUS_ENTRY = " /Prev nope"
        const val NOT_A_PDF = "not a document"
        const val FIXTURE_OBJECT_COUNT = 4
        const val SINGLE_XREF_ENTRY = 1
        const val HUGE_SUBSECTION_COUNT = Int.MAX_VALUE
        const val ZERO_OFFSET = 0
        const val FREE_ENTRY_OFFSET = 0
        const val FREE_OBJECT_GENERATION = 1
        const val LIVE_OBJECT_GENERATION = 0
        const val XREF_ENTRY_FORMAT = "%010d %05d %s "
    }
}
