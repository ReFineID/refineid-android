package fi.refineid.android.document

import java.util.Locale

internal object PdfTestDocuments {
    data class Classic(
        val document: ByteArray,
        val xrefOffset: Int,
    )

    fun minimalClassic(
        catalog: String = DEFAULT_CATALOG,
        lineEnding: String = LINE_FEED,
        trailerExtra: String = EMPTY_TEXT,
    ): Classic {
        var text = PDF_HEADER + lineEnding
        val offsets = mutableListOf<Int>()
        val objects =
            listOf(
                CATALOG_OBJECT_NUMBER to catalog,
                PAGE_TREE_OBJECT_NUMBER to DEFAULT_PAGE_TREE,
                PAGE_OBJECT_NUMBER to DEFAULT_PAGE,
            )
        for ((number, body) in objects) {
            offsets.add(latin1(text).size)
            text += "$number $OBJECT_GENERATION ${PdfFormat.OBJECT_KEYWORD}$lineEnding"
            text += body + lineEnding
            text += PdfFormat.END_OBJECT_KEYWORD + lineEnding
        }
        val xrefOffset = latin1(text).size
        text += PdfFormat.XREF_KEYWORD + lineEnding
        text += "$FIRST_OBJECT_NUMBER $FIXTURE_OBJECT_COUNT$lineEnding"
        text += FREE_XREF_ENTRY + lineEnding
        for (offset in offsets) {
            text +=
                String.format(
                    Locale.ROOT,
                    IN_USE_XREF_ENTRY_FORMAT + lineEnding,
                    offset,
                )
        }
        text += PdfFormat.TRAILER_KEYWORD + lineEnding
        text +=
            "<< ${PdfFormat.SIZE_KEY} $FIXTURE_OBJECT_COUNT " +
            "${PdfFormat.ROOT_KEY} $CATALOG_OBJECT_NUMBER $OBJECT_GENERATION R" +
            trailerExtra + " >>" + lineEnding
        text += PdfFormat.START_XREF_KEYWORD + lineEnding
        text += xrefOffset.toString() + lineEnding
        text += PdfFormat.END_OF_FILE_MARKER + lineEnding
        return Classic(document = latin1(text), xrefOffset = xrefOffset)
    }

    fun latin1(text: String): ByteArray = text.toByteArray(Charsets.ISO_8859_1)

    const val CATALOG_OBJECT_NUMBER = 1
    const val PAGE_TREE_OBJECT_NUMBER = 2
    const val PAGE_OBJECT_NUMBER = 3
    const val OBJECT_GENERATION = 0
    const val DEFAULT_CATALOG = "<< /Type /Catalog /Pages 2 0 R >>"
    const val DEFAULT_PAGE_TREE = "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
    const val DEFAULT_PAGE = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"

    private const val PDF_HEADER = "%PDF-1.7"
    private const val LINE_FEED = "\n"
    private const val EMPTY_TEXT = ""
    private const val FIRST_OBJECT_NUMBER = 0
    private const val FIXTURE_OBJECT_COUNT = 4
    private const val FREE_XREF_ENTRY = "0000000000 65535 f "
    private const val IN_USE_XREF_ENTRY_FORMAT = "%010d 00000 n "
}
