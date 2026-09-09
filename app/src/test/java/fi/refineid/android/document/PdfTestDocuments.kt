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
    ): Classic =
        classic(
            objects =
                listOf(
                    ObjectDefinition(CATALOG_OBJECT_NUMBER, catalog),
                    ObjectDefinition(PAGE_TREE_OBJECT_NUMBER, DEFAULT_PAGE_TREE),
                    ObjectDefinition(PAGE_OBJECT_NUMBER, DEFAULT_PAGE),
                ),
            lineEnding = lineEnding,
            trailerExtra = trailerExtra,
        )

    fun classicWithIndirectFormAndAnnotations(): Classic =
        classic(
            objects =
                listOf(
                    ObjectDefinition(CATALOG_OBJECT_NUMBER, INDIRECT_FORM_CATALOG),
                    ObjectDefinition(PAGE_TREE_OBJECT_NUMBER, DEFAULT_PAGE_TREE),
                    ObjectDefinition(PAGE_OBJECT_NUMBER, INDIRECT_ANNOTATIONS_PAGE),
                    ObjectDefinition(ACRO_FORM_OBJECT_NUMBER, INDIRECT_FIELDS_FORM),
                    ObjectDefinition(FIELDS_ARRAY_OBJECT_NUMBER, EXISTING_FIELD_ARRAY),
                    ObjectDefinition(ANNOTATIONS_ARRAY_OBJECT_NUMBER, EXISTING_FIELD_ARRAY),
                    ObjectDefinition(EXISTING_FIELD_OBJECT_NUMBER, EXISTING_FIELD),
                ),
        )

    fun classicWithExtraObjects(
        catalog: String,
        extraObjects: Map<Int, String>,
        trailerExtra: String = EMPTY_TEXT,
    ): Classic {
        require(extraObjects.keys.none(REQUIRED_OBJECT_NUMBERS::contains))
        return classic(
            objects =
                listOf(
                    ObjectDefinition(CATALOG_OBJECT_NUMBER, catalog),
                    ObjectDefinition(PAGE_TREE_OBJECT_NUMBER, DEFAULT_PAGE_TREE),
                    ObjectDefinition(PAGE_OBJECT_NUMBER, DEFAULT_PAGE),
                ) + extraObjects.map { (number, body) -> ObjectDefinition(number, body) },
            trailerExtra = trailerExtra,
        )
    }

    private fun classic(
        objects: List<ObjectDefinition>,
        lineEnding: String = LINE_FEED,
        trailerExtra: String = EMPTY_TEXT,
    ): Classic {
        var text = PDF_HEADER + lineEnding
        val offsets = mutableMapOf<Int, Int>()
        for (definition in objects.sortedBy(ObjectDefinition::number)) {
            check(offsets.put(definition.number, latin1(text).size) == null)
            text += "${definition.number} $OBJECT_GENERATION ${PdfFormat.OBJECT_KEYWORD}$lineEnding"
            text += definition.body + lineEnding
            text += PdfFormat.END_OBJECT_KEYWORD + lineEnding
        }
        val objectCount =
            Math.addExact(
                checkNotNull(objects.maxOfOrNull(ObjectDefinition::number)),
                OBJECT_COUNT_OFFSET,
            )
        val xrefOffset = latin1(text).size
        text += PdfFormat.XREF_KEYWORD + lineEnding
        text += "$FIRST_OBJECT_NUMBER $objectCount$lineEnding"
        text += FREE_XREF_ENTRY + lineEnding
        for (number in FIRST_LIVE_OBJECT_NUMBER until objectCount) {
            val offset = offsets[number]
            text +=
                if (offset == null) {
                    FREE_XREF_ENTRY + lineEnding
                } else {
                    String.format(
                        Locale.ROOT,
                        IN_USE_XREF_ENTRY_FORMAT + lineEnding,
                        offset,
                    )
                }
        }
        text += PdfFormat.TRAILER_KEYWORD + lineEnding
        text +=
            "<< ${PdfFormat.SIZE_KEY} $objectCount " +
            "${PdfFormat.ROOT_KEY} $CATALOG_OBJECT_NUMBER $OBJECT_GENERATION R" +
            trailerExtra + " >>" + lineEnding
        text += PdfFormat.START_XREF_KEYWORD + lineEnding
        text += xrefOffset.toString() + lineEnding
        text += PdfFormat.END_OF_FILE_MARKER + lineEnding
        return Classic(document = latin1(text), xrefOffset = xrefOffset)
    }

    private data class ObjectDefinition(
        val number: Int,
        val body: String,
    )

    fun latin1(text: String): ByteArray = text.toByteArray(Charsets.ISO_8859_1)

    const val CATALOG_OBJECT_NUMBER = 1
    const val PAGE_TREE_OBJECT_NUMBER = 2
    const val PAGE_OBJECT_NUMBER = 3
    const val ACRO_FORM_OBJECT_NUMBER = 4
    const val FIELDS_ARRAY_OBJECT_NUMBER = 5
    const val ANNOTATIONS_ARRAY_OBJECT_NUMBER = 6
    const val EXISTING_FIELD_OBJECT_NUMBER = 7
    const val OBJECT_GENERATION = 0
    const val DEFAULT_CATALOG = "<< /Type /Catalog /Pages 2 0 R >>"
    const val DEFAULT_PAGE_TREE = "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
    const val DEFAULT_PAGE =
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>"
    const val INDIRECT_FORM_CATALOG =
        "<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>"
    const val INDIRECT_ANNOTATIONS_PAGE =
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] " +
            "/Resources << >> /Annots 6 0 R >>"
    const val INDIRECT_FIELDS_FORM = "<< /Fields 5 0 R /SigFlags 4 >>"
    const val EXISTING_FIELD_ARRAY = "[7 0 R]"
    const val EXISTING_FIELD = "<< /FT /Sig /T (Existing) >>"

    private const val PDF_HEADER = "%PDF-1.7"
    private const val LINE_FEED = "\n"
    private const val EMPTY_TEXT = ""
    private const val FIRST_OBJECT_NUMBER = 0
    private const val FIRST_LIVE_OBJECT_NUMBER = 1
    private const val OBJECT_COUNT_OFFSET = 1
    private const val FREE_XREF_ENTRY = "0000000000 65535 f "
    private const val IN_USE_XREF_ENTRY_FORMAT = "%010d 00000 n "
    private val REQUIRED_OBJECT_NUMBERS =
        setOf(
            CATALOG_OBJECT_NUMBER,
            PAGE_TREE_OBJECT_NUMBER,
            PAGE_OBJECT_NUMBER,
        )
}
