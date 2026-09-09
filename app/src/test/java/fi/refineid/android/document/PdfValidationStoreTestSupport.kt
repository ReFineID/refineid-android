package fi.refineid.android.document

internal object PdfValidationStoreTestSupport {
    data class Store(
        val number: Int,
        val body: String,
    )

    fun material(
        certificate: String,
        ocspResponse: String,
        revocationList: String,
    ): PdfValidationMaterial =
        PdfValidationMaterial.copyOf(
            certificates = listOf(certificate.encodeToByteArray()),
            ocspResponses = listOf(ocspResponse.encodeToByteArray()),
            revocationLists = listOf(revocationList.encodeToByteArray()),
        )

    fun emptyMaterial(): PdfValidationMaterial =
        PdfValidationMaterial.copyOf(
            certificates = emptyList(),
            ocspResponses = emptyList(),
            revocationLists = emptyList(),
        )

    fun catalog(
        dss: String? = null,
        additions: String = EMPTY_TEXT,
    ): String {
        val entries = StringBuilder(DEFAULT_CATALOG_ENTRIES)
        dss?.let { value -> entries.append(" /DSS ").append(value) }
        if (additions.isNotEmpty()) {
            entries.append(ENTRY_SEPARATOR).append(additions)
        }
        return "<< $entries >>"
    }

    fun document(
        catalog: String,
        extraObjects: Map<Int, String> = emptyMap(),
        trailerExtra: String = EMPTY_TEXT,
    ): ByteArray =
        PdfTestDocuments
            .classicWithExtraObjects(
                catalog = catalog,
                extraObjects = extraObjects,
                trailerExtra = trailerExtra,
            ).document

    fun stream(value: String): String = "<< /Length ${value.encodeToByteArray().size} >>\nstream\n$value\nendstream"

    fun latestStore(document: ByteArray): Store? {
        val catalog = latestObject(PdfTestDocuments.CATALOG_OBJECT_NUMBER, document) ?: return null
        val number = reference(DSS_NAME, catalog)?.number ?: return null
        val body = latestObject(number, document) ?: return null
        return Store(number = number, body = body)
    }

    fun latestObject(
        number: Int,
        document: ByteArray,
    ): String? {
        val text = String(document, Charsets.ISO_8859_1)
        val header = "$number ${PdfTestDocuments.OBJECT_GENERATION} ${PdfFormat.OBJECT_KEYWORD}\n"
        val start = text.lastIndexOf(header)
        if (start < FIRST_TEXT_OFFSET) {
            return null
        }
        val bodyStart = start + header.length
        val end = text.indexOf("\n${PdfFormat.END_OBJECT_KEYWORD}", bodyStart)
        if (end < bodyStart) {
            return null
        }
        return text.substring(bodyStart, end)
    }

    fun reference(
        name: String,
        dictionary: String,
    ): PdfDocumentIndex.Reference? {
        val syntax = PdfDictionarySyntax(dictionary)
        val entry = syntax.entry(name) ?: return null
        return PdfValueParser.reference(syntax.value(entry))
    }

    fun references(
        name: String,
        dictionary: String,
    ): List<PdfDocumentIndex.Reference> {
        val syntax = PdfDictionarySyntax(dictionary)
        val entry = syntax.entry(name) ?: return emptyList()
        return PdfValueParser.referenceArray(syntax.value(entry)).orEmpty()
    }

    fun occurrences(
        marker: String,
        document: ByteArray,
    ): Int = String(document, Charsets.ISO_8859_1).split(marker).size - OCCURRENCE_COUNT_OFFSET

    const val DSS_NAME = "DSS"
    const val CERTIFICATES_NAME = "Certs"
    const val OCSP_RESPONSES_NAME = "OCSPs"
    const val REVOCATION_LISTS_NAME = "CRLs"
    const val VRI_NAME = "VRI"

    private const val DEFAULT_CATALOG_ENTRIES = "/Type /Catalog /Pages 2 0 R"
    private const val ENTRY_SEPARATOR = " "
    private const val EMPTY_TEXT = ""
    private const val FIRST_TEXT_OFFSET = 0
    private const val OCCURRENCE_COUNT_OFFSET = 1
}
