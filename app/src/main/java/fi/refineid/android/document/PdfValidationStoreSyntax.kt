// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

internal data class PdfValidationStorePrevious(
    val certificates: List<PdfDocumentIndex.Reference>,
    val ocspResponses: List<PdfDocumentIndex.Reference>,
    val revocationLists: List<PdfDocumentIndex.Reference>,
    val vri: String?,
    val otherEntries: List<String>,
) {
    companion object {
        val EMPTY =
            PdfValidationStorePrevious(
                certificates = emptyList(),
                ocspResponses = emptyList(),
                revocationLists = emptyList(),
                vri = null,
                otherEntries = emptyList(),
            )
    }
}

/** Reads and rewrites only the token-delimited PDF syntax owned by a DSS. */
internal object PdfValidationStoreSyntax {
    fun previousStore(
        catalog: String,
        index: PdfDocumentIndex,
        document: ByteArray,
    ): PdfValidationStorePrevious {
        val catalogSyntax = PdfDictionarySyntax(catalog)
        val storeEntry = catalogSyntax.entry(DSS_NAME) ?: return PdfValidationStorePrevious.EMPTY
        val storeText =
            dictionaryText(
                value = catalogSyntax.value(storeEntry),
                index = index,
                document = document,
            )
        val store = PdfDictionarySyntax(storeText)
        var certificates = emptyList<PdfDocumentIndex.Reference>()
        var ocspResponses = emptyList<PdfDocumentIndex.Reference>()
        var revocationLists = emptyList<PdfDocumentIndex.Reference>()
        var vri: String? = null
        val otherEntries = mutableListOf<String>()
        for (entry in store.entries) {
            val value = store.value(entry)
            when (entry.name) {
                CERTIFICATES_NAME -> {
                    certificates = references(value, index, document)
                }

                OCSP_RESPONSES_NAME -> {
                    ocspResponses = references(value, index, document)
                }

                REVOCATION_LISTS_NAME -> {
                    revocationLists = references(value, index, document)
                }

                TYPE_NAME -> {
                    // The type entry itself needs no value validation.
                }

                VRI_NAME -> {
                    dictionaryText(value, index, document)
                    vri = value
                }

                else -> {
                    otherEntries += "${entry.rawName} $value"
                }
            }
        }
        return PdfValidationStorePrevious(
            certificates = certificates,
            ocspResponses = ocspResponses,
            revocationLists = revocationLists,
            vri = vri,
            otherEntries = otherEntries,
        )
    }

    fun catalogReferencing(
        store: PdfDocumentIndex.Reference,
        catalog: String,
    ): String =
        PdfDictionarySyntax(catalog).replacing(
            name = DSS_NAME,
            value = store.encodedIndirectReference(),
        )

    private fun dictionaryText(
        value: String,
        index: PdfDocumentIndex,
        document: ByteArray,
    ): String {
        try {
            PdfDictionarySyntax(value)
            return value
        } catch (_: PdfSigningException) {
            // The value may instead be one indirect dictionary reference.
        }
        val reference = PdfValueParser.reference(value) ?: throw unreadable()
        val body = index.body(reference, document) ?: throw unreadable()
        try {
            PdfDictionarySyntax(body)
        } catch (_: PdfSigningException) {
            throw unreadable()
        }
        return body
    }

    private fun references(
        value: String,
        index: PdfDocumentIndex,
        document: ByteArray,
    ): List<PdfDocumentIndex.Reference> {
        PdfValueParser.referenceArray(value)?.let { return it }
        val reference = PdfValueParser.reference(value) ?: throw unreadable()
        val body = index.body(reference, document) ?: throw unreadable()
        return PdfValueParser.referenceArray(body) ?: throw unreadable()
    }

    private fun unreadable(): PdfSigningException = PdfSigningException(PdfSigningFailure.STRUCTURE_UNREADABLE)

    private const val DSS_NAME = "DSS"
    private const val TYPE_NAME = "Type"
    private const val CERTIFICATES_NAME = "Certs"
    private const val OCSP_RESPONSES_NAME = "OCSPs"
    private const val REVOCATION_LISTS_NAME = "CRLs"
    private const val VRI_NAME = "VRI"
}
