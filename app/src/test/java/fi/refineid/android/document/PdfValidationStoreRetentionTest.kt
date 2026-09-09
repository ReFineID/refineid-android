package fi.refineid.android.document

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PdfValidationStoreRetentionTest {
    @Test
    fun indirectArraysVriAndUnrecognizedEntriesArePreserved() {
        val original =
            PdfValidationStoreTestSupport.document(
                catalog = PdfValidationStoreTestSupport.catalog(dss = reference(DSS_OBJECT_NUMBER)),
                extraObjects =
                    mapOf(
                        DSS_OBJECT_NUMBER to
                            "<< /Type /DSS /Certs ${reference(CERTIFICATE_ARRAY_OBJECT_NUMBER)} " +
                            "/OCSPs [${reference(OCSP_OBJECT_NUMBER)}] " +
                            "/CRLs [${reference(CRL_OBJECT_NUMBER)}] " +
                            "/VRI ${reference(VRI_OBJECT_NUMBER)} " +
                            "/Future ${reference(FUTURE_OBJECT_NUMBER)} >>",
                        CERTIFICATE_ARRAY_OBJECT_NUMBER to
                            "[${reference(CERTIFICATE_OBJECT_NUMBER)}]",
                        CERTIFICATE_OBJECT_NUMBER to PdfValidationStoreTestSupport.stream(CERTIFICATE_OLD),
                        OCSP_OBJECT_NUMBER to PdfValidationStoreTestSupport.stream(OCSP_OLD),
                        CRL_OBJECT_NUMBER to PdfValidationStoreTestSupport.stream(CRL_OLD),
                        VRI_OBJECT_NUMBER to "<< /OLD ${reference(CERTIFICATE_OBJECT_NUMBER)} >>",
                        FUTURE_OBJECT_NUMBER to "<< /Value (kept) >>",
                    ),
            )
        val result = appendCertificate(original, CERTIFICATE_NEW)
        val store = checkNotNull(PdfValidationStoreTestSupport.latestStore(result))

        assertEquals(
            pdfReference(CERTIFICATE_OBJECT_NUMBER),
            PdfValidationStoreTestSupport
                .references(PdfValidationStoreTestSupport.CERTIFICATES_NAME, store.body)
                .first(),
        )
        assertEquals(
            listOf(pdfReference(OCSP_OBJECT_NUMBER)),
            PdfValidationStoreTestSupport.references(
                PdfValidationStoreTestSupport.OCSP_RESPONSES_NAME,
                store.body,
            ),
        )
        assertEquals(
            listOf(pdfReference(CRL_OBJECT_NUMBER)),
            PdfValidationStoreTestSupport.references(
                PdfValidationStoreTestSupport.REVOCATION_LISTS_NAME,
                store.body,
            ),
        )
        assertTrue(store.body.contains("/VRI ${reference(VRI_OBJECT_NUMBER)}"))
        assertTrue(store.body.contains("/Future ${reference(FUTURE_OBJECT_NUMBER)}"))
    }

    @Test
    fun directStoreAndVriDictionariesArePreserved() {
        val directStore =
            "<< /Certs [${reference(CERTIFICATE_OBJECT_NUMBER)}] " +
                "/VRI << /OLD ${reference(CERTIFICATE_OBJECT_NUMBER)} >> >>"
        val original =
            PdfValidationStoreTestSupport.document(
                catalog = PdfValidationStoreTestSupport.catalog(dss = directStore),
                extraObjects =
                    mapOf(
                        CERTIFICATE_OBJECT_NUMBER to
                            PdfValidationStoreTestSupport.stream(CERTIFICATE_OLD),
                    ),
            )
        val result = appendOcsp(original, OCSP_NEW)
        val store = checkNotNull(PdfValidationStoreTestSupport.latestStore(result))

        assertEquals(
            listOf(pdfReference(CERTIFICATE_OBJECT_NUMBER)),
            PdfValidationStoreTestSupport.references(
                PdfValidationStoreTestSupport.CERTIFICATES_NAME,
                store.body,
            ),
        )
        assertEquals(
            SINGLE_REFERENCE_COUNT,
            PdfValidationStoreTestSupport
                .references(PdfValidationStoreTestSupport.OCSP_RESPONSES_NAME, store.body)
                .size,
        )
        assertTrue(
            store.body.contains(
                "/VRI << /OLD ${reference(CERTIFICATE_OBJECT_NUMBER)} >>",
            ),
        )
    }

    @Test
    fun malformedEarlierStoreIsRejectedRatherThanDiscarded() {
        val original =
            PdfValidationStoreTestSupport.document(
                catalog = PdfValidationStoreTestSupport.catalog(dss = reference(DSS_OBJECT_NUMBER)),
                extraObjects =
                    mapOf(
                        DSS_OBJECT_NUMBER to
                            "<< /Certs [${reference(CERTIFICATE_ARRAY_OBJECT_NUMBER)} false] >>",
                        CERTIFICATE_ARRAY_OBJECT_NUMBER to
                            PdfValidationStoreTestSupport.stream(CERTIFICATE_OLD),
                    ),
            )

        assertPdfFailure(PdfSigningFailure.STRUCTURE_UNREADABLE) {
            appendCertificate(original, CERTIFICATE_NEW).fill(ZERO_BYTE)
        }
    }

    @Test
    fun nestedOrQuotedDssNamesAreNotReplaced() {
        val additions =
            "/Note (text /DSS ${reference(QUOTED_DSS_OBJECT_NUMBER)}) " +
                "/Metadata << /DSS ${reference(NESTED_DSS_OBJECT_NUMBER)} >>"
        val original =
            PdfValidationStoreTestSupport.document(
                PdfValidationStoreTestSupport.catalog(additions = additions),
            )
        val result = appendCertificate(original, CERTIFICATE_NEW)
        val latestCatalog =
            checkNotNull(
                PdfValidationStoreTestSupport.latestObject(
                    PdfTestDocuments.CATALOG_OBJECT_NUMBER,
                    result,
                ),
            )
        val store = checkNotNull(PdfValidationStoreTestSupport.latestStore(result))

        assertTrue(latestCatalog.contains("/Note (text /DSS ${reference(QUOTED_DSS_OBJECT_NUMBER)})"))
        assertTrue(latestCatalog.contains("/Metadata << /DSS ${reference(NESTED_DSS_OBJECT_NUMBER)} >>"))
        assertTrue(latestCatalog.contains("/DSS ${reference(store.number)}"))
    }

    @Test
    fun escapedDssNameIsUpdatedWithoutAddingADuplicate() {
        val original =
            PdfValidationStoreTestSupport.document(
                catalog =
                    "<< /Type /Catalog /Pages ${reference(PdfTestDocuments.PAGE_TREE_OBJECT_NUMBER)} " +
                        "/D#53S ${reference(DSS_OBJECT_NUMBER)} >>",
                extraObjects =
                    mapOf(
                        DSS_OBJECT_NUMBER to
                            "<< /Certs [${reference(CERTIFICATE_ARRAY_OBJECT_NUMBER)}] >>",
                        CERTIFICATE_ARRAY_OBJECT_NUMBER to
                            PdfValidationStoreTestSupport.stream(CERTIFICATE_OLD),
                    ),
            )
        val result = appendCertificate(original, CERTIFICATE_NEW)
        val latestCatalog =
            checkNotNull(
                PdfValidationStoreTestSupport.latestObject(
                    PdfTestDocuments.CATALOG_OBJECT_NUMBER,
                    result,
                ),
            )
        val store = checkNotNull(PdfValidationStoreTestSupport.latestStore(result))

        assertFalse(latestCatalog.contains("/DSS "))
        assertTrue(latestCatalog.contains("/D#53S ${reference(store.number)}"))
        assertEquals(
            pdfReference(CERTIFICATE_ARRAY_OBJECT_NUMBER),
            PdfValidationStoreTestSupport
                .references(PdfValidationStoreTestSupport.CERTIFICATES_NAME, store.body)
                .first(),
        )
        assertEquals(
            TWO_REFERENCE_COUNT,
            PdfValidationStoreTestSupport
                .references(PdfValidationStoreTestSupport.CERTIFICATES_NAME, store.body)
                .size,
        )
    }

    @Test
    fun rawCatalogAndPreviousStoreBytesAreNotTranscodedToUtf8() {
        val catalogDocument =
            PdfValidationStoreTestSupport.document(
                PdfValidationStoreTestSupport.catalog(additions = "/Note $RAW_CATALOG_MARKER"),
            )
        replaceMarkerByte(catalogDocument, RAW_CATALOG_MARKER, RAW_CATALOG_PREFIX, RAW_PDF_BYTE)
        val catalogResult = appendCertificate(catalogDocument, CERTIFICATE_NEW)
        assertRawBytePreserved(catalogResult)

        val storeDocument =
            PdfValidationStoreTestSupport.document(
                catalog = PdfValidationStoreTestSupport.catalog(dss = reference(DSS_OBJECT_NUMBER)),
                extraObjects = mapOf(DSS_OBJECT_NUMBER to "<< /Future $RAW_STORE_MARKER >>"),
            )
        replaceMarkerByte(storeDocument, RAW_STORE_MARKER, RAW_STORE_PREFIX, RAW_PDF_BYTE)
        val storeResult = appendCertificate(storeDocument, CERTIFICATE_NEW)
        assertRawBytePreserved(storeResult)
    }

    @Test
    fun trailerIdentifierPreservesRawBytesAndTokenAwareArrayBoundary() {
        val rawIdentifierEntry = " /ID [$RAW_IDENTIFIER_MARKER(second)]"
        val rawDocument =
            PdfValidationStoreTestSupport.document(
                catalog = PdfValidationStoreTestSupport.catalog(),
                trailerExtra = rawIdentifierEntry,
            )
        replaceMarkerByte(rawDocument, RAW_IDENTIFIER_MARKER, RAW_IDENTIFIER_PREFIX, RAW_PDF_BYTE)
        val rawResult = appendCertificate(rawDocument, CERTIFICATE_NEW)
        assertRawBytePreserved(rawResult)

        val bracketIdentifierEntry = " /ID [(first]value)(second)]"
        val bracketDocument =
            PdfValidationStoreTestSupport.document(
                catalog = PdfValidationStoreTestSupport.catalog(),
                trailerExtra = bracketIdentifierEntry,
            )
        val bracketResult = appendCertificate(bracketDocument, CERTIFICATE_NEW)
        assertEquals(
            TWO_OCCURRENCE_COUNT,
            PdfValidationStoreTestSupport.occurrences(bracketIdentifierEntry.trim(), bracketResult),
        )
    }

    private fun appendCertificate(
        document: ByteArray,
        certificate: String,
    ): ByteArray =
        append(
            document = document,
            certificates = listOf(certificate.encodeToByteArray()),
            ocspResponses = emptyList(),
        )

    private fun appendOcsp(
        document: ByteArray,
        ocspResponse: String,
    ): ByteArray =
        append(
            document = document,
            certificates = emptyList(),
            ocspResponses = listOf(ocspResponse.encodeToByteArray()),
        )

    private fun append(
        document: ByteArray,
        certificates: List<ByteArray>,
        ocspResponses: List<ByteArray>,
    ): ByteArray {
        val material =
            PdfValidationMaterial.copyOf(
                certificates = certificates,
                ocspResponses = ocspResponses,
                revocationLists = emptyList(),
            )
        return try {
            PdfValidationStore.append(document, material)
        } finally {
            material.close()
        }
    }

    private fun replaceMarkerByte(
        document: ByteArray,
        marker: String,
        prefix: String,
        replacement: Byte,
    ) {
        val markerBytes = marker.encodeToByteArray()
        val start =
            document.indices.firstOrNull { candidate ->
                candidate <= document.size - markerBytes.size &&
                    markerBytes.indices.all { offset ->
                        document[candidate + offset] == markerBytes[offset]
                    }
            }
        checkNotNull(start)
        document[start + prefix.encodeToByteArray().size] = replacement
    }

    private fun assertRawBytePreserved(document: ByteArray) {
        assertEquals(TWO_OCCURRENCE_COUNT, document.count { byte -> byte == RAW_PDF_BYTE })
        assertFalse(document.containsSubsequence(TRANSCODED_RAW_PDF_BYTES))
    }

    private fun ByteArray.containsSubsequence(expected: ByteArray): Boolean =
        indices.any { start ->
            start <= size - expected.size &&
                expected.indices.all { offset -> this[start + offset] == expected[offset] }
        }

    private fun assertPdfFailure(
        expected: PdfSigningFailure,
        operation: () -> Unit,
    ) {
        val failure =
            assertThrows(PdfSigningException::class.java) {
                operation()
            }
        assertEquals(expected, failure.kind)
    }

    private fun reference(number: Int): String = pdfReference(number).encodedIndirectReference()

    private fun pdfReference(number: Int): PdfDocumentIndex.Reference =
        PdfDocumentIndex.Reference(
            number = number,
            generation = PdfTestDocuments.OBJECT_GENERATION,
        )

    private companion object {
        const val DSS_OBJECT_NUMBER = 4
        const val CERTIFICATE_ARRAY_OBJECT_NUMBER = 5
        const val CERTIFICATE_OBJECT_NUMBER = 6
        const val OCSP_OBJECT_NUMBER = 7
        const val CRL_OBJECT_NUMBER = 8
        const val VRI_OBJECT_NUMBER = 9
        const val FUTURE_OBJECT_NUMBER = 10
        const val QUOTED_DSS_OBJECT_NUMBER = 99
        const val NESTED_DSS_OBJECT_NUMBER = 98
        const val CERTIFICATE_OLD = "CERT-OLD"
        const val CERTIFICATE_NEW = "CERT-NEW"
        const val OCSP_OLD = "OCSP-OLD"
        const val OCSP_NEW = "OCSP-NEW"
        const val CRL_OLD = "CRL-OLD"
        const val RAW_CATALOG_MARKER = "(raw-X-byte)"
        const val RAW_CATALOG_PREFIX = "(raw-"
        const val RAW_STORE_MARKER = "(store-X-byte)"
        const val RAW_STORE_PREFIX = "(store-"
        const val RAW_IDENTIFIER_MARKER = "(id-X-byte)"
        const val RAW_IDENTIFIER_PREFIX = "(id-"
        const val SINGLE_REFERENCE_COUNT = 1
        const val TWO_REFERENCE_COUNT = 2
        const val TWO_OCCURRENCE_COUNT = 2
        const val ZERO_BYTE: Byte = 0
        val RAW_PDF_BYTE: Byte = 0xE9.toByte()
        val TRANSCODED_RAW_PDF_BYTES = byteArrayOf(0xC3.toByte(), 0xA9.toByte())
    }
}
