package fi.refineid.android.document

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.concurrent.TimeUnit

class PdfValidationStoreTest {
    @Test
    fun firstStoreCarriesEveryKindOfMaterialInAnIncrementalRevision() {
        val original =
            PdfValidationStoreTestSupport.document(
                PdfValidationStoreTestSupport.catalog(),
            )
        val material =
            PdfValidationStoreTestSupport.material(
                certificate = CERTIFICATE_A,
                ocspResponse = OCSP_RESPONSE_A,
                revocationList = REVOCATION_LIST_A,
            )
        val result =
            try {
                PdfValidationStore.append(original, material)
            } finally {
                material.close()
            }
        val store = checkNotNull(PdfValidationStoreTestSupport.latestStore(result))

        assertArrayEquals(original, result.copyOfRange(FIRST_BYTE_OFFSET, original.size))
        assertTrue(store.body.contains(DSS_TYPE_ENTRY))
        assertEquals(
            SINGLE_REFERENCE_COUNT,
            PdfValidationStoreTestSupport
                .references(PdfValidationStoreTestSupport.CERTIFICATES_NAME, store.body)
                .size,
        )
        assertEquals(
            SINGLE_REFERENCE_COUNT,
            PdfValidationStoreTestSupport
                .references(PdfValidationStoreTestSupport.OCSP_RESPONSES_NAME, store.body)
                .size,
        )
        assertEquals(
            SINGLE_REFERENCE_COUNT,
            PdfValidationStoreTestSupport
                .references(PdfValidationStoreTestSupport.REVOCATION_LISTS_NAME, store.body)
                .size,
        )
        assertTrue(String(result, Charsets.ISO_8859_1).contains(streamMarker(CERTIFICATE_A)))
        assertTrue(String(result, Charsets.ISO_8859_1).contains(streamMarker(OCSP_RESPONSE_A)))
        assertTrue(String(result, Charsets.ISO_8859_1).contains(streamMarker(REVOCATION_LIST_A)))
    }

    @Test
    fun emptyMaterialLeavesTheDocumentByteIdentical() {
        val original =
            PdfValidationStoreTestSupport.document(
                PdfValidationStoreTestSupport.catalog(),
            )
        val material = PdfValidationStoreTestSupport.emptyMaterial()
        val result =
            try {
                PdfValidationStore.append(original, material)
            } finally {
                material.close()
            }

        assertArrayEquals(original, result)
    }

    @Test
    fun duplicateNewMaterialIsWrittenOncePerCategory() {
        val duplicate = DUPLICATE_CERTIFICATE.encodeToByteArray()
        val material =
            PdfValidationMaterial.copyOf(
                certificates = listOf(duplicate, duplicate),
                ocspResponses = emptyList(),
                revocationLists = emptyList(),
            )
        val result =
            try {
                PdfValidationStore.append(
                    document =
                        PdfValidationStoreTestSupport.document(
                            PdfValidationStoreTestSupport.catalog(),
                        ),
                    material = material,
                )
            } finally {
                material.close()
                duplicate.fill(ZERO_BYTE)
            }
        val store = checkNotNull(PdfValidationStoreTestSupport.latestStore(result))

        assertEquals(
            SINGLE_REFERENCE_COUNT,
            PdfValidationStoreTestSupport
                .references(PdfValidationStoreTestSupport.CERTIFICATES_NAME, store.body)
                .size,
        )
        assertEquals(
            SINGLE_OCCURRENCE_COUNT,
            PdfValidationStoreTestSupport.occurrences(
                marker = streamMarker(DUPLICATE_CERTIFICATE),
                document = result,
            ),
        )
    }

    @Test
    fun secondAppendRetainsAllEarlierValidationReferences() {
        val original =
            PdfValidationStoreTestSupport.document(
                PdfValidationStoreTestSupport.catalog(),
            )
        val first = appendMaterial(original, MATERIAL_SUFFIX_OLD)
        val firstStore = checkNotNull(PdfValidationStoreTestSupport.latestStore(first))
        val second = appendMaterial(first, MATERIAL_SUFFIX_NEW)
        val secondStore = checkNotNull(PdfValidationStoreTestSupport.latestStore(second))

        for (name in MATERIAL_CATEGORY_NAMES) {
            val oldReferences = PdfValidationStoreTestSupport.references(name, firstStore.body)
            val newReferences = PdfValidationStoreTestSupport.references(name, secondStore.body)
            assertEquals(SINGLE_REFERENCE_COUNT, oldReferences.size)
            assertEquals(TWO_REFERENCE_COUNT, newReferences.size)
            assertEquals(oldReferences.first(), newReferences.first())
        }
        for (marker in ALL_MATERIAL_MARKERS) {
            assertTrue(String(second, Charsets.ISO_8859_1).contains(marker))
        }
    }

    @Test
    fun materialCopiesItsInputClearsTransientViewsAndFailsAfterClose() {
        val source = OWNED_CERTIFICATE.encodeToByteArray()
        val material =
            PdfValidationMaterial.copyOf(
                certificates = listOf(source),
                ocspResponses = emptyList(),
                revocationLists = emptyList(),
            )
        source.fill(ZERO_BYTE)
        var transient: ByteArray? = null
        material.useCopies { certificates, _, _ ->
            transient = certificates.single()
            assertArrayEquals(OWNED_CERTIFICATE.encodeToByteArray(), certificates.single())
        }
        assertTrue(checkNotNull(transient).all { byte -> byte == ZERO_BYTE })
        material.close()

        assertPdfFailure(PdfSigningFailure.VALIDATION_MATERIAL_UNAVAILABLE) {
            PdfValidationStore
                .append(
                    document =
                        PdfValidationStoreTestSupport.document(
                            PdfValidationStoreTestSupport.catalog(),
                        ),
                    material = material,
                ).fill(ZERO_BYTE)
        }
    }

    @Test
    fun malformedOrExcessiveMaterialIsRejectedBeforeCopying() {
        assertMaterialMalformed(certificates = listOf(ByteArray(EMPTY_EVIDENCE_LENGTH)))
        assertMaterialMalformed(
            certificates =
                List(PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_COUNT + EXCESS_COUNT) {
                    MINIMAL_DER_SEQUENCE.copyOf()
                },
        )
        assertMaterialMalformed(
            certificates =
                listOf(
                    ByteArray(
                        PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES + EXCESS_BYTE_COUNT,
                    ),
                ),
        )
    }

    @Test
    fun qpdfAcceptsTheValidationStoreRevisionWhenAvailable() {
        val qpdf = findExecutable(QPDF_EXECUTABLE_NAME)
        assumeTrue("qpdf is not installed", qpdf != null)
        val signedDocument =
            PdfIncrementalSigner
                .prepare(
                    document =
                        PdfValidationStoreTestSupport.document(
                            PdfValidationStoreTestSupport.catalog(),
                        ),
                    revision = PdfSignatureRevision.Signature(SYNTHETIC_SIGNATURE_CLAIM),
                ).filledWith(MINIMAL_DER_SEQUENCE)
        val result =
            appendMaterial(
                document = signedDocument,
                suffix = MATERIAL_SUFFIX_QPDF,
            )
        assertArrayEquals(
            signedDocument,
            result.copyOfRange(FIRST_BYTE_OFFSET, signedDocument.size),
        )
        val path = Files.createTempFile(QPDF_TEMPORARY_FILE_PREFIX, PDF_FILE_SUFFIX)
        try {
            Files.write(path, result)
            val process =
                ProcessBuilder(checkNotNull(qpdf).toString(), QPDF_CHECK_ARGUMENT, path.toString())
                    .redirectErrorStream(true)
                    .start()
            val completed = process.waitFor(QPDF_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            if (!completed) {
                process.destroyForcibly()
            }
            val report = process.inputStream.bufferedReader().use { reader -> reader.readText() }
            assertTrue(report, completed)
            assertEquals(report, SUCCESSFUL_PROCESS_EXIT_CODE, process.exitValue())
        } finally {
            Files.deleteIfExists(path)
            result.fill(ZERO_BYTE)
        }
    }

    private fun appendMaterial(
        document: ByteArray,
        suffix: String,
    ): ByteArray {
        val material =
            PdfValidationStoreTestSupport.material(
                certificate = CERTIFICATE_PREFIX + suffix,
                ocspResponse = OCSP_RESPONSE_PREFIX + suffix,
                revocationList = REVOCATION_LIST_PREFIX + suffix,
            )
        return try {
            PdfValidationStore.append(document, material)
        } finally {
            material.close()
        }
    }

    private fun assertMaterialMalformed(certificates: List<ByteArray>) {
        assertPdfFailure(PdfSigningFailure.VALIDATION_MATERIAL_MALFORMED) {
            PdfValidationMaterial
                .copyOf(
                    certificates = certificates,
                    ocspResponses = emptyList(),
                    revocationLists = emptyList(),
                ).close()
        }
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

    private fun streamMarker(value: String): String = "stream\n$value\nendstream"

    private fun findExecutable(name: String): Path? =
        System
            .getenv(PATH_ENVIRONMENT_VARIABLE)
            ?.split(File.pathSeparator)
            ?.asSequence()
            ?.map { directory -> Path.of(directory, name) }
            ?.firstOrNull(Files::isExecutable)

    private companion object {
        const val CERTIFICATE_A = "CERT-A"
        const val OCSP_RESPONSE_A = "OCSP-A"
        const val REVOCATION_LIST_A = "CRL-A"
        const val DUPLICATE_CERTIFICATE = "CERT-DUPLICATE"
        const val OWNED_CERTIFICATE = "CERT-OWNED"
        const val CERTIFICATE_PREFIX = "CERT-"
        const val OCSP_RESPONSE_PREFIX = "OCSP-"
        const val REVOCATION_LIST_PREFIX = "CRL-"
        const val MATERIAL_SUFFIX_OLD = "OLD"
        const val MATERIAL_SUFFIX_NEW = "NEW"
        const val MATERIAL_SUFFIX_QPDF = "QPDF"
        const val DSS_TYPE_ENTRY = "/Type /DSS"
        const val FIRST_BYTE_OFFSET = 0
        const val EMPTY_EVIDENCE_LENGTH = 0
        const val EXCESS_COUNT = 1
        const val EXCESS_BYTE_COUNT = 1
        const val SINGLE_REFERENCE_COUNT = 1
        const val TWO_REFERENCE_COUNT = 2
        const val SINGLE_OCCURRENCE_COUNT = 1
        const val ZERO_BYTE: Byte = 0
        val MINIMAL_DER_SEQUENCE = byteArrayOf(DerValues.TAG_SEQUENCE.toByte(), ZERO_BYTE)
        val SYNTHETIC_SIGNATURE_CLAIM =
            PdfSignatureClaim(
                signedAt = Instant.parse("2026-08-15T12:34:56Z"),
                reason = null,
                location = null,
            )
        val MATERIAL_CATEGORY_NAMES =
            listOf(
                PdfValidationStoreTestSupport.CERTIFICATES_NAME,
                PdfValidationStoreTestSupport.OCSP_RESPONSES_NAME,
                PdfValidationStoreTestSupport.REVOCATION_LISTS_NAME,
            )
        val ALL_MATERIAL_MARKERS =
            listOf(
                CERTIFICATE_PREFIX + MATERIAL_SUFFIX_OLD,
                OCSP_RESPONSE_PREFIX + MATERIAL_SUFFIX_OLD,
                REVOCATION_LIST_PREFIX + MATERIAL_SUFFIX_OLD,
                CERTIFICATE_PREFIX + MATERIAL_SUFFIX_NEW,
                OCSP_RESPONSE_PREFIX + MATERIAL_SUFFIX_NEW,
                REVOCATION_LIST_PREFIX + MATERIAL_SUFFIX_NEW,
            )
        const val PATH_ENVIRONMENT_VARIABLE = "PATH"
        const val QPDF_EXECUTABLE_NAME = "qpdf"
        const val QPDF_CHECK_ARGUMENT = "--check"
        const val QPDF_TEMPORARY_FILE_PREFIX = "refineid-dss-"
        const val PDF_FILE_SUFFIX = ".pdf"
        const val QPDF_TIMEOUT_SECONDS = 30L
        const val SUCCESSFUL_PROCESS_EXIT_CODE = 0
    }
}
