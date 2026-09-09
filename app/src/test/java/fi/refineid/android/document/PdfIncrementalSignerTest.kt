package fi.refineid.android.document

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Instant
import java.util.concurrent.TimeUnit

class PdfIncrementalSignerTest {
    @Test
    fun appendsASignatureFieldWithVisibleStampAndPreservesTheOriginalRevision() {
        val original =
            PdfTestDocuments.minimalClassic(
                trailerExtra = IDENTIFIER_TRAILER_ENTRY,
            )
        val placeholder =
            PdfIncrementalSigner.prepare(
                document = original.document,
                revision = PdfSignatureRevision.Signature(VALID_CLAIM),
            )
        val prepared = placeholder.copyDocument()
        val index = PdfDocumentIndex.parse(prepared)
        val signature = reference(EXPECTED_FIRST_SIGNATURE_OBJECT_NUMBER)
        val field = reference(EXPECTED_FIRST_FIELD_OBJECT_NUMBER)
        val appearance = reference(EXPECTED_FIRST_APPEARANCE_OBJECT_NUMBER)

        assertEquals(PdfFormat.SIGNATURE_CAPACITY_BYTES, placeholder.capacity)
        assertArrayEquals(
            original.document,
            prepared.copyOfRange(FIRST_DOCUMENT_OFFSET, original.document.size),
        )
        assertEquals(EXPECTED_FIRST_APPEARANCE_OBJECT_NUMBER, index.highestObjectNumber)
        assertEquals(IDENTIFIER_VALUE, dictionaryValue(index.trailer, IDENTIFIER_NAME))
        assertEquals(
            listOf(field),
            formFields(index = index, document = prepared),
        )
        assertEquals(
            listOf(field),
            references(
                dictionaryValue(
                    checkNotNull(index.body(PdfTestDocuments.PAGE_OBJECT_NUMBER, prepared)),
                    ANNOTATIONS_NAME,
                ),
            ),
        )

        val signatureSyntax =
            PdfDictionarySyntax(checkNotNull(index.body(signature, prepared)))
        assertEquals(SIGNATURE_TYPE, nameValue(signatureSyntax, TYPE_NAME))
        assertEquals(CADES_SUBFILTER, nameValue(signatureSyntax, SUBFILTER_NAME))

        val appearanceBody = checkNotNull(index.body(appearance, prepared))
        assertTrue(appearanceBody.contains("/Type /XObject"))
        assertTrue(appearanceBody.contains("/Subtype /Form"))
        assertTrue(appearanceBody.contains("0.7765 0.1569 0.1569 RG"))

        val fieldSyntax = PdfDictionarySyntax(checkNotNull(index.body(field, prepared)))
        assertEquals(SIGNATURE_FIELD_TYPE, nameValue(fieldSyntax, FIELD_TYPE_NAME))
        assertEquals(signature, PdfValueParser.reference(value(fieldSyntax, VALUE_NAME)))
        assertEquals(
            reference(PdfTestDocuments.PAGE_OBJECT_NUMBER),
            PdfValueParser.reference(value(fieldSyntax, PAGE_NAME)),
        )
        assertEquals(EXPECTED_FIRST_FIELD_NAME, value(fieldSyntax, FIELD_NAME))
        assertTrue(value(fieldSyntax, "AP").contains("6 0 R"))
    }

    @Test
    fun byteRangeExcludesOnlyTheFixedContentsHoleAndSurvivesFilling() {
        val original = PdfTestDocuments.minimalClassic().document
        val placeholder =
            PdfIncrementalSigner.prepare(
                document = original,
                revision = PdfSignatureRevision.Signature(VALID_CLAIM),
            )
        val prepared = placeholder.copyDocument()
        val inspection = inspect(prepared)

        assertArrayEquals(
            intArrayOf(
                FIRST_DOCUMENT_OFFSET,
                inspection.contentsOpen,
                inspection.secondSpanStart,
                prepared.size - inspection.secondSpanStart,
            ),
            inspection.byteRange,
        )
        assertEquals(
            PdfFormat.SIGNATURE_CAPACITY_BYTES * PdfFormat.HEX_CHARACTERS_PER_BYTE +
                PdfFormat.HEX_DELIMITER_COUNT,
            inspection.secondSpanStart - inspection.contentsOpen,
        )
        assertArrayEquals(inspection.signedOctets(prepared), placeholder.copySignedOctets())
        assertArrayEquals(
            MessageDigest.getInstance(SHA384_DIGEST_ALGORITHM).digest(inspection.signedOctets(prepared)),
            placeholder.digest(),
        )

        val filled = placeholder.filledWith(SYNTHETIC_DER)
        assertEquals(prepared.size, filled.size)
        assertArrayEquals(inspection.signedOctets(prepared), inspection.signedOctets(filled))
        assertEquals(
            SYNTHETIC_DER_HEX,
            String(
                filled,
                inspection.contentsOpen + HEX_OPEN_DELIMITER_LENGTH,
                SYNTHETIC_DER_HEX.length,
                Charsets.ISO_8859_1,
            ),
        )
        PdfDocumentIndex.parse(filled)
    }

    @Test
    fun encodesClaimTextAndSeparatesSignatureFromTimestampDictionaries() {
        val original = PdfTestDocuments.minimalClassic().document
        val signature =
            PdfIncrementalSigner.prepare(
                document = original,
                revision =
                    PdfSignatureRevision.Signature(
                        PdfSignatureClaim(
                            signedAt = VALID_SIGNING_INSTANT,
                            reason = INJECTION_SHAPED_REASON,
                            location = UNICODE_LOCATION,
                        ),
                    ),
            )
        val signatureDocument = signature.copyDocument()
        val signatureIndex = PdfDocumentIndex.parse(signatureDocument)
        val signatureSyntax =
            PdfDictionarySyntax(
                checkNotNull(
                    signatureIndex.body(
                        reference(EXPECTED_FIRST_SIGNATURE_OBJECT_NUMBER),
                        signatureDocument,
                    ),
                ),
            )

        assertEquals(ENCODED_INJECTION_SHAPED_REASON, value(signatureSyntax, REASON_NAME))
        assertEquals(ENCODED_UNICODE_LOCATION, value(signatureSyntax, LOCATION_NAME))
        assertEquals(EXPECTED_SIGNING_DATE, value(signatureSyntax, MODIFICATION_DATE_NAME))
        assertNull(signatureSyntax.entry(INJECTED_ACTION_NAME))
        assertFalse(signatureSyntax.encoded().contains(INJECTION_SHAPED_REASON))

        val timestamp =
            PdfIncrementalSigner.prepare(
                document = original,
                revision = PdfSignatureRevision.DocumentTimestamp,
            )
        val timestampDocument = timestamp.copyDocument()
        val timestampIndex = PdfDocumentIndex.parse(timestampDocument)
        val timestampSyntax =
            PdfDictionarySyntax(
                checkNotNull(
                    timestampIndex.body(
                        reference(EXPECTED_FIRST_SIGNATURE_OBJECT_NUMBER),
                        timestampDocument,
                    ),
                ),
            )

        assertEquals(PdfFormat.TIMESTAMP_CAPACITY_BYTES, timestamp.capacity)
        assertEquals(DOCUMENT_TIMESTAMP_TYPE, nameValue(timestampSyntax, TYPE_NAME))
        assertEquals(TIMESTAMP_SUBFILTER, nameValue(timestampSyntax, SUBFILTER_NAME))
        assertNull(timestampSyntax.entry(MODIFICATION_DATE_NAME))
        assertNull(timestampSyntax.entry(REASON_NAME))
        assertNull(timestampSyntax.entry(LOCATION_NAME))
    }

    @Test
    fun chainsSignaturesWithUniqueFieldsAndPreviousCrossReference() {
        val first =
            PdfIncrementalSigner.prepare(
                document = PdfTestDocuments.minimalClassic().document,
                revision = PdfSignatureRevision.Signature(VALID_CLAIM),
            )
        val firstFilled = first.filledWith(SYNTHETIC_DER)
        val firstIndex = PdfDocumentIndex.parse(firstFilled)
        val second =
            PdfIncrementalSigner.prepare(
                document = firstFilled,
                revision = PdfSignatureRevision.Signature(VALID_CLAIM),
            )
        val secondDocument = second.copyDocument()
        val secondIndex = PdfDocumentIndex.parse(secondDocument)
        val expectedFields =
            listOf(
                reference(EXPECTED_FIRST_FIELD_OBJECT_NUMBER),
                reference(EXPECTED_SECOND_FIELD_OBJECT_NUMBER),
            )

        assertEquals(expectedFields, formFields(index = secondIndex, document = secondDocument))
        assertEquals(
            expectedFields,
            references(
                dictionaryValue(
                    checkNotNull(secondIndex.body(PdfTestDocuments.PAGE_OBJECT_NUMBER, secondDocument)),
                    ANNOTATIONS_NAME,
                ),
            ),
        )
        assertEquals(
            firstIndex.previousStartXref,
            PdfDocumentIndex.integer(PdfFormat.PREVIOUS_XREF_KEY, secondIndex.trailer),
        )
        assertTrue(
            checkNotNull(
                secondIndex.body(reference(EXPECTED_FIRST_SIGNATURE_OBJECT_NUMBER), secondDocument),
            ).contains(SYNTHETIC_DER_HEX),
        )
        assertEquals(
            EXPECTED_FIRST_FIELD_NAME,
            dictionaryValue(
                checkNotNull(secondIndex.body(reference(EXPECTED_FIRST_FIELD_OBJECT_NUMBER), secondDocument)),
                FIELD_NAME,
            ),
        )
        assertEquals(
            EXPECTED_SECOND_FIELD_NAME,
            dictionaryValue(
                checkNotNull(secondIndex.body(reference(EXPECTED_SECOND_FIELD_OBJECT_NUMBER), secondDocument)),
                FIELD_NAME,
            ),
        )
    }

    @Test
    fun updatesExistingIndirectFieldAndAnnotationArrays() {
        val original = PdfTestDocuments.classicWithIndirectFormAndAnnotations().document
        val placeholder =
            PdfIncrementalSigner.prepare(
                document = original,
                revision = PdfSignatureRevision.Signature(VALID_CLAIM),
            )
        val prepared = placeholder.copyDocument()
        val index = PdfDocumentIndex.parse(prepared)
        val expectedFields =
            listOf(
                reference(PdfTestDocuments.EXISTING_FIELD_OBJECT_NUMBER),
                reference(EXPECTED_INDIRECT_FIXTURE_FIELD_OBJECT_NUMBER),
            )

        assertEquals(
            expectedFields,
            references(checkNotNull(index.body(PdfTestDocuments.FIELDS_ARRAY_OBJECT_NUMBER, prepared))),
        )
        assertEquals(
            expectedFields,
            references(checkNotNull(index.body(PdfTestDocuments.ANNOTATIONS_ARRAY_OBJECT_NUMBER, prepared))),
        )
        assertEquals(
            EXPECTED_MERGED_SIGNATURE_FLAGS,
            dictionaryValue(
                checkNotNull(index.body(PdfTestDocuments.ACRO_FORM_OBJECT_NUMBER, prepared)),
                SIGNATURE_FLAGS_NAME,
            ),
        )
        assertEquals(
            reference(PdfTestDocuments.FIELDS_ARRAY_OBJECT_NUMBER),
            PdfValueParser.reference(
                dictionaryValue(
                    checkNotNull(index.body(PdfTestDocuments.ACRO_FORM_OBJECT_NUMBER, prepared)),
                    FIELDS_NAME,
                ),
            ),
        )
    }

    @Test
    fun rejectsOverlongMalformedUnicodeAndOutOfRangeDateClaims() {
        val document = PdfTestDocuments.minimalClassic().document
        val malformedClaims =
            listOf(
                PdfSignatureClaim(
                    signedAt = VALID_SIGNING_INSTANT,
                    reason = CLAIM_CHARACTER.repeat(OVER_LIMIT_CLAIM_CHARACTER_COUNT),
                    location = null,
                ),
                PdfSignatureClaim(
                    signedAt = VALID_SIGNING_INSTANT,
                    reason = UNPAIRED_HIGH_SURROGATE,
                    location = null,
                ),
                PdfSignatureClaim(
                    signedAt = OUT_OF_RANGE_SIGNING_INSTANT,
                    reason = null,
                    location = null,
                ),
            )

        for (claim in malformedClaims) {
            val failure =
                assertThrows(PdfSigningException::class.java) {
                    PdfIncrementalSigner.prepare(
                        document = document,
                        revision = PdfSignatureRevision.Signature(claim),
                    )
                }
            assertEquals(PdfSigningFailure.SIGNATURE_CLAIM_MALFORMED, failure.kind)
        }
    }

    @Test
    fun qpdfAcceptsTheFilledIncrementalRevisionWhenAvailable() {
        val qpdf = qpdfExecutable()
        assumeTrue("qpdf is not installed", qpdf != null)
        val document =
            PdfIncrementalSigner
                .prepare(
                    document = PdfTestDocuments.classicWithIndirectFormAndAnnotations().document,
                    revision = PdfSignatureRevision.Signature(VALID_CLAIM),
                ).filledWith(SYNTHETIC_DER)
        val path = Files.createTempFile(QPDF_TEMPORARY_FILE_PREFIX, PDF_FILE_SUFFIX)
        try {
            Files.write(path, document)
            val process =
                ProcessBuilder(checkNotNull(qpdf).toString(), QPDF_CHECK_ARGUMENT, path.toString())
                    .redirectErrorStream(true)
                    .start()
            val completed = process.waitFor(QPDF_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            if (!completed) {
                process.destroyForcibly()
            }
            val output = process.inputStream.bufferedReader().use { reader -> reader.readText() }
            assertTrue(output, completed)
            assertEquals(output, SUCCESSFUL_PROCESS_EXIT_CODE, process.exitValue())
        } finally {
            Files.deleteIfExists(path)
        }
    }

    private fun formFields(
        index: PdfDocumentIndex,
        document: ByteArray,
    ): List<PdfDocumentIndex.Reference> {
        val catalog =
            PdfDictionarySyntax(
                checkNotNull(index.body(PdfTestDocuments.CATALOG_OBJECT_NUMBER, document)),
            )
        val form = PdfDictionarySyntax(value(catalog, ACRO_FORM_NAME))
        assertEquals(EXPECTED_DEFAULT_SIGNATURE_FLAGS, value(form, SIGNATURE_FLAGS_NAME))
        return references(value(form, FIELDS_NAME))
    }

    private fun inspect(document: ByteArray): PreparedPdfInspection {
        val text = String(document, Charsets.ISO_8859_1)
        val byteRangeStart = text.lastIndexOf(BYTE_RANGE_PREFIX)
        check(byteRangeStart >= FIRST_DOCUMENT_OFFSET)
        val valuesStart = byteRangeStart + BYTE_RANGE_PREFIX.length
        val valuesEnd = text.indexOf(BYTE_RANGE_CLOSE, valuesStart)
        check(valuesEnd >= valuesStart)
        val byteRange =
            text
                .substring(valuesStart, valuesEnd)
                .trim()
                .split(Regex(WHITESPACE_PATTERN))
                .map(String::toInt)
                .toIntArray()
        assertEquals(PdfFormat.BYTE_RANGE_FIELD_COUNT, byteRange.size)
        val contentsMarker = text.indexOf(CONTENTS_PREFIX, valuesEnd)
        check(contentsMarker >= valuesEnd)
        val contentsOpen = contentsMarker + CONTENTS_PREFIX.length
        assertEquals(HEX_OPEN_DELIMITER, text[contentsOpen])
        val contentsClose = text.indexOf(HEX_CLOSE_DELIMITER, contentsOpen)
        check(contentsClose > contentsOpen)
        return PreparedPdfInspection(
            byteRange = byteRange,
            contentsOpen = contentsOpen,
            secondSpanStart = contentsClose + HEX_CLOSE_DELIMITER_LENGTH,
        )
    }

    private fun dictionaryValue(
        dictionary: String,
        name: String,
    ): String = value(PdfDictionarySyntax(dictionary), name)

    private fun value(
        syntax: PdfDictionarySyntax,
        name: String,
    ): String = syntax.value(checkNotNull(syntax.entry(name)))

    private fun nameValue(
        syntax: PdfDictionarySyntax,
        name: String,
    ): String? = PdfValueLexemes.name(value(syntax, name))

    private fun references(text: String): List<PdfDocumentIndex.Reference> =
        checkNotNull(PdfValueParser.referenceArray(text))

    private fun reference(number: Int): PdfDocumentIndex.Reference =
        PdfDocumentIndex.Reference(number = number, generation = PdfTestDocuments.OBJECT_GENERATION)

    private fun qpdfExecutable(): Path? =
        System
            .getenv(PATH_ENVIRONMENT_VARIABLE)
            ?.split(File.pathSeparator)
            ?.asSequence()
            ?.map { directory -> Path.of(directory, QPDF_EXECUTABLE_NAME) }
            ?.firstOrNull(Files::isExecutable)

    private data class PreparedPdfInspection(
        val byteRange: IntArray,
        val contentsOpen: Int,
        val secondSpanStart: Int,
    ) {
        fun signedOctets(document: ByteArray): ByteArray =
            document.copyOfRange(FIRST_DOCUMENT_OFFSET, contentsOpen) +
                document.copyOfRange(secondSpanStart, document.size)
    }

    private companion object {
        const val TYPE_NAME = "Type"
        const val SUBFILTER_NAME = "SubFilter"
        const val FIELD_TYPE_NAME = "FT"
        const val VALUE_NAME = "V"
        const val PAGE_NAME = "P"
        const val FIELD_NAME = "T"
        const val RECTANGLE_NAME = "Rect"
        const val ANNOTATIONS_NAME = "Annots"
        const val ACRO_FORM_NAME = "AcroForm"
        const val FIELDS_NAME = "Fields"
        const val SIGNATURE_FLAGS_NAME = "SigFlags"
        const val IDENTIFIER_NAME = "ID"
        const val REASON_NAME = "Reason"
        const val LOCATION_NAME = "Location"
        const val MODIFICATION_DATE_NAME = "M"
        const val INJECTED_ACTION_NAME = "OpenAction"
        const val SIGNATURE_TYPE = "Sig"
        const val DOCUMENT_TIMESTAMP_TYPE = "DocTimeStamp"
        const val SIGNATURE_FIELD_TYPE = "Sig"
        const val CADES_SUBFILTER = "ETSI.CAdES.detached"
        const val TIMESTAMP_SUBFILTER = "ETSI.RFC3161"
        const val IDENTIFIER_VALUE = "[<0011> <2233>]"
        const val IDENTIFIER_TRAILER_ENTRY = " /ID $IDENTIFIER_VALUE"
        const val EXPECTED_FIRST_SIGNATURE_OBJECT_NUMBER = 4
        const val EXPECTED_FIRST_FIELD_OBJECT_NUMBER = 5
        const val EXPECTED_FIRST_APPEARANCE_OBJECT_NUMBER = 6
        const val EXPECTED_SECOND_FIELD_OBJECT_NUMBER = 8
        const val EXPECTED_INDIRECT_FIXTURE_FIELD_OBJECT_NUMBER = 9
        const val EXPECTED_FIRST_FIELD_NAME = "(Signature4)"
        const val EXPECTED_SECOND_FIELD_NAME = "(Signature7)"
        const val INVISIBLE_RECTANGLE = "[0 0 0 0]"
        const val EXPECTED_DEFAULT_SIGNATURE_FLAGS = "3"
        const val EXPECTED_MERGED_SIGNATURE_FLAGS = "7"
        const val FIRST_DOCUMENT_OFFSET = 0
        const val HEX_OPEN_DELIMITER_LENGTH = 1
        const val HEX_CLOSE_DELIMITER_LENGTH = 1
        const val BYTE_RANGE_PREFIX = "/ByteRange ["
        const val BYTE_RANGE_CLOSE = ']'
        const val CONTENTS_PREFIX = "/Contents "
        const val HEX_OPEN_DELIMITER = '<'
        const val HEX_CLOSE_DELIMITER = '>'
        const val WHITESPACE_PATTERN = "\\s+"
        const val SHA384_DIGEST_ALGORITHM = "SHA-384"
        const val INJECTION_SHAPED_REASON = ") /OpenAction"
        const val UNICODE_LOCATION = "Helsinki \u00E4\uD83D\uDD10"
        const val ENCODED_INJECTION_SHAPED_REASON =
            "<FEFF00290020002F004F00700065006E0041006300740069006F006E>"
        const val ENCODED_UNICODE_LOCATION =
            "<FEFF00480065006C00730069006E006B0069002000E4D83DDD10>"
        const val EXPECTED_SIGNING_DATE = "(D:20260815123456+00'00')"
        const val CLAIM_CHARACTER = "x"
        const val MAXIMUM_ACCEPTED_CLAIM_CHARACTER_COUNT = 1_024
        const val OVER_LIMIT_CHARACTER_COUNT = 1
        const val OVER_LIMIT_CLAIM_CHARACTER_COUNT =
            MAXIMUM_ACCEPTED_CLAIM_CHARACTER_COUNT + OVER_LIMIT_CHARACTER_COUNT
        const val UNPAIRED_HIGH_SURROGATE = "\uD800"
        const val PATH_ENVIRONMENT_VARIABLE = "PATH"
        const val QPDF_EXECUTABLE_NAME = "qpdf"
        const val QPDF_CHECK_ARGUMENT = "--check"
        const val QPDF_TEMPORARY_FILE_PREFIX = "refineid-synthetic-"
        const val PDF_FILE_SUFFIX = ".pdf"
        const val QPDF_TIMEOUT_SECONDS = 10L
        const val SUCCESSFUL_PROCESS_EXIT_CODE = 0
        const val DER_SEQUENCE_TAG: Byte = 0x30
        const val DER_SEQUENCE_CONTENT_LENGTH: Byte = 0x03
        const val DER_BOOLEAN_TAG: Byte = 0x01
        const val DER_BOOLEAN_CONTENT_LENGTH: Byte = 0x01
        const val DER_TRUE_VALUE: Byte = -0x01
        const val SYNTHETIC_DER_HEX = "30030101FF"
        val VALID_SIGNING_INSTANT: Instant = Instant.parse("2026-08-15T12:34:56Z")
        val OUT_OF_RANGE_SIGNING_INSTANT: Instant = Instant.parse("+10000-01-01T00:00:00Z")
        val VALID_CLAIM =
            PdfSignatureClaim(
                signedAt = VALID_SIGNING_INSTANT,
                reason = null,
                location = null,
            )
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
