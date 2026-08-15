// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.io.ByteArrayOutputStream
import java.time.DateTimeException
import java.time.Instant
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.util.Locale

internal data class PdfSignatureClaim(
    val signedAt: Instant,
    val reason: String?,
    val location: String?,
)

internal sealed interface PdfSignatureRevision {
    val contentsCapacity: Int

    data object DocumentTimestamp : PdfSignatureRevision {
        override val contentsCapacity: Int = PdfFormat.TIMESTAMP_CAPACITY_BYTES
    }

    data class Signature(
        val claim: PdfSignatureClaim,
    ) : PdfSignatureRevision {
        override val contentsCapacity: Int = PdfFormat.SIGNATURE_CAPACITY_BYTES
    }
}

/** Appends one invisible PAdES signature or document-timestamp revision. */
internal object PdfIncrementalSigner {
    fun prepare(
        document: ByteArray,
        revision: PdfSignatureRevision,
    ): PdfSignaturePlaceholder {
        val index = PdfDocumentIndex.parse(document)
        val root =
            PdfDocumentIndex.reference(PdfFormat.ROOT_KEY, index.trailer)
                ?: throw unreadable()
        val declaredSize =
            PdfDocumentIndex.integer(PdfFormat.SIZE_KEY, index.trailer)
                ?: throw unreadable()
        val signatureNumber =
            maxOf(
                declaredSize,
                increment(index.highestObjectNumber),
                MINIMUM_NEW_OBJECT_NUMBER,
            )
        val signature = PdfDocumentIndex.Reference(signatureNumber, NEW_OBJECT_GENERATION)
        val field =
            PdfDocumentIndex.Reference(
                number = increment(signature.number),
                generation = NEW_OBJECT_GENERATION,
            )
        val source = PdfRevisionSource(document = document, index = index, root = root)
        val plan = PdfIncrementalRevisionPlanner.plan(source = source, field = field)
        val capacity = revision.contentsCapacity
        val output = PdfOutput(document.size)
        output.write(document)
        output.ensureLineTerminated()
        val offsets = mutableMapOf<PdfDocumentIndex.Reference, Int>()
        offsets[signature] = output.size
        val holes = appendSignatureObject(output, revision, signature, capacity)
        offsets[field] = output.size
        output.writeLatin1(widget(field = field, signature = signature, page = plan.page))
        for ((reference, body) in plan.mutations.entries.sortedBy { entry -> entry.key.number }) {
            offsets[reference] = output.size
            output.writeLatin1(indirectObject(reference, body))
        }
        val xrefOffset = output.size
        val finalSize = increment(field.number)
        output.writeLatin1(
            crossReferenceSection(
                offsets = offsets,
                size = maxOf(declaredSize, finalSize),
                root = root,
                xrefOffset = xrefOffset,
                index = index,
            ),
        )
        return patched(
            document = output.toByteArray(),
            holes = holes,
            capacity = capacity,
        )
    }

    private fun appendSignatureObject(
        output: PdfOutput,
        revision: PdfSignatureRevision,
        signature: PdfDocumentIndex.Reference,
        capacity: Int,
    ): PlaceholderHoles {
        output.writeLatin1(signatureHeader(revision, signature))
        output.writeLatin1(BYTE_RANGE_PREFIX)
        val fieldOffsets = IntArray(PdfFormat.BYTE_RANGE_FIELD_COUNT)
        for (index in fieldOffsets.indices) {
            output.writeLatin1(BYTE_RANGE_FIELD_SEPARATOR)
            fieldOffsets[index] = output.size
            output.writeLatin1(BYTE_RANGE_ZERO_FIELD)
        }
        output.writeLatin1(BYTE_RANGE_SUFFIX)
        output.writeLatin1(CONTENTS_PREFIX)
        val contentsOpen = output.size
        output.writeByte(HEX_OPEN_DELIMITER)
        output.writeRepeated(
            byte = ZERO_HEX_DIGIT,
            count = Math.multiplyExact(capacity, PdfFormat.HEX_CHARACTERS_PER_BYTE),
        )
        output.writeByte(HEX_CLOSE_DELIMITER)
        output.writeLatin1(SIGNATURE_OBJECT_SUFFIX)
        return PlaceholderHoles(
            byteRangeFieldOffsets = fieldOffsets,
            contentsOpen = contentsOpen,
        )
    }

    private fun signatureHeader(
        revision: PdfSignatureRevision,
        signature: PdfDocumentIndex.Reference,
    ): String =
        when (revision) {
            PdfSignatureRevision.DocumentTimestamp -> {
                signature.encodedObjectHeader() +
                    "<< /Type /DocTimeStamp /Filter /Adobe.PPKLite " +
                    "/SubFilter /ETSI.RFC3161\n"
            }

            is PdfSignatureRevision.Signature -> {
                validateClaim(revision.claim)
                buildString {
                    append(signature.encodedObjectHeader())
                    append("<< /Type /Sig /Filter /Adobe.PPKLite ")
                    append("/SubFilter /ETSI.CAdES.detached\n")
                    revision.claim.reason?.let { reason ->
                        append("/Reason ")
                        append(pdfTextString(reason))
                        append(LINE_FEED)
                    }
                    revision.claim.location?.let { location ->
                        append("/Location ")
                        append(pdfTextString(location))
                        append(LINE_FEED)
                    }
                    append("/M (")
                    append(pdfDate(revision.claim.signedAt))
                    append(")\n")
                }
            }
        }

    private fun widget(
        field: PdfDocumentIndex.Reference,
        signature: PdfDocumentIndex.Reference,
        page: PdfDocumentIndex.Reference,
    ): String =
        indirectObject(
            reference = field,
            body =
                "<< /Type /Annot /Subtype /Widget /FT /Sig " +
                    "/T (Signature${signature.number}) /V ${signature.encodedIndirectReference()} " +
                    "/P ${page.encodedIndirectReference()} /Rect [0 0 0 0] /F $SIGNATURE_WIDGET_FLAGS >>",
        )

    private fun indirectObject(
        reference: PdfDocumentIndex.Reference,
        body: String,
    ): String = "${reference.encodedObjectHeader()}$body\n${PdfFormat.END_OBJECT_KEYWORD}\n"

    internal fun crossReferenceSection(
        offsets: Map<PdfDocumentIndex.Reference, Int>,
        size: Int,
        root: PdfDocumentIndex.Reference,
        xrefOffset: Int,
        index: PdfDocumentIndex,
    ): String {
        val text = StringBuilder(PdfFormat.XREF_KEYWORD).append(LINE_FEED)
        for ((reference, offset) in offsets.entries.sortedBy { entry -> entry.key.number }) {
            text.append(reference.number).append(" 1\n")
            text.append(
                String.format(
                    Locale.ROOT,
                    XREF_ENTRY_FORMAT,
                    offset,
                    reference.generation,
                ),
            )
        }
        text.append(PdfFormat.TRAILER_KEYWORD).append(LINE_FEED)
        text.append(
            "<< ${PdfFormat.SIZE_KEY} $size ${PdfFormat.ROOT_KEY} ${root.encodedIndirectReference()}",
        )
        text.append(" ${PdfFormat.PREVIOUS_XREF_KEY} ${index.previousStartXref}")
        text.append(carriedTrailerEntries(index.trailer))
        text.append(" >>\n${PdfFormat.START_XREF_KEYWORD}\n$xrefOffset\n")
        text.append(PdfFormat.END_OF_FILE_MARKER).append(LINE_FEED)
        return text.toString()
    }

    private fun carriedTrailerEntries(trailer: String): String {
        val syntax = PdfDictionarySyntax(trailer)
        val carried = StringBuilder()
        syntax.entry(TRAILER_IDENTIFIER_NAME)?.let { identifier ->
            carried.append(" /$TRAILER_IDENTIFIER_NAME ").append(syntax.value(identifier))
        }
        syntax.entry(TRAILER_INFO_NAME)?.let { info ->
            val reference = PdfValueParser.reference(syntax.value(info)) ?: throw unreadable()
            carried.append(" /$TRAILER_INFO_NAME ").append(reference.encodedIndirectReference())
        }
        return carried.toString()
    }

    private fun patched(
        document: ByteArray,
        holes: PlaceholderHoles,
        capacity: Int,
    ): PdfSignaturePlaceholder {
        val hexLength = Math.multiplyExact(capacity, PdfFormat.HEX_CHARACTERS_PER_BYTE)
        val secondSpanStart =
            Math.addExact(
                holes.contentsOpen,
                Math.addExact(hexLength, PdfFormat.HEX_DELIMITER_COUNT),
            )
        val values =
            intArrayOf(
                FIRST_DOCUMENT_OFFSET,
                holes.contentsOpen,
                secondSpanStart,
                document.size - secondSpanStart,
            )
        for (index in values.indices) {
            patchDecimalField(
                document = document,
                offset = holes.byteRangeFieldOffsets[index],
                value = values[index],
            )
        }
        return PdfSignaturePlaceholder(
            document = document,
            contentsOpen = holes.contentsOpen,
            secondSpanStart = secondSpanStart,
            capacity = capacity,
        )
    }

    private fun patchDecimalField(
        document: ByteArray,
        offset: Int,
        value: Int,
    ) {
        val text = value.toString()
        if (value < MINIMUM_BYTE_RANGE_VALUE || text.length > PdfFormat.BYTE_RANGE_DIGITS) {
            throw unreadable()
        }
        val padding = PdfFormat.BYTE_RANGE_DIGITS - text.length
        repeat(padding) { index ->
            document[offset + index] = SPACE_BYTE
        }
        text.encodeToByteArray().copyInto(document, destinationOffset = offset + padding)
    }

    private fun validateClaim(claim: PdfSignatureClaim) {
        if (
            claim.reason?.let(::isValidClaimText) == false ||
            claim.location?.let(::isValidClaimText) == false
        ) {
            throw claimMalformed()
        }
        pdfDate(claim.signedAt)
    }

    private fun isValidClaimText(text: String): Boolean {
        if (text.length > MAXIMUM_CLAIM_TEXT_LENGTH) {
            return false
        }
        var index = FIRST_TEXT_OFFSET
        while (index < text.length) {
            val character = text[index]
            when {
                character.isHighSurrogate() -> {
                    if (index + SURROGATE_PAIR_TRAIL_OFFSET >= text.length) {
                        return false
                    }
                    if (!text[index + SURROGATE_PAIR_TRAIL_OFFSET].isLowSurrogate()) {
                        return false
                    }
                    index += SURROGATE_PAIR_LENGTH
                }

                character.isLowSurrogate() -> {
                    return false
                }

                else -> {
                    index += TEXT_OFFSET_STEP
                }
            }
        }
        return true
    }

    private fun pdfTextString(text: String): String {
        if (!isValidClaimText(text)) {
            throw claimMalformed()
        }
        val encoded = UTF16_BIG_ENDIAN_BOM + text.toByteArray(Charsets.UTF_16BE)
        return buildString(HEX_STRING_DELIMITER_COUNT + encoded.size * PdfFormat.HEX_CHARACTERS_PER_BYTE) {
            append(HEX_OPEN_DELIMITER.toInt().toChar())
            for (byte in encoded) {
                val unsigned = byte.toUByte().toInt()
                append(PdfFormat.HEX_DIGIT_TEXT[unsigned ushr PdfFormat.HEX_DIGIT_BITS])
                append(PdfFormat.HEX_DIGIT_TEXT[unsigned and PdfFormat.HEX_DIGIT_MASK])
            }
            append(HEX_CLOSE_DELIMITER.toInt().toChar())
        }
    }

    private fun pdfDate(instant: Instant): String {
        val date =
            try {
                ZonedDateTime.ofInstant(instant, ZoneOffset.UTC)
            } catch (_: DateTimeException) {
                throw claimMalformed()
            }
        if (date.year !in MINIMUM_PDF_YEAR..MAXIMUM_PDF_YEAR) {
            throw claimMalformed()
        }
        return String.format(
            Locale.ROOT,
            PDF_DATE_FORMAT,
            date.year,
            date.monthValue,
            date.dayOfMonth,
            date.hour,
            date.minute,
            date.second,
        )
    }

    private fun increment(value: Int): Int =
        try {
            Math.incrementExact(value)
        } catch (_: ArithmeticException) {
            throw unreadable()
        }

    private fun claimMalformed(): PdfSigningException = PdfSigningException(PdfSigningFailure.SIGNATURE_CLAIM_MALFORMED)

    private fun unreadable(): PdfSigningException = PdfSigningException(PdfSigningFailure.STRUCTURE_UNREADABLE)

    private data class PlaceholderHoles(
        val byteRangeFieldOffsets: IntArray,
        val contentsOpen: Int,
    )

    private class PdfOutput(
        initialCapacity: Int,
    ) {
        private val output = ByteArrayOutputStream(initialCapacity)

        val size: Int
            get() = output.size()

        fun write(bytes: ByteArray) {
            output.write(bytes)
        }

        fun writeByte(byte: Byte) {
            output.write(byte.toUByte().toInt())
        }

        fun writeRepeated(
            byte: Byte,
            count: Int,
        ) {
            repeat(count) {
                writeByte(byte)
            }
        }

        fun writeLatin1(text: String) {
            val bytes = PdfValueLexemes.strictLatin1(text) ?: throw unreadable()
            write(bytes)
        }

        fun ensureLineTerminated() {
            val bytes = output.toByteArray()
            if (bytes.lastOrNull() != PdfFormat.LINE_FEED_BYTE) {
                writeByte(PdfFormat.LINE_FEED_BYTE)
            }
        }

        fun toByteArray(): ByteArray = output.toByteArray()
    }

    private const val BYTE_RANGE_PREFIX = "/ByteRange ["
    private const val BYTE_RANGE_FIELD_SEPARATOR = " "
    private const val BYTE_RANGE_SUFFIX = " ]\n"
    private const val CONTENTS_PREFIX = "/Contents "
    private const val SIGNATURE_OBJECT_SUFFIX = "\n>>\nendobj\n"
    private const val XREF_ENTRY_FORMAT = "%010d %05d n \n"
    private const val PDF_DATE_FORMAT = "D:%04d%02d%02d%02d%02d%02d+00'00'"
    private const val TRAILER_IDENTIFIER_NAME = "ID"
    private const val TRAILER_INFO_NAME = "Info"
    private const val LINE_FEED = '\n'
    private const val MINIMUM_NEW_OBJECT_NUMBER = 1
    private const val NEW_OBJECT_GENERATION = 0
    private const val MINIMUM_BYTE_RANGE_VALUE = 0
    private const val FIRST_DOCUMENT_OFFSET = 0
    private const val FIRST_TEXT_OFFSET = 0
    private const val TEXT_OFFSET_STEP = 1
    private const val SURROGATE_PAIR_TRAIL_OFFSET = 1
    private const val SURROGATE_PAIR_LENGTH = 2
    private const val MAXIMUM_CLAIM_TEXT_LENGTH = 1_024
    private const val MINIMUM_PDF_YEAR = 1
    private const val MAXIMUM_PDF_YEAR = 9_999
    private const val SIGNATURE_WIDGET_PRINT_FLAG = 4
    private const val SIGNATURE_WIDGET_LOCKED_FLAG = 128
    private const val SIGNATURE_WIDGET_FLAGS =
        SIGNATURE_WIDGET_PRINT_FLAG or SIGNATURE_WIDGET_LOCKED_FLAG
    private const val HEX_STRING_DELIMITER_COUNT = 2
    private val BYTE_RANGE_ZERO_FIELD = "0".repeat(PdfFormat.BYTE_RANGE_DIGITS)
    private val HEX_OPEN_DELIMITER = '<'.code.toByte()
    private val HEX_CLOSE_DELIMITER = '>'.code.toByte()
    private val ZERO_HEX_DIGIT = '0'.code.toByte()
    private val SPACE_BYTE = ' '.code.toByte()
    private val UTF16_BIG_ENDIAN_BOM =
        byteArrayOf(
            0xFE.toByte(),
            0xFF.toByte(),
        )
}
