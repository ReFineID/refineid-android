// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.io.ByteArrayOutputStream
import java.util.Locale

/** Writes the table or stream closing one byte-preserving incremental revision. */
internal object PdfCrossReferenceSectionWriter {
    fun write(
        offsets: Map<PdfDocumentIndex.Reference, Int>,
        size: Int,
        root: PdfDocumentIndex.Reference,
        xrefOffset: Int,
        index: PdfDocumentIndex,
    ): ByteArray =
        if (index.newestSectionIsStream) {
            stream(offsets, size, root, xrefOffset, index)
        } else {
            table(offsets, size, root, xrefOffset, index)
        }

    private fun table(
        offsets: Map<PdfDocumentIndex.Reference, Int>,
        size: Int,
        root: PdfDocumentIndex.Reference,
        xrefOffset: Int,
        index: PdfDocumentIndex,
    ): ByteArray {
        val text = StringBuilder(PdfFormat.XREF_KEYWORD).append(LINE_FEED)
        for ((reference, offset) in offsets.entries.sortedBy { entry -> entry.key.number }) {
            text.append(reference.number).append(TABLE_SINGLE_ENTRY_SUBSECTION)
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
        return PdfValueLexemes.strictLatin1(text.toString()) ?: throw unreadable()
    }

    private fun stream(
        offsets: Map<PdfDocumentIndex.Reference, Int>,
        size: Int,
        root: PdfDocumentIndex.Reference,
        xrefOffset: Int,
        index: PdfDocumentIndex,
    ): ByteArray {
        val streamReference = PdfDocumentIndex.Reference(size, NEW_OBJECT_GENERATION)
        val entries =
            offsets
                .map { (reference, offset) -> StreamEntry(reference, offset) }
                .plus(StreamEntry(streamReference, xrefOffset))
                .sortedBy { entry -> entry.reference.number }
        val objectNumbers = mutableSetOf<Int>()
        val rows = ByteArrayOutputStream()
        val indexEntries = StringBuilder()
        for (entry in entries) {
            validate(entry, objectNumbers)
            indexEntries
                .append(entry.reference.number)
                .append(STREAM_SINGLE_ENTRY_SUBSECTION)
            rows.write(PdfFormat.XREF_STREAM_DIRECT_ENTRY_TYPE)
            writeBigEndian(rows, entry.offset, PdfFormat.XREF_STREAM_OFFSET_WIDTH_BYTES)
            writeBigEndian(
                rows,
                entry.reference.generation,
                PdfFormat.XREF_STREAM_GENERATION_WIDTH_BYTES,
            )
        }
        val streamSize = increment(streamReference.number)
        val header =
            buildString {
                append(streamReference.encodedObjectHeader())
                append("<< ${PdfFormat.TYPE_KEY} /${PdfFormat.XREF_STREAM_TYPE_NAME}")
                append(" ${PdfFormat.SIZE_KEY} ")
                append(streamSize)
                append(" ${PdfFormat.ROOT_KEY} ")
                append(root.encodedIndirectReference())
                append(" ${PdfFormat.PREVIOUS_XREF_KEY} ")
                append(index.previousStartXref)
                append(carriedTrailerEntries(index.trailer))
                append(" ${PdfFormat.XREF_STREAM_INDEX_KEY} [ ")
                append(indexEntries)
                append("]")
                append(" ${PdfFormat.XREF_STREAM_WIDTHS_KEY} [")
                append(PdfFormat.XREF_STREAM_TYPE_WIDTH_BYTES)
                append(' ')
                append(PdfFormat.XREF_STREAM_OFFSET_WIDTH_BYTES)
                append(' ')
                append(PdfFormat.XREF_STREAM_GENERATION_WIDTH_BYTES)
                append("]")
                append(" ${PdfFormat.STREAM_LENGTH_KEY} ")
                append(rows.size())
                append(" >>\n${PdfFormat.STREAM_KEYWORD}\n")
            }
        val output = ByteArrayOutputStream()
        output.write(PdfValueLexemes.strictLatin1(header) ?: throw unreadable())
        rows.writeTo(output)
        val suffix =
            "\n${PdfFormat.END_STREAM_KEYWORD}\n${PdfFormat.END_OBJECT_KEYWORD}\n" +
                "${PdfFormat.START_XREF_KEYWORD}\n$xrefOffset\n" +
                "${PdfFormat.END_OF_FILE_MARKER}\n"
        output.write(PdfValueLexemes.strictLatin1(suffix) ?: throw unreadable())
        return output.toByteArray()
    }

    private fun validate(
        entry: StreamEntry,
        objectNumbers: MutableSet<Int>,
    ) {
        val reference = entry.reference
        if (
            reference.number < MINIMUM_OBJECT_NUMBER ||
            reference.generation !in MINIMUM_OBJECT_GENERATION..MAXIMUM_OBJECT_GENERATION ||
            entry.offset < FIRST_DOCUMENT_OFFSET ||
            !objectNumbers.add(reference.number)
        ) {
            throw unreadable()
        }
    }

    private fun writeBigEndian(
        output: ByteArrayOutputStream,
        value: Int,
        width: Int,
    ) {
        repeat(width) { byteIndex ->
            val shift = (width - byteIndex - MOST_SIGNIFICANT_BYTE_OFFSET) * Byte.SIZE_BITS
            output.write((value ushr shift) and PdfFormat.UNSIGNED_BYTE_MASK)
        }
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

    private fun increment(value: Int): Int =
        try {
            Math.incrementExact(value)
        } catch (_: ArithmeticException) {
            throw unreadable()
        }

    private fun unreadable(): PdfSigningException = PdfSigningException(PdfSigningFailure.STRUCTURE_UNREADABLE)

    private data class StreamEntry(
        val reference: PdfDocumentIndex.Reference,
        val offset: Int,
    )

    private const val XREF_ENTRY_FORMAT = "%010d %05d n \n"
    private const val TABLE_SINGLE_ENTRY_SUBSECTION = " 1\n"
    private const val STREAM_SINGLE_ENTRY_SUBSECTION = " 1 "
    private const val TRAILER_IDENTIFIER_NAME = "ID"
    private const val TRAILER_INFO_NAME = "Info"
    private const val LINE_FEED = '\n'
    private const val NEW_OBJECT_GENERATION = 0
    private const val MINIMUM_OBJECT_NUMBER = 0
    private const val MINIMUM_OBJECT_GENERATION = 0
    private const val MAXIMUM_OBJECT_GENERATION = 65_535
    private const val FIRST_DOCUMENT_OFFSET = 0
    private const val MOST_SIGNIFICANT_BYTE_OFFSET = 1
}
