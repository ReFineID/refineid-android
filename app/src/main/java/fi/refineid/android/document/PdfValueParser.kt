// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** Bounded byte parser for the PDF value subset needed by incremental signing. */
internal class PdfValueParser(
    private val bytes: ByteArray,
) {
    data class DictionaryResult(
        val entries: List<PdfDictionaryEntry>,
        val closingOffset: Int,
    )

    private var offset = FIRST_BYTE_OFFSET

    fun dictionary(): DictionaryResult = dictionary(INITIAL_NESTING_DEPTH)

    fun requireEnd() {
        skipTrivia()
        if (offset != bytes.size) {
            throw unreadable()
        }
    }

    private fun dictionary(depth: Int): DictionaryResult {
        requireNestingDepth(depth)
        skipTrivia()
        if (!consume(PdfFormat.DICTIONARY_OPEN)) {
            throw unreadable()
        }
        val entries = mutableListOf<PdfDictionaryEntry>()
        val names = mutableSetOf<String>()
        while (true) {
            skipTrivia()
            val closingOffset = offset
            if (consume(PdfFormat.DICTIONARY_CLOSE)) {
                return DictionaryResult(entries = entries, closingOffset = closingOffset)
            }
            val name = name()
            if (!names.add(name.decoded)) {
                throw unreadable()
            }
            skipTrivia()
            val valueRange = value(depth + NESTING_DEPTH_STEP)
            entries.add(
                PdfDictionaryEntry(
                    name = name.decoded,
                    rawName = PdfValueLexemes.text(bytes, name.raw),
                    valueRange = valueRange,
                ),
            )
        }
    }

    private fun value(depth: Int): PdfBytes.Range {
        requireNestingDepth(depth)
        val start = offset
        when {
            has(PdfFormat.DICTIONARY_OPEN) -> {
                dictionary(depth)
            }

            consume(ARRAY_OPEN) -> {
                arrayRemainder(depth)
            }

            consume(LITERAL_STRING_OPEN) -> {
                literalStringRemainder()
            }

            consume(HEX_STRING_OPEN) -> {
                hexStringRemainder()
            }

            has(NAME_PREFIX) -> {
                name()
            }

            else -> {
                val first = atom()
                consumeReferenceTail(first)
            }
        }
        return PdfBytes.Range(start = start, endExclusive = offset)
    }

    private fun arrayRemainder(depth: Int) {
        while (true) {
            skipTrivia()
            if (consume(ARRAY_CLOSE)) {
                return
            }
            value(depth + NESTING_DEPTH_STEP)
        }
    }

    private fun literalStringRemainder() {
        var depth = INITIAL_LITERAL_STRING_DEPTH
        while (offset < bytes.size) {
            val byte = bytes[offset]
            offset += BYTE_OFFSET_STEP
            when (byte) {
                LITERAL_ESCAPE_BYTE -> {
                    if (offset < bytes.size) {
                        offset += BYTE_OFFSET_STEP
                    }
                }

                LITERAL_OPEN_BYTE -> {
                    depth += LITERAL_DEPTH_STEP
                    if (depth > MAXIMUM_LITERAL_STRING_DEPTH) {
                        throw unreadable()
                    }
                }

                LITERAL_CLOSE_BYTE -> {
                    depth -= LITERAL_DEPTH_STEP
                    if (depth == FINISHED_LITERAL_STRING_DEPTH) {
                        return
                    }
                }
            }
        }
        throw unreadable()
    }

    private fun hexStringRemainder() {
        while (offset < bytes.size) {
            val byte = bytes[offset]
            offset += BYTE_OFFSET_STEP
            if (byte == HEX_STRING_CLOSE_BYTE) {
                return
            }
        }
        throw unreadable()
    }

    private fun name(): ParsedName {
        val start = offset
        if (!consume(NAME_PREFIX)) {
            throw unreadable()
        }
        while (offset < bytes.size && !PdfValueLexemes.isDelimiter(bytes[offset])) {
            offset += BYTE_OFFSET_STEP
        }
        if (offset <= start + NAME_PREFIX_LENGTH) {
            throw unreadable()
        }
        val raw = PdfBytes.Range(start = start, endExclusive = offset)
        return ParsedName(
            decoded = PdfValueLexemes.decodedName(bytes, raw) ?: throw unreadable(),
            raw = raw,
        )
    }

    private fun atom(): PdfBytes.Range {
        return atomOrNull() ?: throw unreadable()
    }

    private fun atomOrNull(): PdfBytes.Range? {
        val start = offset
        while (offset < bytes.size && !PdfValueLexemes.isDelimiter(bytes[offset])) {
            offset += BYTE_OFFSET_STEP
        }
        if (offset == start) {
            return null
        }
        return PdfBytes.Range(start = start, endExclusive = offset)
    }

    private fun consumeReferenceTail(first: PdfBytes.Range) {
        if (PdfValueLexemes.unsignedInteger(bytes, first) == null) {
            return
        }
        val valueEnd = offset
        skipTrivia()
        val second = atomOrNull()
        if (second == null || PdfValueLexemes.unsignedInteger(bytes, second) == null) {
            offset = valueEnd
            return
        }
        skipTrivia()
        val marker = atomOrNull()
        if (marker == null || PdfValueLexemes.text(bytes, marker) != REFERENCE_MARKER) {
            offset = valueEnd
        }
    }

    private fun skipTrivia() {
        while (offset < bytes.size) {
            if (PdfValueLexemes.isWhitespace(bytes[offset])) {
                offset += BYTE_OFFSET_STEP
                continue
            }
            if (bytes[offset] != COMMENT_MARKER_BYTE) {
                return
            }
            while (
                offset < bytes.size &&
                bytes[offset] != PdfFormat.LINE_FEED_BYTE &&
                bytes[offset] != PdfFormat.CARRIAGE_RETURN_BYTE
            ) {
                offset += BYTE_OFFSET_STEP
            }
        }
    }

    private fun consume(marker: String): Boolean {
        if (!has(marker)) {
            return false
        }
        offset += marker.length
        return true
    }

    private fun has(marker: String): Boolean {
        val encoded = marker.encodeToByteArray()
        if (encoded.size > bytes.size - offset) {
            return false
        }
        return encoded.indices.all { index -> bytes[offset + index] == encoded[index] }
    }

    private fun requireNestingDepth(depth: Int) {
        if (depth > MAXIMUM_VALUE_NESTING_DEPTH) {
            throw unreadable()
        }
    }

    private fun referenceAtCurrent(): PdfDocumentIndex.Reference? {
        skipTrivia()
        val numberRange = atomOrNull() ?: return null
        val number = PdfValueLexemes.unsignedInteger(bytes, numberRange) ?: return null
        skipTrivia()
        val generationRange = atomOrNull() ?: return null
        val generation = PdfValueLexemes.unsignedInteger(bytes, generationRange) ?: return null
        if (generation !in MINIMUM_GENERATION..MAXIMUM_GENERATION) {
            return null
        }
        skipTrivia()
        val marker = atomOrNull() ?: return null
        if (PdfValueLexemes.text(bytes, marker) != REFERENCE_MARKER) {
            return null
        }
        return PdfDocumentIndex.Reference(number = number, generation = generation)
    }

    private data class ParsedName(
        val decoded: String,
        val raw: PdfBytes.Range,
    )

    companion object {
        fun reference(text: String): PdfDocumentIndex.Reference? {
            val encoded = PdfValueLexemes.strictLatin1(text) ?: return null
            val parser = PdfValueParser(encoded)
            val reference = parser.referenceAtCurrent() ?: return null
            return try {
                parser.requireEnd()
                reference
            } catch (_: PdfSigningException) {
                null
            }
        }

        fun referenceArray(text: String): List<PdfDocumentIndex.Reference>? {
            val encoded = PdfValueLexemes.strictLatin1(text) ?: return null
            val parser = PdfValueParser(encoded)
            parser.skipTrivia()
            if (!parser.consume(ARRAY_OPEN)) {
                return null
            }
            val references = mutableListOf<PdfDocumentIndex.Reference>()
            while (true) {
                parser.skipTrivia()
                if (parser.consume(ARRAY_CLOSE)) {
                    return try {
                        parser.requireEnd()
                        references
                    } catch (_: PdfSigningException) {
                        null
                    }
                }
                references.add(parser.referenceAtCurrent() ?: return null)
            }
        }

        fun unsignedInteger(text: String): Int? {
            val encoded = PdfValueLexemes.strictLatin1(text) ?: return null
            val parser = PdfValueParser(encoded)
            parser.skipTrivia()
            val range = parser.atomOrNull() ?: return null
            val value = PdfValueLexemes.unsignedInteger(encoded, range) ?: return null
            return try {
                parser.requireEnd()
                value
            } catch (_: PdfSigningException) {
                null
            }
        }

        fun isPlainName(name: String): Boolean = PdfValueLexemes.isPlainName(name)

        private fun unreadable(): PdfSigningException = PdfSigningException(PdfSigningFailure.STRUCTURE_UNREADABLE)

        private const val ARRAY_OPEN = "["
        private const val ARRAY_CLOSE = "]"
        private const val LITERAL_STRING_OPEN = "("
        private const val HEX_STRING_OPEN = "<"
        private const val NAME_PREFIX = "/"
        private const val REFERENCE_MARKER = "R"
        private const val FIRST_BYTE_OFFSET = 0
        private const val BYTE_OFFSET_STEP = 1
        private const val INITIAL_NESTING_DEPTH = 0
        private const val NESTING_DEPTH_STEP = 1
        private const val MAXIMUM_VALUE_NESTING_DEPTH = 64
        private const val INITIAL_LITERAL_STRING_DEPTH = 1
        private const val FINISHED_LITERAL_STRING_DEPTH = 0
        private const val LITERAL_DEPTH_STEP = 1
        private const val MAXIMUM_LITERAL_STRING_DEPTH = 1_024
        private const val NAME_PREFIX_LENGTH = 1
        private const val MINIMUM_GENERATION = 0
        private const val MAXIMUM_GENERATION = 65_535
        private val LITERAL_ESCAPE_BYTE = '\\'.code.toByte()
        private val LITERAL_OPEN_BYTE = '('.code.toByte()
        private val LITERAL_CLOSE_BYTE = ')'.code.toByte()
        private val HEX_STRING_CLOSE_BYTE = '>'.code.toByte()
        private val COMMENT_MARKER_BYTE = '%'.code.toByte()
    }
}
