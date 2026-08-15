// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** The classic cross-reference chain needed to append one PDF revision. */
internal class PdfDocumentIndex private constructor(
    private val locations: Map<Int, ObjectLocation>,
    val trailer: String,
    val previousStartXref: Int,
) {
    data class Reference(
        val number: Int,
        val generation: Int,
    ) {
        fun encoded(): String = "$number $generation $REFERENCE_MARKER"

        private companion object {
            const val REFERENCE_MARKER = "R"
        }
    }

    private sealed interface ObjectLocation {
        data class Direct(
            val offset: Int,
            val generation: Int,
        ) : ObjectLocation
    }

    private data class SectionRecord(
        val number: Int,
        val location: ObjectLocation?,
    )

    private data class Section(
        val records: List<SectionRecord>,
        val trailer: String,
    )

    fun body(
        number: Int,
        document: ByteArray,
    ): String? =
        when (val location = locations[number]) {
            is ObjectLocation.Direct -> {
                directBody(
                    expected = Reference(number, location.generation),
                    offset = location.offset,
                    bytes = PdfBytes(document),
                )
            }

            null -> {
                null
            }
        }

    fun body(
        reference: Reference,
        document: ByteArray,
    ): String? =
        when (val location = locations[reference.number]) {
            is ObjectLocation.Direct -> {
                if (location.generation != reference.generation) {
                    null
                } else {
                    directBody(reference, location.offset, PdfBytes(document))
                }
            }

            null -> {
                null
            }
        }

    companion object {
        fun integer(
            key: String,
            dictionary: String,
        ): Int? = dictionaryDecimalToken(key, dictionary)?.first

        fun reference(
            key: String,
            dictionary: String,
        ): Reference? {
            val token = dictionaryDecimalToken(key, dictionary) ?: return null
            val rest = dictionary.substring(token.second).dropWhile(::isPdfWhitespace)
            val generationText = rest.takeWhile(::isAsciiDigit)
            val generation = generationText.toIntOrNull() ?: return null
            if (generation !in MINIMUM_GENERATION..MAXIMUM_GENERATION) {
                return null
            }
            val afterGeneration = rest.drop(generationText.length).dropWhile(::isPdfWhitespace)
            val afterMarker = afterGeneration.getOrNull(REFERENCE_MARKER.length)
            if (
                !afterGeneration.startsWith(REFERENCE_MARKER) ||
                (afterMarker != null && !isDictionaryBoundary(afterMarker))
            ) {
                return null
            }
            return Reference(number = token.first, generation = generation)
        }

        fun parse(document: ByteArray): PdfDocumentIndex {
            val bytes = PdfBytes(document)
            if (!bytes.startsWith(PdfFormat.FILE_PREFIX)) {
                throw failure(PdfSigningFailure.NOT_A_PDF)
            }
            val startXref = startXref(bytes) ?: throw unreadable()
            val collected = mutableMapOf<Int, ObjectLocation>()
            val claimed = mutableSetOf<Int>()
            val visited = mutableSetOf<Int>()
            var newestTrailer: String? = null
            var offset: Int? = startXref
            var depth = INITIAL_CHAIN_DEPTH
            while (offset != null) {
                if (
                    depth >= PdfFormat.MAXIMUM_XREF_CHAIN_DEPTH ||
                    !visited.add(offset)
                ) {
                    throw unreadable()
                }
                depth += CHAIN_DEPTH_STEP
                val section = tableSection(bytes, offset)
                if (newestTrailer == null) {
                    newestTrailer = section.trailer
                }
                for (record in section.records) {
                    if (claimed.add(record.number) && record.location != null) {
                        collected[record.number] = record.location
                    }
                }
                val previous = integer(PdfFormat.PREVIOUS_XREF_KEY, section.trailer)
                if (
                    dictionaryValueStart(PdfFormat.PREVIOUS_XREF_KEY, section.trailer) != null &&
                    previous == null
                ) {
                    throw unreadable()
                }
                offset = previous
            }
            val newest = newestTrailer ?: throw unreadable()
            if (dictionaryValueStart(PdfFormat.ENCRYPT_KEY, newest) != null) {
                throw failure(PdfSigningFailure.ENCRYPTED)
            }
            return PdfDocumentIndex(
                locations = collected,
                trailer = newest,
                previousStartXref = startXref,
            )
        }

        private fun dictionaryDecimalToken(
            key: String,
            dictionary: String,
        ): Pair<Int, Int>? {
            var cursor = dictionaryValueStart(key, dictionary) ?: return null
            val digitsStart = cursor
            while (cursor < dictionary.length && isAsciiDigit(dictionary[cursor])) {
                cursor += TEXT_OFFSET_STEP
            }
            if (cursor == digitsStart) {
                return null
            }
            if (cursor < dictionary.length && !isDictionaryBoundary(dictionary[cursor])) {
                return null
            }
            val value = dictionary.substring(digitsStart, cursor).toIntOrNull() ?: return null
            return value to cursor
        }

        private fun dictionaryValueStart(
            key: String,
            dictionary: String,
        ): Int? {
            var searchFrom = FIRST_TEXT_OFFSET
            while (searchFrom < dictionary.length) {
                val keyStart = dictionary.indexOf(key, startIndex = searchFrom)
                if (keyStart == MISSING_INDEX) {
                    return null
                }
                var cursor = keyStart + key.length
                if (cursor < dictionary.length && isDictionaryBoundary(dictionary[cursor])) {
                    while (cursor < dictionary.length && isPdfWhitespace(dictionary[cursor])) {
                        cursor += TEXT_OFFSET_STEP
                    }
                    return cursor
                }
                searchFrom = keyStart + TEXT_OFFSET_STEP
            }
            return null
        }

        private fun isDictionaryBoundary(character: Char): Boolean =
            isPdfWhitespace(character) || character in PDF_DELIMITER_CHARACTERS

        private fun isPdfWhitespace(character: Char): Boolean = character in PDF_WHITESPACE_CHARACTERS

        private fun isAsciiDigit(character: Char): Boolean = character in ASCII_ZERO..ASCII_NINE

        private fun startXref(bytes: PdfBytes): Int? {
            val found = bytes.lastRange(PdfFormat.START_XREF_KEYWORD) ?: return null
            return bytes.decimal(bytes.skippingWhitespace(found.endExclusive))
        }

        private fun tableSection(
            bytes: PdfBytes,
            offset: Int,
        ): Section {
            if (offset !in FIRST_BYTE_OFFSET until bytes.size) {
                throw unreadable()
            }
            val start = bytes.skippingWhitespace(offset)
            if (!bytes.hasToken(PdfFormat.XREF_KEYWORD, start)) {
                throw failure(PdfSigningFailure.CROSS_REFERENCE_STREAM_UNSUPPORTED)
            }
            val trailerRange =
                bytes.firstRange(
                    keyword = PdfFormat.TRAILER_KEYWORD,
                    from = start + PdfFormat.XREF_KEYWORD.length,
                ) ?: throw unreadable()
            val records =
                records(
                    bytes.text(
                        PdfBytes.Range(
                            start = start + PdfFormat.XREF_KEYWORD.length,
                            endExclusive = trailerRange.start,
                        ),
                    ),
                )
            val trailer =
                bytes.balancedDictionary(trailerRange.endExclusive)
                    ?: throw unreadable()
            return Section(records = records, trailer = trailer.first)
        }

        private fun records(text: String): List<SectionRecord> {
            val tokens = text.split(Regex(WHITESPACE_PATTERN)).filter(String::isNotEmpty)
            val records = mutableListOf<SectionRecord>()
            val objectNumbers = mutableSetOf<Int>()
            var index = FIRST_TOKEN_INDEX
            while (index < tokens.size) {
                if (tokens.size - index < PdfFormat.XREF_SUBSECTION_HEADER_TOKEN_COUNT) {
                    throw unreadable()
                }
                val first = tokens[index].toIntOrNull() ?: throw unreadable()
                val count = tokens[index + SUBSECTION_COUNT_TOKEN_OFFSET].toIntOrNull() ?: throw unreadable()
                if (first < MINIMUM_OBJECT_NUMBER || count < MINIMUM_SUBSECTION_COUNT) {
                    throw unreadable()
                }
                index += PdfFormat.XREF_SUBSECTION_HEADER_TOKEN_COUNT
                val availableEntries = (tokens.size - index) / PdfFormat.XREF_ENTRY_TOKEN_COUNT
                if (count > availableEntries) {
                    throw unreadable()
                }
                repeat(count) { entry ->
                    val offset = tokens[index + PdfFormat.XREF_ENTRY_OFFSET_INDEX].toIntOrNull()
                    val generation =
                        tokens[index + PdfFormat.XREF_ENTRY_GENERATION_INDEX].toIntOrNull()
                    val flag = tokens[index + PdfFormat.XREF_ENTRY_FLAG_INDEX]
                    val number =
                        try {
                            Math.addExact(first, entry)
                        } catch (_: ArithmeticException) {
                            throw unreadable()
                        }
                    val location =
                        when {
                            flag == PdfFormat.XREF_IN_USE_FLAG &&
                                offset != null &&
                                offset >= FIRST_BYTE_OFFSET &&
                                generation != null &&
                                generation in MINIMUM_GENERATION..MAXIMUM_GENERATION -> {
                                ObjectLocation.Direct(offset, generation)
                            }

                            flag == PdfFormat.XREF_FREE_FLAG &&
                                generation != null &&
                                generation in MINIMUM_GENERATION..MAXIMUM_GENERATION -> {
                                null
                            }

                            else -> {
                                throw unreadable()
                            }
                        }
                    if (!objectNumbers.add(number)) {
                        throw unreadable()
                    }
                    records.add(SectionRecord(number = number, location = location))
                    index += PdfFormat.XREF_ENTRY_TOKEN_COUNT
                }
            }
            return records
        }

        private fun directBody(
            expected: Reference,
            offset: Int,
            bytes: PdfBytes,
        ): String? {
            if (offset !in FIRST_BYTE_OFFSET until bytes.size) {
                return null
            }
            val number = bytes.decimalToken(bytes.skippingWhitespace(offset)) ?: return null
            if (number.value != expected.number) {
                return null
            }
            val generationAt = bytes.skippingWhitespace(number.endExclusive)
            val generation = bytes.decimalToken(generationAt) ?: return null
            if (generation.value != expected.generation) {
                return null
            }
            val objectAt = bytes.skippingWhitespace(generation.endExclusive)
            if (!bytes.hasToken(PdfFormat.OBJECT_KEYWORD, objectAt)) {
                return null
            }
            val bodyStart = objectAt + PdfFormat.OBJECT_KEYWORD.length
            val bodyEnd = bytes.firstRange(PdfFormat.END_OBJECT_KEYWORD, bodyStart) ?: return null
            return bytes.text(PdfBytes.Range(bodyStart, bodyEnd.start)).trim()
        }

        private fun failure(kind: PdfSigningFailure): PdfSigningException = PdfSigningException(kind)

        private fun unreadable(): PdfSigningException = failure(PdfSigningFailure.STRUCTURE_UNREADABLE)

        private const val REFERENCE_MARKER = "R"
        private const val WHITESPACE_PATTERN = "[\\u0000\\u0009\\u000A\\u000C\\u000D\\u0020]+"
        private const val PDF_WHITESPACE_CHARACTERS = "\u0000\u0009\u000A\u000C\u000D\u0020"
        private const val PDF_DELIMITER_CHARACTERS = "()<>[]{}/%"
        private const val ASCII_ZERO = '0'
        private const val ASCII_NINE = '9'
        private const val MISSING_INDEX = -1
        private const val FIRST_TEXT_OFFSET = 0
        private const val TEXT_OFFSET_STEP = 1
        private const val FIRST_BYTE_OFFSET = 0
        private const val INITIAL_CHAIN_DEPTH = 0
        private const val CHAIN_DEPTH_STEP = 1
        private const val FIRST_TOKEN_INDEX = 0
        private const val SUBSECTION_COUNT_TOKEN_OFFSET = 1
        private const val MINIMUM_OBJECT_NUMBER = 0
        private const val MINIMUM_SUBSECTION_COUNT = 0
        private const val MINIMUM_GENERATION = 0
        private const val MAXIMUM_GENERATION = 65_535
    }
}
