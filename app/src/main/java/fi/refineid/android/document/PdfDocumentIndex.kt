// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** The bounded cross-reference chain needed to append one PDF revision. */
internal class PdfDocumentIndex private constructor(
    private val locations: Map<Int, ObjectLocation>,
    val trailer: String,
    val previousStartXref: Int,
    val highestObjectNumber: Int,
    val newestSectionIsStream: Boolean,
) {
    data class Reference(
        val number: Int,
        val generation: Int,
    ) {
        fun encodedIndirectReference(): String = "$number $generation $REFERENCE_MARKER"

        fun encodedObjectHeader(): String = "$number $generation ${PdfFormat.OBJECT_KEYWORD}\n"

        private companion object {
            const val REFERENCE_MARKER = "R"
        }
    }

    private sealed interface ObjectLocation {
        data class Direct(
            val offset: Int,
            val generation: Int,
        ) : ObjectLocation

        data class Compressed(
            val container: Int,
            val position: Int,
        ) : ObjectLocation
    }

    private data class SectionRecord(
        val number: Int,
        val location: ObjectLocation?,
    )

    private data class Section(
        val records: List<SectionRecord>,
        val trailer: String,
        val isStream: Boolean,
    )

    private data class ObjectStreamEntry(
        val number: Int,
        val relativeOffset: Int,
    )

    private data class ObjectStreamDescriptor(
        val first: Int,
        val count: Int,
        val entries: List<ObjectStreamEntry>,
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

            is ObjectLocation.Compressed -> {
                compressedBody(
                    number = number,
                    container = location.container,
                    position = location.position,
                    document = document,
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

            is ObjectLocation.Compressed -> {
                if (reference.generation != COMPRESSED_OBJECT_GENERATION) {
                    null
                } else {
                    compressedBody(
                        number = reference.number,
                        container = location.container,
                        position = location.position,
                        document = document,
                    )
                }
            }

            null -> {
                null
            }
        }

    private fun compressedBody(
        number: Int,
        container: Int,
        position: Int,
        document: ByteArray,
    ): String? {
        val stream = objectStream(container, document) ?: return null
        val descriptor = objectStreamDescriptor(stream) ?: return null
        val first = descriptor.first
        val count = descriptor.count
        if (position !in FIRST_OBJECT_STREAM_POSITION until count) {
            return null
        }
        val entry = descriptor.entries[position]
        if (entry.number != number) {
            return null
        }
        val nextOffset =
            descriptor.entries.getOrNull(position + OBJECT_STREAM_POSITION_STEP)?.relativeOffset
                ?: (stream.payload.size - first)
        val bodyStart = safeAdd(first, entry.relativeOffset) ?: return null
        val bodyEnd = safeAdd(first, nextOffset) ?: return null
        if (bodyStart > bodyEnd || bodyEnd > stream.payload.size) {
            return null
        }
        return PdfBytes(stream.payload)
            .text(PdfBytes.Range(start = bodyStart, endExclusive = bodyEnd))
            .trim()
    }

    private fun objectStream(
        container: Int,
        document: ByteArray,
    ): PdfStreamObject? {
        val location = locations[container] as? ObjectLocation.Direct ?: return null
        return try {
            PdfStreamObject.parse(
                bytes = PdfBytes(document),
                offset = location.offset,
                expected = Reference(container, location.generation),
            )
        } catch (_: PdfSigningException) {
            null
        }
    }

    private fun objectStreamDescriptor(stream: PdfStreamObject): ObjectStreamDescriptor? {
        val syntax = dictionarySyntaxOrNull(stream.dictionary) ?: return null
        val typeName = dictionaryKeyName(PdfFormat.TYPE_KEY) ?: return null
        val typeEntry = syntax.entry(typeName) ?: return null
        if (PdfValueLexemes.name(syntax.value(typeEntry)) != PdfFormat.OBJECT_STREAM_TYPE_NAME) {
            return null
        }
        val first = integer(PdfFormat.OBJECT_STREAM_FIRST_KEY, stream.dictionary) ?: return null
        val count = integer(PdfFormat.OBJECT_STREAM_COUNT_KEY, stream.dictionary) ?: return null
        if (first > stream.payload.size) {
            return null
        }
        val entries = objectStreamEntries(stream.payload, first, count) ?: return null
        return ObjectStreamDescriptor(first = first, count = count, entries = entries)
    }

    private fun objectStreamEntries(
        payload: ByteArray,
        first: Int,
        count: Int,
    ): List<ObjectStreamEntry>? {
        val expectedTokenCount =
            try {
                Math.multiplyExact(count, PdfFormat.OBJECT_STREAM_PAIR_TOKEN_COUNT)
            } catch (_: ArithmeticException) {
                return null
            }
        val header = PdfBytes(payload).text(PdfBytes.Range(start = FIRST_BYTE_OFFSET, endExclusive = first))
        val tokens = header.split(Regex(WHITESPACE_PATTERN)).filter(String::isNotEmpty)
        if (tokens.size != expectedTokenCount) {
            return null
        }
        val entries = mutableListOf<ObjectStreamEntry>()
        val objectNumbers = mutableSetOf<Int>()
        var previousOffset = FIRST_RELATIVE_OBJECT_OFFSET
        repeat(count) { position ->
            val tokenOffset = position * PdfFormat.OBJECT_STREAM_PAIR_TOKEN_COUNT
            val objectNumber = tokens[tokenOffset].toIntOrNull() ?: return null
            val relativeOffset =
                tokens[tokenOffset + OBJECT_STREAM_OFFSET_TOKEN_OFFSET].toIntOrNull() ?: return null
            if (
                objectNumber < MINIMUM_OBJECT_NUMBER ||
                !objectNumbers.add(objectNumber) ||
                relativeOffset < previousOffset ||
                relativeOffset > payload.size - first
            ) {
                return null
            }
            entries += ObjectStreamEntry(objectNumber, relativeOffset)
            previousOffset = relativeOffset
        }
        return entries
    }

    private fun safeAdd(
        left: Int,
        right: Int,
    ): Int? =
        try {
            Math.addExact(left, right)
        } catch (_: ArithmeticException) {
            null
        }

    companion object {
        fun integer(
            key: String,
            dictionary: String,
        ): Int? {
            val syntax = dictionarySyntaxOrNull(dictionary) ?: return null
            val entry = syntax.entry(dictionaryKeyName(key) ?: return null) ?: return null
            return PdfValueParser.unsignedInteger(syntax.value(entry))
        }

        fun reference(
            key: String,
            dictionary: String,
        ): Reference? {
            val syntax = dictionarySyntaxOrNull(dictionary) ?: return null
            val entry = syntax.entry(dictionaryKeyName(key) ?: return null) ?: return null
            return PdfValueParser.reference(syntax.value(entry))
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
            var newestSectionIsStream = false
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
                val section = section(bytes, offset)
                if (newestTrailer == null) {
                    newestTrailer = section.trailer
                    newestSectionIsStream = section.isStream
                }
                for (record in section.records) {
                    if (claimed.add(record.number) && record.location != null) {
                        collected[record.number] = record.location
                    }
                }
                val syntax = PdfDictionarySyntax(section.trailer)
                val encryptName = dictionaryKeyName(PdfFormat.ENCRYPT_KEY) ?: throw unreadable()
                if (syntax.entry(encryptName) != null) {
                    throw failure(PdfSigningFailure.ENCRYPTED)
                }
                val previousName =
                    dictionaryKeyName(PdfFormat.PREVIOUS_XREF_KEY) ?: throw unreadable()
                offset =
                    syntax.entry(previousName)?.let { entry ->
                        PdfValueParser.unsignedInteger(syntax.value(entry)) ?: throw unreadable()
                    }
            }
            val newest = newestTrailer ?: throw unreadable()
            return PdfDocumentIndex(
                locations = collected,
                trailer = newest,
                previousStartXref = startXref,
                highestObjectNumber = claimed.maxOrNull() ?: MINIMUM_OBJECT_NUMBER,
                newestSectionIsStream = newestSectionIsStream,
            )
        }

        private fun dictionarySyntaxOrNull(dictionary: String): PdfDictionarySyntax? =
            try {
                PdfDictionarySyntax(dictionary)
            } catch (_: PdfSigningException) {
                null
            }

        private fun dictionaryKeyName(key: String): String? =
            key
                .takeIf { candidate -> candidate.startsWith(NAME_PREFIX) }
                ?.drop(NAME_PREFIX.length)
                ?.takeIf(String::isNotEmpty)

        private fun startXref(bytes: PdfBytes): Int? {
            val found = bytes.lastRange(PdfFormat.START_XREF_KEYWORD) ?: return null
            return bytes.decimal(bytes.skippingWhitespace(found.endExclusive))
        }

        private fun section(
            bytes: PdfBytes,
            offset: Int,
        ): Section {
            if (offset !in FIRST_BYTE_OFFSET until bytes.size) {
                throw unreadable()
            }
            val start = bytes.skippingWhitespace(offset)
            if (!bytes.hasToken(PdfFormat.XREF_KEYWORD, start)) {
                return streamSection(bytes, start)
            }
            return tableSection(bytes, start)
        }

        private fun tableSection(
            bytes: PdfBytes,
            start: Int,
        ): Section {
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
            val syntax = PdfDictionarySyntax(trailer.first)
            val hybridName = dictionaryKeyName(PdfFormat.XREF_STREAM_KEY) ?: throw unreadable()
            val combinedRecords =
                syntax.entry(hybridName)?.let { entry ->
                    val streamOffset =
                        PdfValueParser.unsignedInteger(syntax.value(entry)) ?: throw unreadable()
                    val stream = streamSection(bytes, streamOffset)
                    val streamSyntax = PdfDictionarySyntax(stream.trailer)
                    val encryptName = dictionaryKeyName(PdfFormat.ENCRYPT_KEY) ?: throw unreadable()
                    if (streamSyntax.entry(encryptName) != null) {
                        throw failure(PdfSigningFailure.ENCRYPTED)
                    }
                    stream.records + records
                } ?: records
            return Section(
                records = combinedRecords,
                trailer = trailer.first,
                isStream = false,
            )
        }

        private fun streamSection(
            bytes: PdfBytes,
            start: Int,
        ): Section {
            val stream = PdfStreamObject.parse(bytes, start)
            val syntax = PdfDictionarySyntax(stream.dictionary)
            val typeName = dictionaryKeyName(PdfFormat.TYPE_KEY) ?: throw unreadable()
            val type =
                syntax.entry(typeName)?.let { entry ->
                    PdfValueLexemes.name(syntax.value(entry))
                }
            if (type != PdfFormat.XREF_STREAM_TYPE_NAME) {
                throw unreadable()
            }
            val widthsName = dictionaryKeyName(PdfFormat.XREF_STREAM_WIDTHS_KEY) ?: throw unreadable()
            val widths =
                syntax.entry(widthsName)?.let { entry ->
                    PdfValueParser.unsignedIntegerArray(syntax.value(entry))
                } ?: throw unreadable()
            if (widths.size != PdfFormat.XREF_STREAM_FIELD_COUNT) {
                throw unreadable()
            }
            val sizeName = dictionaryKeyName(PdfFormat.SIZE_KEY) ?: throw unreadable()
            val size =
                syntax.entry(sizeName)?.let { entry ->
                    PdfValueParser.unsignedInteger(syntax.value(entry))
                } ?: throw unreadable()
            if (size < MINIMUM_XREF_STREAM_SIZE) {
                throw unreadable()
            }
            val indexName = dictionaryKeyName(PdfFormat.XREF_STREAM_INDEX_KEY) ?: throw unreadable()
            val subsections =
                syntax.entry(indexName)?.let { entry ->
                    PdfValueParser
                        .unsignedIntegerArray(syntax.value(entry))
                        ?.takeIf(List<Int>::isNotEmpty)
                        ?: throw unreadable()
                } ?: listOf(MINIMUM_OBJECT_NUMBER, size)
            return Section(
                records = streamRecords(stream.payload, widths, subsections, size),
                trailer = stream.dictionary,
                isStream = true,
            )
        }

        private fun streamRecords(
            payload: ByteArray,
            widths: List<Int>,
            subsections: List<Int>,
            size: Int,
        ): List<SectionRecord> {
            if (
                widths.any { width -> width > PdfFormat.XREF_STREAM_MAXIMUM_FIELD_WIDTH_BYTES } ||
                subsections.size % PdfFormat.XREF_SUBSECTION_HEADER_TOKEN_COUNT != COMPLETE_PAIR_REMAINDER
            ) {
                throw unreadable()
            }
            val rowLength =
                widths.fold(INITIAL_ROW_LENGTH) { length, width ->
                    try {
                        Math.addExact(length, width)
                    } catch (_: ArithmeticException) {
                        throw unreadable()
                    }
                }
            if (rowLength <= EMPTY_ROW_LENGTH) {
                throw unreadable()
            }
            var expectedPayloadLength = EMPTY_PAYLOAD_LENGTH
            var subsectionOffset = FIRST_SUBSECTION_OFFSET
            while (subsectionOffset < subsections.size) {
                val first = subsections[subsectionOffset]
                val count = subsections[subsectionOffset + SUBSECTION_COUNT_TOKEN_OFFSET]
                val endExclusive =
                    try {
                        Math.addExact(first, count)
                    } catch (_: ArithmeticException) {
                        throw unreadable()
                    }
                if (endExclusive > size) {
                    throw unreadable()
                }
                expectedPayloadLength =
                    try {
                        Math.addExact(expectedPayloadLength, Math.multiplyExact(count, rowLength))
                    } catch (_: ArithmeticException) {
                        throw unreadable()
                    }
                subsectionOffset += PdfFormat.XREF_SUBSECTION_HEADER_TOKEN_COUNT
            }
            if (expectedPayloadLength != payload.size) {
                throw unreadable()
            }

            val records = mutableListOf<SectionRecord>()
            val objectNumbers = mutableSetOf<Int>()
            var cursor = FIRST_BYTE_OFFSET
            subsectionOffset = FIRST_SUBSECTION_OFFSET
            while (subsectionOffset < subsections.size) {
                val first = subsections[subsectionOffset]
                val count = subsections[subsectionOffset + SUBSECTION_COUNT_TOKEN_OFFSET]
                repeat(count) { entryOffset ->
                    val number =
                        try {
                            Math.addExact(first, entryOffset)
                        } catch (_: ArithmeticException) {
                            throw unreadable()
                        }
                    val fields = streamEntryFields(payload, cursor, widths)
                    cursor += rowLength
                    if (!objectNumbers.add(number)) {
                        throw unreadable()
                    }
                    records += streamRecord(number, fields)
                }
                subsectionOffset += PdfFormat.XREF_SUBSECTION_HEADER_TOKEN_COUNT
            }
            return records
        }

        private fun streamEntryFields(
            payload: ByteArray,
            cursor: Int,
            widths: List<Int>,
        ): List<Int> {
            val fields = mutableListOf<Int>()
            var fieldOffset = cursor
            widths.forEachIndexed { fieldIndex, width ->
                var value = INITIAL_UNSIGNED_FIELD_VALUE
                repeat(width) {
                    value =
                        (value shl Byte.SIZE_BITS) or
                        payload[fieldOffset].toUByte().toULong()
                    fieldOffset += BYTE_OFFSET_STEP
                }
                val decoded =
                    if (
                        fieldIndex == PdfFormat.XREF_STREAM_TYPE_FIELD_INDEX &&
                        width == EMPTY_FIELD_WIDTH
                    ) {
                        PdfFormat.XREF_STREAM_DIRECT_ENTRY_TYPE
                    } else {
                        if (value > Int.MAX_VALUE.toULong()) {
                            throw unreadable()
                        }
                        value.toInt()
                    }
                fields += decoded
            }
            return fields
        }

        private fun streamRecord(
            number: Int,
            fields: List<Int>,
        ): SectionRecord =
            when (fields[PdfFormat.XREF_STREAM_TYPE_FIELD_INDEX]) {
                PdfFormat.XREF_STREAM_DIRECT_ENTRY_TYPE -> {
                    val generation = fields[PdfFormat.XREF_STREAM_SECOND_FIELD_INDEX]
                    if (generation !in MINIMUM_GENERATION..MAXIMUM_GENERATION) {
                        throw unreadable()
                    }
                    SectionRecord(
                        number = number,
                        location =
                            ObjectLocation.Direct(
                                offset = fields[PdfFormat.XREF_STREAM_FIRST_FIELD_INDEX],
                                generation = generation,
                            ),
                    )
                }

                PdfFormat.XREF_STREAM_COMPRESSED_ENTRY_TYPE -> {
                    if (number == MINIMUM_OBJECT_NUMBER) {
                        throw unreadable()
                    }
                    SectionRecord(
                        number = number,
                        location =
                            ObjectLocation.Compressed(
                                container = fields[PdfFormat.XREF_STREAM_FIRST_FIELD_INDEX],
                                position = fields[PdfFormat.XREF_STREAM_SECOND_FIELD_INDEX],
                            ),
                    )
                }

                else -> {
                    // Unknown entry types are forward-compatible null references.
                    SectionRecord(number = number, location = null)
                }
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

        private const val NAME_PREFIX = "/"
        private const val WHITESPACE_PATTERN = "[\\u0000\\u0009\\u000A\\u000C\\u000D\\u0020]+"
        private const val FIRST_BYTE_OFFSET = 0
        private const val INITIAL_CHAIN_DEPTH = 0
        private const val CHAIN_DEPTH_STEP = 1
        private const val FIRST_TOKEN_INDEX = 0
        private const val SUBSECTION_COUNT_TOKEN_OFFSET = 1
        private const val MINIMUM_OBJECT_NUMBER = 0
        private const val MINIMUM_SUBSECTION_COUNT = 0
        private const val MINIMUM_GENERATION = 0
        private const val MAXIMUM_GENERATION = 65_535
        private const val COMPRESSED_OBJECT_GENERATION = 0
        private const val FIRST_OBJECT_STREAM_POSITION = 0
        private const val OBJECT_STREAM_POSITION_STEP = 1
        private const val OBJECT_STREAM_OFFSET_TOKEN_OFFSET = 1
        private const val FIRST_RELATIVE_OBJECT_OFFSET = 0
        private const val MINIMUM_XREF_STREAM_SIZE = 1
        private const val COMPLETE_PAIR_REMAINDER = 0
        private const val INITIAL_ROW_LENGTH = 0
        private const val EMPTY_ROW_LENGTH = 0
        private const val EMPTY_PAYLOAD_LENGTH = 0
        private const val FIRST_SUBSECTION_OFFSET = 0
        private const val EMPTY_FIELD_WIDTH = 0
        private const val BYTE_OFFSET_STEP = 1
        private const val INITIAL_UNSIGNED_FIELD_VALUE: ULong = 0UL
    }
}
