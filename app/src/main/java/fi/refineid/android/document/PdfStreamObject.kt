// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** One bounded, decoded PDF stream object used by cross-reference and object streams. */
internal class PdfStreamObject private constructor(
    val reference: PdfDocumentIndex.Reference,
    val dictionary: String,
    val payload: ByteArray,
) {
    companion object {
        fun parse(
            bytes: PdfBytes,
            offset: Int,
            expected: PdfDocumentIndex.Reference? = null,
        ): PdfStreamObject {
            val start = bytes.skippingWhitespace(offset)
            val header = objectHeader(bytes, start) ?: throw unreadable()
            if (expected != null && header.reference != expected) {
                throw unreadable()
            }
            val dictionary = bytes.balancedDictionary(header.endExclusive) ?: throw unreadable()
            val syntax = PdfDictionarySyntax(dictionary.first)
            val raw = rawPayload(bytes, dictionary.second, syntax)
            return PdfStreamObject(
                reference = header.reference,
                dictionary = dictionary.first,
                payload = decoded(raw, syntax),
            )
        }

        private fun objectHeader(
            bytes: PdfBytes,
            start: Int,
        ): ObjectHeader? {
            val number = bytes.decimalToken(start) ?: return null
            val generationAt = bytes.skippingWhitespace(number.endExclusive)
            val generation = bytes.decimalToken(generationAt) ?: return null
            if (generation.value !in MINIMUM_GENERATION..MAXIMUM_GENERATION) {
                return null
            }
            val objectAt = bytes.skippingWhitespace(generation.endExclusive)
            if (!bytes.hasToken(PdfFormat.OBJECT_KEYWORD, objectAt)) {
                return null
            }
            return ObjectHeader(
                reference =
                    PdfDocumentIndex.Reference(
                        number = number.value,
                        generation = generation.value,
                    ),
                endExclusive = objectAt + PdfFormat.OBJECT_KEYWORD.length,
            )
        }

        private fun rawPayload(
            bytes: PdfBytes,
            dictionaryEnd: Int,
            syntax: PdfDictionarySyntax,
        ): ByteArray {
            val streamAt = bytes.skippingWhitespace(dictionaryEnd)
            if (!bytes.hasToken(PdfFormat.STREAM_KEYWORD, streamAt)) {
                throw unreadable()
            }
            var dataStart = streamAt + PdfFormat.STREAM_KEYWORD.length
            dataStart =
                when {
                    bytes.hasKeyword(CARRIAGE_RETURN_LINE_FEED, dataStart) -> {
                        dataStart + CARRIAGE_RETURN_LINE_FEED.length
                    }

                    bytes.hasKeyword(LINE_FEED, dataStart) -> {
                        dataStart + LINE_FEED.length
                    }

                    else -> {
                        throw unreadable()
                    }
                }

            val length =
                syntax.entry(keyName(PdfFormat.STREAM_LENGTH_KEY))?.let { entry ->
                    PdfValueParser.unsignedInteger(syntax.value(entry))
                }
            if (length != null) {
                val dataEnd =
                    try {
                        Math.addExact(dataStart, length)
                    } catch (_: ArithmeticException) {
                        throw unreadable()
                    }
                if (dataEnd > bytes.size) {
                    throw unreadable()
                }
                val endStreamAt = bytes.skippingWhitespace(dataEnd)
                if (!bytes.hasToken(PdfFormat.END_STREAM_KEYWORD, endStreamAt)) {
                    throw unreadable()
                }
                return bytes.data(PdfBytes.Range(start = dataStart, endExclusive = dataEnd))
            }

            val endStream =
                bytes.firstTokenRange(PdfFormat.END_STREAM_KEYWORD, dataStart)
                    ?: throw unreadable()
            var dataEnd = endStream.start
            if (dataEnd > dataStart && bytes.hasKeyword(LINE_FEED, dataEnd - LINE_FEED.length)) {
                dataEnd -= LINE_FEED.length
            }
            if (
                dataEnd > dataStart &&
                bytes.hasKeyword(CARRIAGE_RETURN, dataEnd - CARRIAGE_RETURN.length)
            ) {
                dataEnd -= CARRIAGE_RETURN.length
            }
            return bytes.data(PdfBytes.Range(start = dataStart, endExclusive = dataEnd))
        }

        private fun decoded(
            raw: ByteArray,
            syntax: PdfDictionarySyntax,
        ): ByteArray {
            val filterEntry = syntax.entry(keyName(PdfFormat.STREAM_FILTER_KEY))
            val filters =
                filterEntry
                    ?.let { entry ->
                        filterNames(syntax.value(entry))
                    }.orEmpty()
            val decodeParameters = decodeParameters(syntax)
            if (filterEntry == null && decodeParameters != null) {
                throw unreadable()
            }
            val unfiltered =
                when (filters) {
                    emptyList<String>() -> {
                        raw.copyOf().also(::requireInflatedBound)
                    }

                    listOf(PdfFormat.FLATE_DECODE_FILTER_NAME) -> {
                        PdfFlateDecoder.decode(
                            input = raw,
                            maximumOutputBytes = PdfFormat.MAXIMUM_INFLATED_STREAM_BYTES,
                        ) ?: throw unreadable()
                    }

                    else -> {
                        throw unsupported()
                    }
                }
            return undoPredictor(unfiltered, decodeParameters)
        }

        private fun filterNames(value: String): List<String> {
            PdfValueLexemes.name(value)?.let { name -> return listOf(name) }
            return PdfValueParser.nameArray(value)?.takeIf(List<String>::isNotEmpty)
                ?: throw unreadable()
        }

        private fun decodeParameters(syntax: PdfDictionarySyntax): PdfDictionarySyntax? {
            val entry = syntax.entry(keyName(PdfFormat.STREAM_DECODE_PARAMETERS_KEY)) ?: return null
            val value = syntax.value(entry)
            if (value.trim() == NULL_VALUE) {
                return null
            }
            dictionaryOrNull(value)?.let { parameters -> return parameters }
            val member = PdfValueParser.arrayValues(value)?.singleOrNull() ?: throw unreadable()
            return if (member.trim() == NULL_VALUE) {
                null
            } else {
                dictionaryOrNull(member) ?: throw unreadable()
            }
        }

        private fun dictionaryOrNull(value: String): PdfDictionarySyntax? =
            try {
                PdfDictionarySyntax(value)
            } catch (_: PdfSigningException) {
                null
            }

        private fun undoPredictor(
            data: ByteArray,
            parameters: PdfDictionarySyntax?,
        ): ByteArray {
            if (parameters == null) {
                return data
            }
            val predictor =
                integerParameter(
                    parameters,
                    PdfFormat.STREAM_PREDICTOR_KEY,
                    PdfFormat.STREAM_NO_PREDICTOR,
                )
            if (predictor == PdfFormat.STREAM_NO_PREDICTOR) {
                return data
            }
            if (
                predictor !in
                PdfFormat.STREAM_PNG_PREDICTOR_FLOOR..PdfFormat.STREAM_PNG_PREDICTOR_CEILING
            ) {
                throw unsupported()
            }
            val colors =
                integerParameter(
                    parameters,
                    PdfFormat.STREAM_COLORS_KEY,
                    PdfFormat.STREAM_PNG_SUPPORTED_COLORS,
                )
            val bitsPerComponent =
                integerParameter(
                    parameters,
                    PdfFormat.STREAM_BITS_PER_COMPONENT_KEY,
                    PdfFormat.STREAM_PNG_SUPPORTED_BITS_PER_COMPONENT,
                )
            if (
                colors != PdfFormat.STREAM_PNG_SUPPORTED_COLORS ||
                bitsPerComponent != PdfFormat.STREAM_PNG_SUPPORTED_BITS_PER_COMPONENT
            ) {
                throw unsupported()
            }
            val columns = integerParameter(parameters, PdfFormat.STREAM_COLUMNS_KEY, DEFAULT_COLUMN_COUNT)
            return PdfPngPredictor.undo(data, columns)
        }

        private fun integerParameter(
            syntax: PdfDictionarySyntax,
            key: String,
            defaultValue: Int,
        ): Int {
            val entry = syntax.entry(keyName(key)) ?: return defaultValue
            return PdfValueParser.unsignedInteger(syntax.value(entry)) ?: throw unreadable()
        }

        private fun requireInflatedBound(data: ByteArray) {
            if (data.size > PdfFormat.MAXIMUM_INFLATED_STREAM_BYTES) {
                throw unreadable()
            }
        }

        private fun keyName(key: String): String =
            key.removePrefix(NAME_PREFIX).takeIf(String::isNotEmpty) ?: throw unreadable()

        private fun unreadable(): PdfSigningException = PdfSigningException(PdfSigningFailure.STRUCTURE_UNREADABLE)

        private fun unsupported(): PdfSigningException =
            PdfSigningException(PdfSigningFailure.STREAM_ENCODING_UNSUPPORTED)

        private data class ObjectHeader(
            val reference: PdfDocumentIndex.Reference,
            val endExclusive: Int,
        )

        private const val NAME_PREFIX = "/"
        private const val NULL_VALUE = "null"
        private const val CARRIAGE_RETURN_LINE_FEED = "\r\n"
        private const val CARRIAGE_RETURN = "\r"
        private const val LINE_FEED = "\n"
        private const val FIRST_BYTE_OFFSET = 0
        private const val BYTE_OFFSET_STEP = 1
        private const val MINIMUM_GENERATION = 0
        private const val MAXIMUM_GENERATION = 65_535
        private const val DEFAULT_COLUMN_COUNT = 1
    }
}
