// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** Named PDF syntax, limits, and PAdES placeholder sizes used by the signing path. */
internal object PdfFormat {
    const val FILE_PREFIX = "%PDF-"
    const val START_XREF_KEYWORD = "startxref"
    const val XREF_KEYWORD = "xref"
    const val XREF_STREAM_KEY = "/XRefStm"
    const val TRAILER_KEYWORD = "trailer"
    const val END_OF_FILE_MARKER = "%%EOF"
    const val OBJECT_KEYWORD = "obj"
    const val END_OBJECT_KEYWORD = "endobj"
    const val STREAM_KEYWORD = "stream"
    const val END_STREAM_KEYWORD = "endstream"
    const val ENCRYPT_KEY = "/Encrypt"
    const val PREVIOUS_XREF_KEY = "/Prev"
    const val ROOT_KEY = "/Root"
    const val SIZE_KEY = "/Size"
    const val TYPE_KEY = "/Type"
    const val XREF_STREAM_TYPE_NAME = "XRef"
    const val OBJECT_STREAM_TYPE_NAME = "ObjStm"
    const val XREF_STREAM_WIDTHS_KEY = "/W"
    const val XREF_STREAM_INDEX_KEY = "/Index"
    const val OBJECT_STREAM_FIRST_KEY = "/First"
    const val OBJECT_STREAM_COUNT_KEY = "/N"
    const val STREAM_LENGTH_KEY = "/Length"
    const val STREAM_FILTER_KEY = "/Filter"
    const val STREAM_DECODE_PARAMETERS_KEY = "/DecodeParms"
    const val STREAM_PREDICTOR_KEY = "/Predictor"
    const val STREAM_COLORS_KEY = "/Colors"
    const val STREAM_BITS_PER_COMPONENT_KEY = "/BitsPerComponent"
    const val STREAM_COLUMNS_KEY = "/Columns"
    const val FLATE_DECODE_FILTER_NAME = "FlateDecode"

    const val DICTIONARY_OPEN = "<<"
    const val DICTIONARY_CLOSE = ">>"
    const val DICTIONARY_MARKER_LENGTH = 2
    const val DECIMAL_RADIX = 10
    const val MAXIMUM_XREF_CHAIN_DEPTH = 64
    const val MAXIMUM_PAGE_TREE_DEPTH = 32

    const val XREF_SUBSECTION_HEADER_TOKEN_COUNT = 2
    const val XREF_ENTRY_TOKEN_COUNT = 3
    const val XREF_ENTRY_OFFSET_INDEX = 0
    const val XREF_ENTRY_GENERATION_INDEX = 1
    const val XREF_ENTRY_FLAG_INDEX = 2
    const val XREF_IN_USE_FLAG = "n"
    const val XREF_FREE_FLAG = "f"

    const val XREF_STREAM_FIELD_COUNT = 3
    const val XREF_STREAM_TYPE_FIELD_INDEX = 0
    const val XREF_STREAM_FIRST_FIELD_INDEX = 1
    const val XREF_STREAM_SECOND_FIELD_INDEX = 2
    const val XREF_STREAM_FREE_ENTRY_TYPE = 0
    const val XREF_STREAM_DIRECT_ENTRY_TYPE = 1
    const val XREF_STREAM_COMPRESSED_ENTRY_TYPE = 2
    const val XREF_STREAM_TYPE_WIDTH_BYTES = 1
    const val XREF_STREAM_OFFSET_WIDTH_BYTES = 4
    const val XREF_STREAM_GENERATION_WIDTH_BYTES = 2
    const val XREF_STREAM_MAXIMUM_FIELD_WIDTH_BYTES = Long.SIZE_BYTES
    const val OBJECT_STREAM_PAIR_TOKEN_COUNT = 2
    const val MAXIMUM_INFLATED_STREAM_BYTES = 67_108_864

    const val STREAM_NO_PREDICTOR = 1
    const val STREAM_PNG_PREDICTOR_FLOOR = 10
    const val STREAM_PNG_PREDICTOR_CEILING = 15
    const val STREAM_PNG_FILTER_NONE = 0
    const val STREAM_PNG_FILTER_SUB = 1
    const val STREAM_PNG_FILTER_UP = 2
    const val STREAM_PNG_FILTER_AVERAGE = 3
    const val STREAM_PNG_FILTER_PAETH = 4
    const val STREAM_PNG_SUPPORTED_COLORS = 1
    const val STREAM_PNG_SUPPORTED_BITS_PER_COMPONENT = 8

    const val SIGNATURE_CAPACITY_BYTES = 49_152
    const val TIMESTAMP_CAPACITY_BYTES = 16_384
    const val BYTE_RANGE_DIGITS = 10
    const val BYTE_RANGE_FIELD_COUNT = 4

    const val HEX_DIGIT_TEXT = "0123456789ABCDEF"
    const val HEX_CHARACTERS_PER_BYTE = 2
    const val HEX_DIGIT_BITS = 4
    const val HEX_DIGIT_MASK = 0x0F
    const val HEX_DELIMITER_COUNT = 2
    const val UNSIGNED_BYTE_MASK = 0xFF

    const val NULL_BYTE: Byte = 0x00
    const val TAB_BYTE: Byte = 0x09
    const val LINE_FEED_BYTE: Byte = 0x0A
    const val FORM_FEED_BYTE: Byte = 0x0C
    const val CARRIAGE_RETURN_BYTE: Byte = 0x0D
    val SPACE_BYTE = ' '.code.toByte()
    val DELIMITER_BYTES =
        setOf(
            '('.code.toByte(),
            ')'.code.toByte(),
            '<'.code.toByte(),
            '>'.code.toByte(),
            '['.code.toByte(),
            ']'.code.toByte(),
            '{'.code.toByte(),
            '}'.code.toByte(),
            '/'.code.toByte(),
            '%'.code.toByte(),
        )
    val WHITESPACE_BYTES =
        setOf(
            NULL_BYTE,
            TAB_BYTE,
            LINE_FEED_BYTE,
            FORM_FEED_BYTE,
            CARRIAGE_RETURN_BYTE,
            SPACE_BYTE,
        )
}
