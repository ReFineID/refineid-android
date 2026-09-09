// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.io.ByteArrayOutputStream
import java.util.zip.DataFormatException
import java.util.zip.Inflater

/** RFC 1950-wrapped or bare deflate decoding with a hard output ceiling. */
internal object PdfFlateDecoder {
    fun decode(
        input: ByteArray,
        maximumOutputBytes: Int,
    ): ByteArray? {
        if (input.size < ZLIB_HEADER_LENGTH) {
            return null
        }
        val first = input[FIRST_BYTE_OFFSET].toUByte().toInt()
        val second = input[SECOND_BYTE_OFFSET].toUByte().toInt()
        val checkWord = (first shl Byte.SIZE_BITS) or second
        val hasZlibWrapper =
            first and ZLIB_METHOD_MASK == ZLIB_DEFLATE_METHOD &&
                checkWord % ZLIB_HEADER_CHECK_MODULUS == ZLIB_VALID_HEADER_REMAINDER
        if (hasZlibWrapper && second and ZLIB_PRESET_DICTIONARY_MASK != ZLIB_NO_PRESET_DICTIONARY) {
            return null
        }
        return inflate(input, maximumOutputBytes, nowrap = !hasZlibWrapper)
    }

    private fun inflate(
        input: ByteArray,
        maximumOutputBytes: Int,
        nowrap: Boolean,
    ): ByteArray? {
        val inflater = Inflater(nowrap)
        return try {
            inflater.setInput(input)
            val output = ByteArrayOutputStream()
            val chunk = ByteArray(INFLATE_CHUNK_LENGTH_BYTES)
            while (!inflater.finished()) {
                val produced = inflater.inflate(chunk)
                if (produced > NO_BYTES_PRODUCED) {
                    if (output.size() > maximumOutputBytes - produced) {
                        return null
                    }
                    output.write(chunk, FIRST_BYTE_OFFSET, produced)
                } else if (inflater.finished()) {
                    break
                } else if (inflater.needsDictionary() || inflater.needsInput()) {
                    return null
                } else {
                    return null
                }
            }
            if (inflater.remaining != NO_REMAINING_COMPRESSED_BYTES) {
                null
            } else {
                output.toByteArray()
            }
        } catch (_: DataFormatException) {
            null
        } finally {
            inflater.end()
        }
    }

    private const val FIRST_BYTE_OFFSET = 0
    private const val SECOND_BYTE_OFFSET = 1
    private const val ZLIB_HEADER_LENGTH = 2
    private const val ZLIB_METHOD_MASK = 0x0F
    private const val ZLIB_DEFLATE_METHOD = 8
    private const val ZLIB_HEADER_CHECK_MODULUS = 31
    private const val ZLIB_VALID_HEADER_REMAINDER = 0
    private const val ZLIB_PRESET_DICTIONARY_MASK = 0x20
    private const val ZLIB_NO_PRESET_DICTIONARY = 0
    private const val INFLATE_CHUNK_LENGTH_BYTES = 65_536
    private const val NO_BYTES_PRODUCED = 0
    private const val NO_REMAINING_COMPRESSED_BYTES = 0
}
