// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import kotlin.math.abs

/** Reverses the one-byte-sample PNG predictors permitted for structural PDF streams. */
internal object PdfPngPredictor {
    fun undo(
        data: ByteArray,
        columns: Int,
    ): ByteArray {
        val rowStride =
            try {
                Math.incrementExact(columns)
            } catch (_: ArithmeticException) {
                throw unreadable()
            }
        if (columns <= NO_COLUMNS || data.size % rowStride != COMPLETE_ROW_REMAINDER) {
            throw unreadable()
        }
        val rowCount = data.size / rowStride
        val output = ByteArray(Math.multiplyExact(rowCount, columns))
        var inputOffset = FIRST_BYTE_OFFSET
        var outputOffset = FIRST_BYTE_OFFSET
        repeat(rowCount) {
            val filter = data[inputOffset].toUByte().toInt()
            inputOffset += BYTE_OFFSET_STEP
            repeat(columns) { column ->
                val left =
                    if (column == FIRST_COLUMN) {
                        ZERO_PREDICTION
                    } else {
                        output[outputOffset - BYTE_OFFSET_STEP].toUByte().toInt()
                    }
                val above =
                    if (outputOffset < columns) {
                        ZERO_PREDICTION
                    } else {
                        output[outputOffset - columns].toUByte().toInt()
                    }
                val upperLeft =
                    if (column == FIRST_COLUMN || outputOffset < columns) {
                        ZERO_PREDICTION
                    } else {
                        output[outputOffset - columns - BYTE_OFFSET_STEP].toUByte().toInt()
                    }
                val prediction = prediction(filter, left, above, upperLeft)
                output[outputOffset] =
                    (
                        (data[inputOffset].toUByte().toInt() + prediction) and
                            PdfFormat.UNSIGNED_BYTE_MASK
                    ).toByte()
                inputOffset += BYTE_OFFSET_STEP
                outputOffset += BYTE_OFFSET_STEP
            }
        }
        return output
    }

    private fun prediction(
        filter: Int,
        left: Int,
        above: Int,
        upperLeft: Int,
    ): Int =
        when (filter) {
            PdfFormat.STREAM_PNG_FILTER_NONE -> ZERO_PREDICTION
            PdfFormat.STREAM_PNG_FILTER_SUB -> left
            PdfFormat.STREAM_PNG_FILTER_UP -> above
            PdfFormat.STREAM_PNG_FILTER_AVERAGE -> (left + above) / AVERAGE_DIVISOR
            PdfFormat.STREAM_PNG_FILTER_PAETH -> paeth(left, above, upperLeft)
            else -> throw unreadable()
        }

    private fun paeth(
        left: Int,
        above: Int,
        upperLeft: Int,
    ): Int {
        val estimate = left + above - upperLeft
        val distanceLeft = abs(estimate - left)
        val distanceAbove = abs(estimate - above)
        val distanceUpperLeft = abs(estimate - upperLeft)
        return when {
            distanceLeft <= distanceAbove && distanceLeft <= distanceUpperLeft -> left
            distanceAbove <= distanceUpperLeft -> above
            else -> upperLeft
        }
    }

    private fun unreadable(): PdfSigningException = PdfSigningException(PdfSigningFailure.STRUCTURE_UNREADABLE)

    private const val FIRST_BYTE_OFFSET = 0
    private const val BYTE_OFFSET_STEP = 1
    private const val NO_COLUMNS = 0
    private const val COMPLETE_ROW_REMAINDER = 0
    private const val FIRST_COLUMN = 0
    private const val ZERO_PREDICTION = 0
    private const val AVERAGE_DIVISOR = 2
}
