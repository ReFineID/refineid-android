// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.MessageDigest

/** A prepared PDF whose fixed-size hexadecimal signature hole already has final byte ranges. */
internal class PdfSignaturePlaceholder(
    document: ByteArray,
    private val contentsOpen: Int,
    private val secondSpanStart: Int,
    val capacity: Int,
) : AutoCloseable {
    private val preparedDocument = document.copyOf()
    private var isClosed = false

    init {
        validatePlaceholder()
    }

    val documentLength: Int
        get() {
            requireOpen()
            return preparedDocument.size
        }

    val signedOctetsLength: Int
        get() {
            requireOpen()
            return Math.addExact(contentsOpen, preparedDocument.size - secondSpanStart)
        }

    fun copyDocument(): ByteArray {
        requireOpen()
        return preparedDocument.copyOf()
    }

    fun copySignedOctets(): ByteArray {
        requireOpen()
        return ByteArray(signedOctetsLength).also { signed ->
            preparedDocument.copyInto(
                destination = signed,
                startIndex = FIRST_DOCUMENT_OFFSET,
                endIndex = contentsOpen,
            )
            preparedDocument.copyInto(
                destination = signed,
                destinationOffset = contentsOpen,
                startIndex = secondSpanStart,
            )
        }
    }

    fun digest(): ByteArray {
        requireOpen()
        return MessageDigest.getInstance(SHA384_DIGEST_ALGORITHM).run {
            update(
                preparedDocument,
                FIRST_DOCUMENT_OFFSET,
                contentsOpen,
            )
            update(
                preparedDocument,
                secondSpanStart,
                preparedDocument.size - secondSpanStart,
            )
            digest()
        }
    }

    fun filledWith(der: ByteArray): ByteArray {
        requireOpen()
        if (der.size > capacity) {
            throw PdfSigningException(
                kind = PdfSigningFailure.SIGNATURE_TOO_LARGE,
                needed = der.size,
                reserved = capacity,
            )
        }
        return preparedDocument.copyOf().also { filled ->
            var cursor = contentsOpen + HEX_OPEN_DELIMITER_LENGTH
            for (byte in der) {
                val unsigned = byte.toUByte().toInt()
                filled[cursor] = HEX_DIGITS[unsigned ushr PdfFormat.HEX_DIGIT_BITS]
                filled[cursor + LOW_HEX_DIGIT_OFFSET] =
                    HEX_DIGITS[unsigned and PdfFormat.HEX_DIGIT_MASK]
                cursor += PdfFormat.HEX_CHARACTERS_PER_BYTE
            }
        }
    }

    override fun close() {
        if (!isClosed) {
            preparedDocument.fill(CLEARED_BYTE)
            isClosed = true
        }
    }

    override fun toString(): String = "PdfSignaturePlaceholder(capacity=" + capacity + ", closed=" + isClosed + ")"

    private fun validatePlaceholder() {
        if (capacity < MINIMUM_CAPACITY) {
            throw malformedPlaceholder()
        }
        val hexLength =
            try {
                Math.multiplyExact(capacity, PdfFormat.HEX_CHARACTERS_PER_BYTE)
            } catch (_: ArithmeticException) {
                throw malformedPlaceholder()
            }
        val excludedLength =
            try {
                Math.addExact(hexLength, PdfFormat.HEX_DELIMITER_COUNT)
            } catch (_: ArithmeticException) {
                throw malformedPlaceholder()
            }
        if (!hasValidBounds(excludedLength) || !hasValidDelimiters() || !hasZeroFilledHole()) {
            throw malformedPlaceholder()
        }
    }

    private fun hasValidBounds(excludedLength: Int): Boolean =
        contentsOpen in FIRST_DOCUMENT_OFFSET until preparedDocument.size &&
            secondSpanStart in FIRST_DOCUMENT_OFFSET..preparedDocument.size &&
            secondSpanStart - contentsOpen == excludedLength

    private fun hasValidDelimiters(): Boolean =
        preparedDocument[contentsOpen] == HEX_OPEN_DELIMITER &&
            preparedDocument[secondSpanStart - HEX_CLOSE_DELIMITER_DISTANCE] ==
            HEX_CLOSE_DELIMITER

    private fun hasZeroFilledHole(): Boolean {
        val holeStart = contentsOpen + HEX_OPEN_DELIMITER_LENGTH
        val holeEnd = secondSpanStart - HEX_CLOSE_DELIMITER_DISTANCE
        return (holeStart until holeEnd).all { index ->
            preparedDocument[index] == ZERO_HEX_DIGIT
        }
    }

    private fun malformedPlaceholder(): PdfSigningException =
        PdfSigningException(PdfSigningFailure.PLACEHOLDER_MALFORMED)

    private fun requireOpen() {
        check(!isClosed) {
            "PDF signature placeholder is closed"
        }
    }

    private companion object {
        const val SHA384_DIGEST_ALGORITHM = "SHA-384"
        const val HEX_OPEN_DELIMITER_LENGTH = 1
        const val HEX_CLOSE_DELIMITER_DISTANCE = 1
        const val LOW_HEX_DIGIT_OFFSET = 1
        const val FIRST_DOCUMENT_OFFSET = 0
        const val MINIMUM_CAPACITY = 0
        const val CLEARED_BYTE: Byte = 0
        val HEX_DIGITS = PdfFormat.HEX_DIGIT_TEXT.encodeToByteArray()
        val HEX_OPEN_DELIMITER = '<'.code.toByte()
        val HEX_CLOSE_DELIMITER = '>'.code.toByte()
        val ZERO_HEX_DIGIT = '0'.code.toByte()
    }
}
