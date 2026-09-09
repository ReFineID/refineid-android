package fi.refineid.android.core

/** Converts the card's fixed-width P-384 `r || s` signature into X.509 DER. */
internal object P384EcdsaSignature {
    fun toDer(rawSignature: ByteArray): ByteArray {
        require(rawSignature.size == RAW_SIGNATURE_LENGTH) {
            "P-384 signature has an invalid length"
        }
        val r = encodeDerInteger(rawSignature, FIRST_COORDINATE_OFFSET, COORDINATE_LENGTH)
        val s = encodeDerInteger(rawSignature, SECOND_COORDINATE_OFFSET, COORDINATE_LENGTH)
        val sequenceLength = r.size + s.size
        check(sequenceLength < DER_LONG_FORM_LENGTH_THRESHOLD) {
            "P-384 signature exceeded the short DER length form"
        }
        return ByteArray(DER_SEQUENCE_HEADER_LENGTH + sequenceLength).also { encoded ->
            encoded[DER_TAG_OFFSET] = DER_SEQUENCE_TAG
            encoded[DER_LENGTH_OFFSET] = sequenceLength.toByte()
            r.copyInto(encoded, destinationOffset = DER_SEQUENCE_HEADER_LENGTH)
            s.copyInto(
                encoded,
                destinationOffset = DER_SEQUENCE_HEADER_LENGTH + r.size,
            )
            r.fill(ZERO_BYTE)
            s.fill(ZERO_BYTE)
        }
    }

    fun fromDer(derSignature: ByteArray): ByteArray {
        if (derSignature.size == RAW_SIGNATURE_LENGTH) {
            return derSignature.copyOf()
        }
        require(derSignature.size >= MINIMUM_DER_SIGNATURE_LENGTH && derSignature[DER_TAG_OFFSET] == DER_SEQUENCE_TAG) {
            "P-384 DER signature has an invalid header"
        }
        var offset = DER_LENGTH_OFFSET
        val lengthByte = derSignature[offset++].toInt() and BYTE_MASK
        if (lengthByte and SIGN_BIT != 0) {
            val lengthBytesCount = lengthByte and LENGTH_MASK
            var sequenceLength = 0
            for (i in 0 until lengthBytesCount) {
                sequenceLength = (sequenceLength shl Byte.SIZE_BITS) or (derSignature[offset++].toInt() and BYTE_MASK)
            }
        }
        require(offset < derSignature.size && derSignature[offset++] == DER_INTEGER_TAG) {
            "P-384 DER signature missing r tag"
        }
        val rLength = derSignature[offset++].toInt() and BYTE_MASK
        require(offset + rLength <= derSignature.size) {
            "P-384 DER signature r exceeds length"
        }
        val rStart = offset
        offset += rLength

        require(offset < derSignature.size && derSignature[offset++] == DER_INTEGER_TAG) {
            "P-384 DER signature missing s tag"
        }
        val sLength = derSignature[offset++].toInt() and BYTE_MASK
        require(offset + sLength <= derSignature.size) {
            "P-384 DER signature s exceeds length"
        }
        val sStart = offset

        val raw = ByteArray(RAW_SIGNATURE_LENGTH)
        copyCoordinate(derSignature, rStart, rLength, raw, FIRST_COORDINATE_OFFSET, COORDINATE_LENGTH)
        copyCoordinate(derSignature, sStart, sLength, raw, SECOND_COORDINATE_OFFSET, COORDINATE_LENGTH)
        return raw
    }

    private fun copyCoordinate(
        source: ByteArray,
        srcOffset: Int,
        srcLength: Int,
        destination: ByteArray,
        destOffset: Int,
        targetLength: Int,
    ) {
        var start = srcOffset
        val end = srcOffset + srcLength
        while (start < end - 1 && source[start] == ZERO_BYTE && end - start > targetLength) {
            start++
        }
        val copyLen = (end - start).coerceAtMost(targetLength)
        val pad = targetLength - copyLen
        source.copyInto(
            destination = destination,
            destinationOffset = destOffset + pad,
            startIndex = start,
            endIndex = start + copyLen,
        )
    }

    private fun encodeDerInteger(
        source: ByteArray,
        offset: Int,
        length: Int,
    ): ByteArray {
        var first = offset
        val end = offset + length
        while (first < end - 1 && source[first] == ZERO_BYTE) {
            first += 1
        }
        val needsPositivePrefix = source[first].toInt() and SIGN_BIT != 0
        val payloadLength =
            end - first +
                if (needsPositivePrefix) {
                    DER_POSITIVE_PREFIX_LENGTH
                } else {
                    NO_DER_POSITIVE_PREFIX_LENGTH
                }
        return ByteArray(DER_INTEGER_HEADER_LENGTH + payloadLength).also { encoded ->
            encoded[DER_TAG_OFFSET] = DER_INTEGER_TAG
            encoded[DER_LENGTH_OFFSET] = payloadLength.toByte()
            val destinationOffset =
                DER_INTEGER_HEADER_LENGTH +
                    if (needsPositivePrefix) {
                        DER_POSITIVE_PREFIX_LENGTH
                    } else {
                        NO_DER_POSITIVE_PREFIX_LENGTH
                    }
            source.copyInto(
                destination = encoded,
                destinationOffset = destinationOffset,
                startIndex = first,
                endIndex = end,
            )
        }
    }

    private const val FIRST_COORDINATE_OFFSET = 0
    private const val COORDINATE_LENGTH = P384_COORDINATE_LENGTH_BITS / Byte.SIZE_BITS
    private const val SECOND_COORDINATE_OFFSET = COORDINATE_LENGTH
    private const val RAW_SIGNATURE_LENGTH = COORDINATE_LENGTH * 2
    private const val DER_TAG_OFFSET = 0
    private const val DER_LENGTH_OFFSET = 1
    private const val DER_SEQUENCE_HEADER_LENGTH = 2
    private const val DER_INTEGER_HEADER_LENGTH = 2
    private const val DER_POSITIVE_PREFIX_LENGTH = 1
    private const val NO_DER_POSITIVE_PREFIX_LENGTH = 0
    private const val DER_LONG_FORM_LENGTH_THRESHOLD = 128
    private const val SIGN_BIT = 0x80
    private const val DER_SEQUENCE_TAG: Byte = 0x30
    private const val DER_INTEGER_TAG: Byte = 0x02
    private const val ZERO_BYTE: Byte = 0
    private const val MINIMUM_DER_SIGNATURE_LENGTH = 8
    private const val BYTE_MASK = 0xFF
    private const val LENGTH_MASK = 0x7F
}
