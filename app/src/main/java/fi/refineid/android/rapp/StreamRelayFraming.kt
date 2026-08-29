package fi.refineid.android.rapp

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** The fi.refineid.stream.v1 frame encoder and decoder. */
internal object StreamRelayFraming {
    const val LENGTH_PREFIX_BYTE_COUNT = 2
    const val MAXIMUM_PAYLOAD_BYTE_COUNT = 65535

    fun encode(payload: ByteArray): ByteArray? {
        if (payload.isEmpty() || payload.size > MAXIMUM_PAYLOAD_BYTE_COUNT) {
            return null
        }
        val buffer = ByteBuffer.allocate(LENGTH_PREFIX_BYTE_COUNT + payload.size)
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.putShort(payload.size.toShort())
        buffer.put(payload)
        return buffer.array()
    }

    fun payloadByteCount(lengthPrefix: ByteArray): Int? {
        if (lengthPrefix.size != LENGTH_PREFIX_BYTE_COUNT) return null
        val buffer = ByteBuffer.wrap(lengthPrefix)
        buffer.order(ByteOrder.BIG_ENDIAN)
        val len = buffer.short.toInt() and 0xFFFF
        return if (len >= 1) len else null
    }
}
