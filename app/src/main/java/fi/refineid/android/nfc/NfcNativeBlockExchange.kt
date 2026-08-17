package fi.refineid.android.nfc

import fi.refineid.android.core.NativeBlockExchange
import fi.refineid.android.core.NativeExchangeReplyTag
import fi.refineid.android.diagnostics.AppTrace

/**
 * Adapts one connected ISO-DEP card to the synchronous native callback
 * ABI. ISO-DEP moves complete APDUs, so both paths submit one block per
 * call and never retry; a lost tag is a typed absence, not an error.
 */
internal class NfcNativeBlockExchange(
    private val channel: NfcCardChannel,
) : NativeBlockExchange {
    override fun exchangePublic(block: ByteArray): ByteArray = exchange(block)

    override fun exchangeCredential(block: ByteArray): ByteArray = exchange(block)

    private fun exchange(block: ByteArray): ByteArray {
        if (block.isEmpty() || block.size > channel.maximumTransceiveLength) {
            return byteArrayOf(NativeExchangeReplyTag.BACKEND_FAILURE.wireValue)
        }
        val startedAtNanos = System.nanoTime()
        val result = channel.transceive(block)
        val elapsedMicros = (System.nanoTime() - startedAtNanos) / NANOSECONDS_PER_MICROSECOND
        return when (result) {
            is NfcTransceiveResult.Response -> {
                AppTrace.nfcTransceive(block.size, result.bytes.size, elapsedMicros)
                encodeResponse(result.bytes)
            }

            NfcTransceiveResult.CardLost -> {
                byteArrayOf(NativeExchangeReplyTag.NO_CARD.wireValue)
            }

            NfcTransceiveResult.TransceiveFailed -> {
                byteArrayOf(NativeExchangeReplyTag.TIMEOUT_UNKNOWN_STATE.wireValue)
            }
        }
    }

    private fun encodeResponse(payload: ByteArray): ByteArray =
        try {
            if (
                payload.size < STATUS_WORD_LENGTH ||
                payload.size > MAXIMUM_RESPONSE_LENGTH
            ) {
                byteArrayOf(NativeExchangeReplyTag.PROTOCOL_DESYNC.wireValue)
            } else {
                ByteArray(TAG_LENGTH + payload.size).also { reply ->
                    reply[TAG_OFFSET] = NativeExchangeReplyTag.RESPONSE.wireValue
                    payload.copyInto(
                        destination = reply,
                        destinationOffset = TAG_LENGTH,
                    )
                }
            }
        } finally {
            payload.fill(0)
        }

    private companion object {
        const val NANOSECONDS_PER_MICROSECOND = 1_000

        const val TAG_OFFSET = 0
        const val TAG_LENGTH = 1

        /** An ISO 7816-4 response carries at least SW1 and SW2. */
        const val STATUS_WORD_LENGTH = 2

        /** Extended-length response body bound plus the status word. */
        const val MAXIMUM_RESPONSE_BODY_LENGTH = 1 shl 16
        const val MAXIMUM_RESPONSE_LENGTH =
            MAXIMUM_RESPONSE_BODY_LENGTH + STATUS_WORD_LENGTH
    }
}
