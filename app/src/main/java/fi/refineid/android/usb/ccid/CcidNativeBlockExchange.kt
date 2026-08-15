package fi.refineid.android.usb.ccid

import fi.refineid.android.core.NativeBlockExchange

/** Stable tags shared with the narrow Rust callback parser. */
internal enum class NativeExchangeReplyTag(
    val wireValue: Byte,
) {
    RESPONSE(0),
    NO_CARD(1),
    TIMEOUT_UNKNOWN_STATE(2),
    CARD_RESET(3),
    PROTOCOL_DESYNC(4),
    READER_REMOVED(5),
    BACKEND_FAILURE(6),
}

/** Adapts one claimed CCID session to the synchronous native callback ABI. */
internal class CcidNativeBlockExchange(
    private val transport: CcidBlockTransport,
) : NativeBlockExchange {
    override fun exchangePublic(block: ByteArray): ByteArray =
        encode(transport.transmitPublic(block))

    override fun exchangeCredential(block: ByteArray): ByteArray =
        encode(transport.transmitCredential(block))

    private fun encode(result: CcidBlockResult): ByteArray =
        when (result) {
            is CcidBlockResult.Response ->
                result.use {
                    val payload = result.copyPayload()
                    try {
                        ByteArray(TAG_LENGTH + payload.size).also { reply ->
                            reply[TAG_OFFSET] = NativeExchangeReplyTag.RESPONSE.wireValue
                            payload.copyInto(
                                destination = reply,
                                destinationOffset = TAG_LENGTH,
                            )
                        }
                    } finally {
                        payload.fill(0)
                    }
                }
            is CcidBlockResult.Failure ->
                byteArrayOf(mapFailure(result.kind).wireValue)
        }

    private fun mapFailure(kind: CcidBlockFailureKind): NativeExchangeReplyTag =
        when (kind) {
            CcidBlockFailureKind.CARD_UNAVAILABLE -> NativeExchangeReplyTag.NO_CARD
            CcidBlockFailureKind.PROTOCOL -> NativeExchangeReplyTag.PROTOCOL_DESYNC
            CcidBlockFailureKind.COMMAND_REJECTED,
            CcidBlockFailureKind.READER,
            CcidBlockFailureKind.TRANSPORT,
            -> NativeExchangeReplyTag.BACKEND_FAILURE
        }

    private companion object {
        const val TAG_OFFSET = 0
        const val TAG_LENGTH = 1
    }
}
