package fi.refineid.android.usb.ccid

import fi.refineid.android.core.NativeExchangeReplyTag
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class CcidNativeBlockExchangeTest {
    @Test
    fun replyTagsAreStableAndDistinct() {
        assertEquals(
            EXPECTED_REPLY_TAGS,
            NativeExchangeReplyTag.entries.map { it.wireValue },
        )
    }

    @Test
    fun publicResponseIsTaggedWithoutRetainingTheOwnedResult() {
        val payload = SYNTHETIC_RESPONSE.copyOf()
        val transport = scriptedTransport(responseFrame(payload))
        val callback = CcidNativeBlockExchange(transport)

        val reply = callback.exchangePublic(SYNTHETIC_COMMAND.copyOf())

        assertArrayEquals(
            byteArrayOf(
                NativeExchangeReplyTag.RESPONSE.wireValue,
                *SYNTHETIC_RESPONSE,
            ),
            reply,
        )
    }

    @Test
    fun unavailableCardUsesOnlyTheTypedTag() {
        val transport = scriptedTransport(cardUnavailableFrame())
        val callback = CcidNativeBlockExchange(transport)

        val reply = callback.exchangePublic(SYNTHETIC_COMMAND.copyOf())

        assertArrayEquals(
            byteArrayOf(NativeExchangeReplyTag.NO_CARD.wireValue),
            reply,
        )
    }

    private fun scriptedTransport(response: ByteArray): CcidBlockTransport {
        val io =
            object : CcidBulkIo {
                override fun write(frame: ByteArray): Int = frame.size

                override fun read(frame: ByteArray): Int {
                    response.copyInto(frame)
                    return response.size
                }
            }
        return CcidBlockTransport(
            exchange =
                CcidCommandExchange(
                    bulkIo = io,
                    maximumMessageLength = MAXIMUM_MESSAGE_LENGTH,
                ),
            maximumBlockLength = MAXIMUM_BLOCK_LENGTH,
        )
    }

    private fun responseFrame(payload: ByteArray): ByteArray =
        dataBlockFrame(
            payload = payload,
            status = CcidWire.CARD_STATUS_ACTIVE,
        )

    private fun cardUnavailableFrame(): ByteArray =
        dataBlockFrame(
            payload = ISO_SUCCESS_STATUS.copyOf(),
            status = CcidWire.CARD_STATUS_NOT_PRESENT,
        )

    private fun dataBlockFrame(
        payload: ByteArray,
        status: Int,
    ): ByteArray =
        ByteArray(CcidWire.HEADER_SIZE + payload.size).also { frame ->
            frame[CcidWire.MESSAGE_TYPE_OFFSET] = CcidWire.RDR_TO_PC_DATA_BLOCK.toByte()
            frame[CcidWire.LENGTH_OFFSET] = payload.size.toByte()
            frame[CcidWire.SLOT_OFFSET] = 0
            frame[CcidWire.SEQUENCE_OFFSET] = 0
            frame[CcidWire.STATUS_OFFSET] = status.toByte()
            frame[CcidWire.RESPONSE_PARAMETER_OFFSET] = CcidWire.COMPLETE_CHAIN.toByte()
            payload.copyInto(frame, destinationOffset = CcidWire.HEADER_SIZE)
        }

    private companion object {
        const val MAXIMUM_BLOCK_LENGTH = 261
        const val MAXIMUM_MESSAGE_LENGTH = CcidWire.HEADER_SIZE + MAXIMUM_BLOCK_LENGTH
        val EXPECTED_REPLY_TAGS = listOf<Byte>(0, 1, 2, 3, 4, 5, 6)
        val SYNTHETIC_COMMAND = byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x0C)
        val ISO_SUCCESS_STATUS = byteArrayOf(0x90.toByte(), 0x00)
        val SYNTHETIC_RESPONSE = byteArrayOf(0x11, *ISO_SUCCESS_STATUS)
    }
}
