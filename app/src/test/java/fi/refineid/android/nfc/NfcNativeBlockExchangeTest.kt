package fi.refineid.android.nfc

import fi.refineid.android.core.NativeExchangeReplyTag
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class NfcNativeBlockExchangeTest {
    private class ScriptedChannel(
        override val maximumTransceiveLength: Int = MAXIMUM_COMMAND_LENGTH,
        private val result: () -> NfcTransceiveResult,
    ) : NfcCardChannel {
        var transceiveCount = 0
            private set

        override fun transceive(command: ByteArray): NfcTransceiveResult {
            transceiveCount += 1
            return result()
        }
    }

    @Test
    fun responseIsTaggedAndPassedThrough() {
        val channel =
            ScriptedChannel {
                NfcTransceiveResult.Response(SYNTHETIC_RESPONSE.copyOf())
            }
        val exchange = NfcNativeBlockExchange(channel)

        val reply = exchange.exchangePublic(SYNTHETIC_COMMAND.copyOf())

        assertArrayEquals(
            byteArrayOf(
                NativeExchangeReplyTag.RESPONSE.wireValue,
                *SYNTHETIC_RESPONSE,
            ),
            reply,
        )
        assertEquals(1, channel.transceiveCount)
    }

    @Test
    fun credentialPathSubmitsExactlyOnce() {
        val channel =
            ScriptedChannel {
                NfcTransceiveResult.Response(SYNTHETIC_RESPONSE.copyOf())
            }
        val exchange = NfcNativeBlockExchange(channel)

        exchange.exchangeCredential(SYNTHETIC_COMMAND.copyOf())

        assertEquals(1, channel.transceiveCount)
    }

    @Test
    fun lostTagUsesOnlyTheTypedTag() {
        val exchange =
            NfcNativeBlockExchange(ScriptedChannel { NfcTransceiveResult.CardLost })

        val reply = exchange.exchangePublic(SYNTHETIC_COMMAND.copyOf())

        assertArrayEquals(
            byteArrayOf(NativeExchangeReplyTag.NO_CARD.wireValue),
            reply,
        )
    }

    @Test
    fun failedTransceiveLeavesCardStateUncertain() {
        val exchange =
            NfcNativeBlockExchange(ScriptedChannel { NfcTransceiveResult.TransceiveFailed })

        val reply = exchange.exchangePublic(SYNTHETIC_COMMAND.copyOf())

        assertArrayEquals(
            byteArrayOf(NativeExchangeReplyTag.TIMEOUT_UNKNOWN_STATE.wireValue),
            reply,
        )
    }

    @Test
    fun responseShorterThanAStatusWordIsProtocolDesync() {
        val exchange =
            NfcNativeBlockExchange(
                ScriptedChannel {
                    NfcTransceiveResult.Response(byteArrayOf(SYNTHETIC_STATUS_BYTE))
                },
            )

        val reply = exchange.exchangePublic(SYNTHETIC_COMMAND.copyOf())

        assertArrayEquals(
            byteArrayOf(NativeExchangeReplyTag.PROTOCOL_DESYNC.wireValue),
            reply,
        )
    }

    @Test
    fun oversizedResponseIsProtocolDesync() {
        val exchange =
            NfcNativeBlockExchange(
                ScriptedChannel {
                    NfcTransceiveResult.Response(ByteArray(OVERSIZED_RESPONSE_LENGTH))
                },
            )

        val reply = exchange.exchangePublic(SYNTHETIC_COMMAND.copyOf())

        assertArrayEquals(
            byteArrayOf(NativeExchangeReplyTag.PROTOCOL_DESYNC.wireValue),
            reply,
        )
    }

    @Test
    fun emptyAndOversizedCommandsNeverReachTheCard() {
        val channel =
            ScriptedChannel {
                NfcTransceiveResult.Response(SYNTHETIC_RESPONSE.copyOf())
            }
        val exchange = NfcNativeBlockExchange(channel)

        val emptyReply = exchange.exchangePublic(byteArrayOf())
        val oversizedReply =
            exchange.exchangePublic(ByteArray(MAXIMUM_COMMAND_LENGTH + 1))

        assertArrayEquals(
            byteArrayOf(NativeExchangeReplyTag.BACKEND_FAILURE.wireValue),
            emptyReply,
        )
        assertArrayEquals(
            byteArrayOf(NativeExchangeReplyTag.BACKEND_FAILURE.wireValue),
            oversizedReply,
        )
        assertEquals(0, channel.transceiveCount)
    }

    private companion object {
        const val MAXIMUM_COMMAND_LENGTH = 261
        const val SYNTHETIC_STATUS_BYTE: Byte = 0x61

        // The ISO 7816 extended response bound plus a status word,
        // plus one byte past the exchange's acceptance limit.
        const val OVERSIZED_RESPONSE_LENGTH = (1 shl 16) + 2 + 1
        val SYNTHETIC_COMMAND = byteArrayOf(0x00, 0xA4.toByte(), 0x00, 0x0C)
        val ISO_SUCCESS_STATUS = byteArrayOf(0x90.toByte(), 0x00)
        val SYNTHETIC_RESPONSE = byteArrayOf(0x11, *ISO_SUCCESS_STATUS)
    }
}
