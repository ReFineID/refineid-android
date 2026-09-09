package fi.refineid.android.usb.ccid

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class CcidCodecTest {
    @Test
    fun encodesGetSlotStatusWithCommonHeader() {
        val command =
            CcidCommand.getSlotStatus(
                slot = TEST_SLOT,
                sequence = TEST_SEQUENCE,
            )
        val frame = command.encodedBytes()

        assertEquals(CcidWire.HEADER_SIZE, frame.size)
        assertEquals(
            CcidWire.PC_TO_RDR_GET_SLOT_STATUS,
            frame.unsignedByte(CcidWire.MESSAGE_TYPE_OFFSET),
        )
        assertZeroLength(frame)
        assertEquals(TEST_SLOT, frame.unsignedByte(CcidWire.SLOT_OFFSET))
        assertEquals(TEST_SEQUENCE, frame.unsignedByte(CcidWire.SEQUENCE_OFFSET))
        assertEquals(0, frame.unsignedByte(CcidWire.STATUS_OFFSET))
        assertEquals(0, frame.unsignedByte(CcidWire.ERROR_OFFSET))
        assertEquals(0, frame.unsignedByte(CcidWire.RESPONSE_PARAMETER_OFFSET))
        assertEquals(CcidResponseMessageType.SLOT_STATUS, command.expectedResponse)
    }

    @Test
    fun encodesPowerOnWithAutomaticVoltageSelection() {
        val command =
            CcidCommand.powerOnAutomatic(
                slot = TEST_SLOT,
                sequence = TEST_SEQUENCE,
            )
        val frame = command.encodedBytes()

        assertEquals(
            CcidWire.PC_TO_RDR_ICC_POWER_ON,
            frame.unsignedByte(CcidWire.MESSAGE_TYPE_OFFSET),
        )
        assertZeroLength(frame)
        assertEquals(
            CcidWire.AUTOMATIC_VOLTAGE_SELECTION,
            frame.unsignedByte(CcidWire.STATUS_OFFSET),
        )
        assertEquals(CcidResponseMessageType.DATA_BLOCK, command.expectedResponse)
    }

    @Test
    fun encodesTransferBlockWithZeroBwiAndLevelParameter() {
        val block =
            byteArrayOf(
                APDU_CLASS,
                APDU_INSTRUCTION,
                APDU_PARAMETER,
                APDU_PARAMETER,
            )
        val command =
            CcidCommand.transferBlock(
                slot = TEST_SLOT,
                sequence = TEST_SEQUENCE,
                block = block,
            )
        val frame = command.encodedBytes()

        assertEquals(CcidWire.HEADER_SIZE + block.size, frame.size)
        assertEquals(
            CcidWire.PC_TO_RDR_XFR_BLOCK,
            frame.unsignedByte(CcidWire.MESSAGE_TYPE_OFFSET),
        )
        assertEquals(block.size, readLength(frame))
        assertEquals(TEST_SLOT, frame.unsignedByte(CcidWire.SLOT_OFFSET))
        assertEquals(TEST_SEQUENCE, frame.unsignedByte(CcidWire.SEQUENCE_OFFSET))
        assertEquals(0, frame.unsignedByte(CcidWire.STATUS_OFFSET))
        assertEquals(0, frame.unsignedByte(CcidWire.ERROR_OFFSET))
        assertEquals(0, frame.unsignedByte(CcidWire.RESPONSE_PARAMETER_OFFSET))
        assertArrayEquals(
            block,
            frame.copyOfRange(CcidWire.HEADER_SIZE, frame.size),
        )
        assertEquals(CcidResponseMessageType.DATA_BLOCK, command.expectedResponse)
        assertEquals(
            "CcidCommand(slot=0, sequence=17, response=DATA_BLOCK, payloadLength=4)",
            command.toString(),
        )

        frame.fill(0)
        command.close()
        assertThrows(IllegalStateException::class.java) {
            command.encodedBytes()
        }
    }

    @Test
    fun rejectsTransferBlockOutsideTheCcidBound() {
        assertThrows(IllegalArgumentException::class.java) {
            CcidCommand.transferBlock(
                slot = TEST_SLOT,
                sequence = TEST_SEQUENCE,
                block = ByteArray(MINIMUM_APDU_LENGTH - 1),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            CcidCommand.transferBlock(
                slot = TEST_SLOT,
                sequence = TEST_SEQUENCE,
                block = ByteArray(MAXIMUM_COMMAND_PAYLOAD_SIZE + 1),
            )
        }
    }

    @Test
    fun sequenceCounterWrapsAfterUnsignedByteMaximum() {
        val counter = CcidSequenceCounter(initialValue = CcidWire.BYTE_MAX)

        assertEquals(CcidWire.BYTE_MAX, counter.take())
        assertEquals(0, counter.take())
    }

    @Test
    fun parsesSuccessfulSlotStatus() {
        val command = slotStatusCommand()
        val frame =
            responseFrame(
                messageType = CcidWire.RDR_TO_PC_SLOT_STATUS,
                cardStatus = CcidWire.CARD_STATUS_ACTIVE,
                commandStatus = CcidWire.COMMAND_STATUS_SUCCEEDED,
                responseParameter = CcidWire.CLOCK_RUNNING,
            )

        val response = CcidResponseParser.parse(frame, command)

        assertEquals(
            CcidSlotStatus(
                cardStatus = CcidCardStatus.ACTIVE,
                clockStatus = CcidClockStatus.RUNNING,
            ),
            response,
        )
    }

    @Test
    fun parsesDataBlockWithoutExposingPayloadInStringForm() {
        val command = powerOnCommand()
        val payload =
            byteArrayOf(
                SYNTHETIC_PAYLOAD_FIRST.toByte(),
                SYNTHETIC_PAYLOAD_SECOND.toByte(),
            )
        val frame =
            responseFrame(
                messageType = CcidWire.RDR_TO_PC_DATA_BLOCK,
                cardStatus = CcidWire.CARD_STATUS_ACTIVE,
                commandStatus = CcidWire.COMMAND_STATUS_SUCCEEDED,
                responseParameter = CcidWire.COMPLETE_CHAIN,
                payload = payload,
            )

        val response = CcidResponseParser.parse(frame, command) as CcidDataBlock

        assertArrayEquals(payload, response.copyPayload())
        assertEquals(
            "CcidDataBlock(cardStatus=ACTIVE, chainParameter=COMPLETE, payloadLength=2)",
            response.toString(),
        )
        response.close()
        assertThrows(IllegalStateException::class.java) {
            response.copyPayload()
        }
    }

    @Test
    fun parsesSignedFailureCode() {
        val command = slotStatusCommand()
        val frame =
            responseFrame(
                messageType = CcidWire.RDR_TO_PC_SLOT_STATUS,
                cardStatus = CcidWire.CARD_STATUS_NOT_PRESENT,
                commandStatus = CcidWire.COMMAND_STATUS_FAILED,
                error = ICC_MUTE_ERROR,
            )

        val response = CcidResponseParser.parse(frame, command)

        assertEquals(
            CcidCommandFailure(
                cardStatus = CcidCardStatus.NOT_PRESENT,
                errorCode = ICC_MUTE_SIGNED_ERROR,
            ),
            response,
        )
    }

    @Test
    fun parsesTimeExtensionMultiplier() {
        val command = powerOnCommand()
        val frame =
            responseFrame(
                messageType = CcidWire.RDR_TO_PC_DATA_BLOCK,
                cardStatus = CcidWire.CARD_STATUS_ACTIVE,
                commandStatus = CcidWire.COMMAND_STATUS_TIME_EXTENSION,
                error = TIME_EXTENSION_MULTIPLIER,
            )

        val response = CcidResponseParser.parse(frame, command)

        assertEquals(
            CcidTimeExtension(
                cardStatus = CcidCardStatus.ACTIVE,
                multiplier = TIME_EXTENSION_MULTIPLIER,
            ),
            response,
        )
    }

    @Test
    fun rejectsTruncatedHeader() {
        assertProtocolError(CcidProtocolErrorKind.TRUNCATED_HEADER) {
            CcidResponseParser.parse(
                frame = ByteArray(CcidWire.HEADER_SIZE - 1),
                command = slotStatusCommand(),
            )
        }
    }

    @Test
    fun rejectsPayloadLengthAboveSpecificationMaximum() {
        val frame = ByteArray(CcidWire.HEADER_SIZE)
        frame[CcidWire.MESSAGE_TYPE_OFFSET] = CcidWire.RDR_TO_PC_DATA_BLOCK.toByte()
        writeLength(
            frame = frame,
            length = CcidWire.MAX_RESPONSE_PAYLOAD_SIZE + 1,
        )

        assertProtocolError(CcidProtocolErrorKind.LENGTH_OUT_OF_RANGE) {
            CcidResponseParser.parse(frame, powerOnCommand())
        }
    }

    @Test
    fun rejectsDeclaredLengthThatDoesNotMatchFrame() {
        val frame = validSlotStatusFrame()
        writeLength(frame, length = 1)

        assertProtocolError(CcidProtocolErrorKind.LENGTH_MISMATCH) {
            CcidResponseParser.parse(frame, slotStatusCommand())
        }
    }

    @Test
    fun rejectsUnexpectedResponseType() {
        val frame =
            responseFrame(
                messageType = CcidWire.RDR_TO_PC_DATA_BLOCK,
                cardStatus = CcidWire.CARD_STATUS_ACTIVE,
                commandStatus = CcidWire.COMMAND_STATUS_SUCCEEDED,
            )

        assertProtocolError(CcidProtocolErrorKind.UNEXPECTED_MESSAGE_TYPE) {
            CcidResponseParser.parse(frame, slotStatusCommand())
        }
    }

    @Test
    fun rejectsUnexpectedSlot() {
        val frame = validSlotStatusFrame()
        frame[CcidWire.SLOT_OFFSET] = OTHER_SLOT.toByte()

        assertProtocolError(CcidProtocolErrorKind.UNEXPECTED_SLOT) {
            CcidResponseParser.parse(frame, slotStatusCommand())
        }
    }

    @Test
    fun rejectsUnexpectedSequence() {
        val frame = validSlotStatusFrame()
        frame[CcidWire.SEQUENCE_OFFSET] = OTHER_SEQUENCE.toByte()

        assertProtocolError(CcidProtocolErrorKind.UNEXPECTED_SEQUENCE) {
            CcidResponseParser.parse(frame, slotStatusCommand())
        }
    }

    @Test
    fun rejectsReservedStatusBits() {
        val frame = validSlotStatusFrame()
        frame[CcidWire.STATUS_OFFSET] =
            (
                CcidWire.CARD_STATUS_ACTIVE or
                    FIRST_RESERVED_STATUS_BIT
            ).toByte()

        assertProtocolError(CcidProtocolErrorKind.RESERVED_STATUS_BITS) {
            CcidResponseParser.parse(frame, slotStatusCommand())
        }
    }

    @Test
    fun rejectsReservedCardStatus() {
        val frame =
            responseFrame(
                messageType = CcidWire.RDR_TO_PC_SLOT_STATUS,
                cardStatus = RESERVED_CARD_STATUS,
                commandStatus = CcidWire.COMMAND_STATUS_SUCCEEDED,
            )

        assertProtocolError(CcidProtocolErrorKind.RESERVED_CARD_STATUS) {
            CcidResponseParser.parse(frame, slotStatusCommand())
        }
    }

    @Test
    fun rejectsReservedCommandStatus() {
        val frame =
            responseFrame(
                messageType = CcidWire.RDR_TO_PC_SLOT_STATUS,
                cardStatus = CcidWire.CARD_STATUS_ACTIVE,
                commandStatus = RESERVED_COMMAND_STATUS,
            )

        assertProtocolError(CcidProtocolErrorKind.RESERVED_COMMAND_STATUS) {
            CcidResponseParser.parse(frame, slotStatusCommand())
        }
    }

    @Test
    fun rejectsPayloadOnSlotStatusResponse() {
        val frame =
            responseFrame(
                messageType = CcidWire.RDR_TO_PC_SLOT_STATUS,
                cardStatus = CcidWire.CARD_STATUS_ACTIVE,
                commandStatus = CcidWire.COMMAND_STATUS_SUCCEEDED,
                payload = byteArrayOf(SYNTHETIC_PAYLOAD_FIRST.toByte()),
            )

        assertProtocolError(CcidProtocolErrorKind.UNEXPECTED_PAYLOAD) {
            CcidResponseParser.parse(frame, slotStatusCommand())
        }
    }

    @Test
    fun rejectsUndefinedClockStatus() {
        val frame =
            responseFrame(
                messageType = CcidWire.RDR_TO_PC_SLOT_STATUS,
                cardStatus = CcidWire.CARD_STATUS_ACTIVE,
                commandStatus = CcidWire.COMMAND_STATUS_SUCCEEDED,
                responseParameter = UNDEFINED_RESPONSE_PARAMETER,
            )

        assertProtocolError(CcidProtocolErrorKind.INVALID_CLOCK_STATUS) {
            CcidResponseParser.parse(frame, slotStatusCommand())
        }
    }

    @Test
    fun rejectsUndefinedChainParameter() {
        val frame =
            responseFrame(
                messageType = CcidWire.RDR_TO_PC_DATA_BLOCK,
                cardStatus = CcidWire.CARD_STATUS_ACTIVE,
                commandStatus = CcidWire.COMMAND_STATUS_SUCCEEDED,
                responseParameter = UNDEFINED_RESPONSE_PARAMETER,
            )

        assertProtocolError(CcidProtocolErrorKind.INVALID_CHAIN_PARAMETER) {
            CcidResponseParser.parse(frame, powerOnCommand())
        }
    }

    private fun slotStatusCommand(): CcidCommand =
        CcidCommand.getSlotStatus(
            slot = TEST_SLOT,
            sequence = TEST_SEQUENCE,
        )

    private fun powerOnCommand(): CcidCommand =
        CcidCommand.powerOnAutomatic(
            slot = TEST_SLOT,
            sequence = TEST_SEQUENCE,
        )

    private fun validSlotStatusFrame(): ByteArray =
        responseFrame(
            messageType = CcidWire.RDR_TO_PC_SLOT_STATUS,
            cardStatus = CcidWire.CARD_STATUS_ACTIVE,
            commandStatus = CcidWire.COMMAND_STATUS_SUCCEEDED,
            responseParameter = CcidWire.CLOCK_RUNNING,
        )

    private fun responseFrame(
        messageType: Int,
        cardStatus: Int,
        commandStatus: Int,
        error: Int = 0,
        responseParameter: Int = 0,
        payload: ByteArray = byteArrayOf(),
    ): ByteArray {
        val frame = ByteArray(CcidWire.HEADER_SIZE + payload.size)
        frame[CcidWire.MESSAGE_TYPE_OFFSET] = messageType.toByte()
        writeLength(frame, payload.size)
        frame[CcidWire.SLOT_OFFSET] = TEST_SLOT.toByte()
        frame[CcidWire.SEQUENCE_OFFSET] = TEST_SEQUENCE.toByte()
        frame[CcidWire.STATUS_OFFSET] =
            (
                cardStatus or
                    (commandStatus shl CcidWire.COMMAND_STATUS_SHIFT)
            ).toByte()
        frame[CcidWire.ERROR_OFFSET] = error.toByte()
        frame[CcidWire.RESPONSE_PARAMETER_OFFSET] = responseParameter.toByte()
        payload.copyInto(
            destination = frame,
            destinationOffset = CcidWire.HEADER_SIZE,
        )
        return frame
    }

    private fun writeLength(
        frame: ByteArray,
        length: Int,
    ) {
        repeat(LENGTH_FIELD_SIZE) { byteIndex ->
            frame[CcidWire.LENGTH_OFFSET + byteIndex] =
                (length ushr (byteIndex * Byte.SIZE_BITS)).toByte()
        }
    }

    private fun assertZeroLength(frame: ByteArray) {
        repeat(LENGTH_FIELD_SIZE) { index ->
            assertEquals(0, frame.unsignedByte(CcidWire.LENGTH_OFFSET + index))
        }
    }

    private fun readLength(frame: ByteArray): Int =
        (0 until LENGTH_FIELD_SIZE).fold(0) { decoded, byteIndex ->
            decoded or
                (
                    frame.unsignedByte(CcidWire.LENGTH_OFFSET + byteIndex) shl
                        (byteIndex * Byte.SIZE_BITS)
                )
        }

    private fun assertProtocolError(
        expectedKind: CcidProtocolErrorKind,
        block: () -> Unit,
    ) {
        val exception =
            assertThrows(CcidProtocolException::class.java) {
                block()
            }
        assertEquals(expectedKind, exception.kind)
    }

    private fun ByteArray.unsignedByte(offset: Int): Int = this[offset].toInt() and CcidWire.BYTE_MAX

    private companion object {
        const val TEST_SLOT = 0
        const val OTHER_SLOT = 1
        const val TEST_SEQUENCE = 17
        const val OTHER_SEQUENCE = 18
        const val LENGTH_FIELD_SIZE = 4
        const val FIRST_RESERVED_STATUS_BIT = 1 shl 2
        const val RESERVED_CARD_STATUS = 3
        const val RESERVED_COMMAND_STATUS = 3
        const val UNDEFINED_RESPONSE_PARAMETER = 4
        const val ICC_MUTE_ERROR = 0xFE
        const val ICC_MUTE_SIGNED_ERROR = -2
        const val TIME_EXTENSION_MULTIPLIER = 3
        const val SYNTHETIC_PAYLOAD_FIRST = 0xA5
        const val SYNTHETIC_PAYLOAD_SECOND = 0x5A
        const val APDU_CLASS: Byte = 0x00
        const val APDU_INSTRUCTION: Byte = 0xA4.toByte()
        const val APDU_PARAMETER: Byte = 0x00
        const val MINIMUM_APDU_LENGTH = 4
        const val MAXIMUM_COMMAND_PAYLOAD_SIZE = 65_544
    }
}
