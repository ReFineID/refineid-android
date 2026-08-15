package fi.refineid.android.usb.ccid

internal object CcidWire {
    const val HEADER_SIZE = 10
    const val MAX_RESPONSE_PAYLOAD_SIZE = 65_538

    const val MESSAGE_TYPE_OFFSET = 0
    const val LENGTH_OFFSET = 1
    const val SLOT_OFFSET = 5
    const val SEQUENCE_OFFSET = 6
    const val STATUS_OFFSET = 7
    const val ERROR_OFFSET = 8
    const val RESPONSE_PARAMETER_OFFSET = 9

    const val PC_TO_RDR_ICC_POWER_ON = 0x62
    const val PC_TO_RDR_GET_SLOT_STATUS = 0x65
    const val PC_TO_RDR_XFR_BLOCK = 0x6F
    const val RDR_TO_PC_DATA_BLOCK = 0x80
    const val RDR_TO_PC_SLOT_STATUS = 0x81

    const val CARD_STATUS_ACTIVE = 0
    const val CARD_STATUS_INACTIVE = 1
    const val CARD_STATUS_NOT_PRESENT = 2

    const val COMMAND_STATUS_SUCCEEDED = 0
    const val COMMAND_STATUS_FAILED = 1
    const val COMMAND_STATUS_TIME_EXTENSION = 2
    const val COMMAND_STATUS_SHIFT = 6

    const val RESERVED_STATUS_MASK = 0x3C
    const val FIELD_MASK = 0x03

    const val AUTOMATIC_VOLTAGE_SELECTION = 0
    const val COMPLETE_CHAIN = 0
    const val BEGIN_CHAIN = 1
    const val END_CHAIN = 2
    const val CONTINUE_CHAIN = 3
    const val COMMAND_CONTINUATION_EXPECTED = 0x10

    const val CLOCK_RUNNING = 0
    const val CLOCK_STOPPED_LOW = 1
    const val CLOCK_STOPPED_HIGH = 2
    const val CLOCK_STOPPED_UNKNOWN = 3

    const val BYTE_MAX = 0xFF
}

internal enum class CcidResponseMessageType(
    val wireValue: Int,
) {
    DATA_BLOCK(CcidWire.RDR_TO_PC_DATA_BLOCK),
    SLOT_STATUS(CcidWire.RDR_TO_PC_SLOT_STATUS),
}

internal class CcidCommand private constructor(
    internal val slot: Int,
    internal val sequence: Int,
    internal val expectedResponse: CcidResponseMessageType,
    private val payloadLength: Int,
    private val wireBytes: ByteArray,
) : AutoCloseable {
    private var isClosed = false

    fun encodedBytes(): ByteArray {
        check(!isClosed) {
            "CCID command is closed"
        }
        return wireBytes.copyOf()
    }

    override fun close() {
        wireBytes.fill(0)
        isClosed = true
    }

    override fun toString(): String =
        "CcidCommand(slot=" + slot +
            ", sequence=" + sequence +
            ", response=" + expectedResponse +
            ", payloadLength=" + payloadLength + ")"

    companion object {
        fun getSlotStatus(
            slot: Int,
            sequence: Int,
        ): CcidCommand =
            commandWithoutPayload(
                messageType = CcidWire.PC_TO_RDR_GET_SLOT_STATUS,
                slot = slot,
                sequence = sequence,
                firstParameter = 0,
                expectedResponse = CcidResponseMessageType.SLOT_STATUS,
            )

        fun powerOnAutomatic(
            slot: Int,
            sequence: Int,
        ): CcidCommand =
            commandWithoutPayload(
                messageType = CcidWire.PC_TO_RDR_ICC_POWER_ON,
                slot = slot,
                sequence = sequence,
                firstParameter = CcidWire.AUTOMATIC_VOLTAGE_SELECTION,
                expectedResponse = CcidResponseMessageType.DATA_BLOCK,
            )

        fun transferBlock(
            slot: Int,
            sequence: Int,
            block: ByteArray,
        ): CcidCommand {
            require(block.size in MINIMUM_TRANSFER_BLOCK_LENGTH..MAXIMUM_COMMAND_PAYLOAD_SIZE) {
                "transfer-block length is outside the CCID command bound"
            }
            requireUnsignedByte("slot", slot)
            requireUnsignedByte("sequence", sequence)

            val bytes = ByteArray(CcidWire.HEADER_SIZE + block.size)
            bytes[CcidWire.MESSAGE_TYPE_OFFSET] = CcidWire.PC_TO_RDR_XFR_BLOCK.toByte()
            writeUnsignedIntLittleEndian(
                bytes = bytes,
                offset = CcidWire.LENGTH_OFFSET,
                value = block.size,
            )
            bytes[CcidWire.SLOT_OFFSET] = slot.toByte()
            bytes[CcidWire.SEQUENCE_OFFSET] = sequence.toByte()
            block.copyInto(
                destination = bytes,
                destinationOffset = CcidWire.HEADER_SIZE,
            )

            return CcidCommand(
                slot = slot,
                sequence = sequence,
                expectedResponse = CcidResponseMessageType.DATA_BLOCK,
                payloadLength = block.size,
                wireBytes = bytes,
            )
        }

        private fun commandWithoutPayload(
            messageType: Int,
            slot: Int,
            sequence: Int,
            firstParameter: Int,
            expectedResponse: CcidResponseMessageType,
        ): CcidCommand {
            requireUnsignedByte("slot", slot)
            requireUnsignedByte("sequence", sequence)

            val bytes = ByteArray(CcidWire.HEADER_SIZE)
            bytes[CcidWire.MESSAGE_TYPE_OFFSET] = messageType.toByte()
            bytes[CcidWire.SLOT_OFFSET] = slot.toByte()
            bytes[CcidWire.SEQUENCE_OFFSET] = sequence.toByte()
            bytes[CcidWire.STATUS_OFFSET] = firstParameter.toByte()

            return CcidCommand(
                slot = slot,
                sequence = sequence,
                expectedResponse = expectedResponse,
                payloadLength = 0,
                wireBytes = bytes,
            )
        }

        private fun writeUnsignedIntLittleEndian(
            bytes: ByteArray,
            offset: Int,
            value: Int,
        ) {
            repeat(UNSIGNED_INT_LENGTH) { index ->
                bytes[offset + index] =
                    (value ushr (index * Byte.SIZE_BITS)).toByte()
            }
        }

        private fun requireUnsignedByte(
            field: String,
            value: Int,
        ) {
            require(value in 0..CcidWire.BYTE_MAX) {
                field + " must fit one unsigned byte"
            }
        }

        private const val UNSIGNED_INT_LENGTH = 4
        private const val MINIMUM_TRANSFER_BLOCK_LENGTH = 4
        private const val MAXIMUM_COMMAND_PAYLOAD_SIZE = 65_544
    }
}

internal class CcidSequenceCounter(
    initialValue: Int = 0,
) {
    private var nextValue = initialValue

    init {
        require(initialValue in 0..CcidWire.BYTE_MAX) {
            "initial sequence must fit one unsigned byte"
        }
    }

    @Synchronized
    fun take(): Int {
        val current = nextValue
        nextValue = (nextValue + 1) and CcidWire.BYTE_MAX
        return current
    }
}

internal enum class CcidCardStatus {
    ACTIVE,
    INACTIVE,
    NOT_PRESENT,
}

internal enum class CcidClockStatus {
    RUNNING,
    STOPPED_LOW,
    STOPPED_HIGH,
    STOPPED_UNKNOWN,
}

internal enum class CcidChainParameter {
    COMPLETE,
    BEGIN,
    END,
    CONTINUE,
    COMMAND_CONTINUATION_EXPECTED,
}

internal sealed interface CcidResponse {
    val cardStatus: CcidCardStatus
}

internal data class CcidSlotStatus(
    override val cardStatus: CcidCardStatus,
    val clockStatus: CcidClockStatus,
) : CcidResponse

internal data class CcidCommandFailure(
    override val cardStatus: CcidCardStatus,
    val errorCode: Int,
) : CcidResponse

internal data class CcidTimeExtension(
    override val cardStatus: CcidCardStatus,
    val multiplier: Int,
) : CcidResponse

internal class CcidDataBlock(
    override val cardStatus: CcidCardStatus,
    val chainParameter: CcidChainParameter,
    payload: ByteArray,
) : CcidResponse,
    AutoCloseable {
    private val ownedPayload = payload.copyOf()
    private var isClosed = false

    val payloadLength: Int
        get() = ownedPayload.size

    fun copyPayload(): ByteArray {
        check(!isClosed) {
            "CCID data block is closed"
        }
        return ownedPayload.copyOf()
    }

    override fun close() {
        ownedPayload.fill(0)
        isClosed = true
    }

    override fun toString(): String =
        "CcidDataBlock(cardStatus=" + cardStatus +
            ", chainParameter=" + chainParameter +
            ", payloadLength=" + payloadLength + ")"
}

internal enum class CcidProtocolErrorKind {
    TRUNCATED_HEADER,
    LENGTH_OUT_OF_RANGE,
    LENGTH_MISMATCH,
    UNEXPECTED_MESSAGE_TYPE,
    UNEXPECTED_SLOT,
    UNEXPECTED_SEQUENCE,
    RESERVED_STATUS_BITS,
    RESERVED_CARD_STATUS,
    RESERVED_COMMAND_STATUS,
    UNEXPECTED_PAYLOAD,
    INVALID_CLOCK_STATUS,
    INVALID_CHAIN_PARAMETER,
}

internal class CcidProtocolException(
    val kind: CcidProtocolErrorKind,
    message: String,
) : Exception(message)

internal object CcidResponseParser {
    fun parse(
        frame: ByteArray,
        command: CcidCommand,
    ): CcidResponse {
        if (frame.size < CcidWire.HEADER_SIZE) {
            throw protocolError(
                CcidProtocolErrorKind.TRUNCATED_HEADER,
                "CCID response header is truncated",
            )
        }

        val declaredLength = readUnsignedIntLittleEndian(frame, CcidWire.LENGTH_OFFSET)
        if (declaredLength > CcidWire.MAX_RESPONSE_PAYLOAD_SIZE.toLong()) {
            throw protocolError(
                CcidProtocolErrorKind.LENGTH_OUT_OF_RANGE,
                "CCID response length exceeds the specification maximum",
            )
        }

        val expectedFrameSize = CcidWire.HEADER_SIZE.toLong() + declaredLength
        if (frame.size.toLong() != expectedFrameSize) {
            throw protocolError(
                CcidProtocolErrorKind.LENGTH_MISMATCH,
                "CCID response length does not match the received byte count",
            )
        }

        val messageType = frame.unsignedByte(CcidWire.MESSAGE_TYPE_OFFSET)
        if (messageType != command.expectedResponse.wireValue) {
            throw protocolError(
                CcidProtocolErrorKind.UNEXPECTED_MESSAGE_TYPE,
                "CCID response type does not match the command",
            )
        }

        val slot = frame.unsignedByte(CcidWire.SLOT_OFFSET)
        if (slot != command.slot) {
            throw protocolError(
                CcidProtocolErrorKind.UNEXPECTED_SLOT,
                "CCID response slot does not match the command",
            )
        }

        val sequence = frame.unsignedByte(CcidWire.SEQUENCE_OFFSET)
        if (sequence != command.sequence) {
            throw protocolError(
                CcidProtocolErrorKind.UNEXPECTED_SEQUENCE,
                "CCID response sequence does not match the command",
            )
        }

        if (
            command.expectedResponse == CcidResponseMessageType.SLOT_STATUS &&
            declaredLength != 0L
        ) {
            throw protocolError(
                CcidProtocolErrorKind.UNEXPECTED_PAYLOAD,
                "CCID slot-status response contains a payload",
            )
        }

        val status = frame.unsignedByte(CcidWire.STATUS_OFFSET)
        if (status and CcidWire.RESERVED_STATUS_MASK != 0) {
            throw protocolError(
                CcidProtocolErrorKind.RESERVED_STATUS_BITS,
                "CCID response sets reserved status bits",
            )
        }

        val cardStatus = parseCardStatus(status and CcidWire.FIELD_MASK)
        val commandStatus =
            (status ushr CcidWire.COMMAND_STATUS_SHIFT) and CcidWire.FIELD_MASK
        val error = frame.unsignedByte(CcidWire.ERROR_OFFSET)

        return when (commandStatus) {
            CcidWire.COMMAND_STATUS_SUCCEEDED ->
                parseSuccessfulResponse(
                    frame = frame,
                    expectedResponse = command.expectedResponse,
                    cardStatus = cardStatus,
                )
            CcidWire.COMMAND_STATUS_FAILED ->
                CcidCommandFailure(
                    cardStatus = cardStatus,
                    errorCode = error.toSignedByteValue(),
                )
            CcidWire.COMMAND_STATUS_TIME_EXTENSION ->
                CcidTimeExtension(
                    cardStatus = cardStatus,
                    multiplier = error,
                )
            else ->
                throw protocolError(
                    CcidProtocolErrorKind.RESERVED_COMMAND_STATUS,
                    "CCID response uses a reserved command status",
                )
        }
    }

    private fun parseSuccessfulResponse(
        frame: ByteArray,
        expectedResponse: CcidResponseMessageType,
        cardStatus: CcidCardStatus,
    ): CcidResponse =
        when (expectedResponse) {
            CcidResponseMessageType.SLOT_STATUS ->
                CcidSlotStatus(
                    cardStatus = cardStatus,
                    clockStatus =
                        parseClockStatus(
                            frame.unsignedByte(CcidWire.RESPONSE_PARAMETER_OFFSET),
                        ),
                )
            CcidResponseMessageType.DATA_BLOCK ->
                copyDataBlock(
                    frame = frame,
                    cardStatus = cardStatus,
                )
        }

    private fun copyDataBlock(
        frame: ByteArray,
        cardStatus: CcidCardStatus,
    ): CcidDataBlock {
        val payload = frame.copyOfRange(CcidWire.HEADER_SIZE, frame.size)
        return try {
            CcidDataBlock(
                cardStatus = cardStatus,
                chainParameter =
                    parseChainParameter(
                        frame.unsignedByte(CcidWire.RESPONSE_PARAMETER_OFFSET),
                    ),
                payload = payload,
            )
        } finally {
            payload.fill(0)
        }
    }

    private fun parseCardStatus(value: Int): CcidCardStatus =
        when (value) {
            CcidWire.CARD_STATUS_ACTIVE -> CcidCardStatus.ACTIVE
            CcidWire.CARD_STATUS_INACTIVE -> CcidCardStatus.INACTIVE
            CcidWire.CARD_STATUS_NOT_PRESENT -> CcidCardStatus.NOT_PRESENT
            else ->
                throw protocolError(
                    CcidProtocolErrorKind.RESERVED_CARD_STATUS,
                    "CCID response uses a reserved card status",
                )
        }

    private fun parseClockStatus(value: Int): CcidClockStatus =
        when (value) {
            CcidWire.CLOCK_RUNNING -> CcidClockStatus.RUNNING
            CcidWire.CLOCK_STOPPED_LOW -> CcidClockStatus.STOPPED_LOW
            CcidWire.CLOCK_STOPPED_HIGH -> CcidClockStatus.STOPPED_HIGH
            CcidWire.CLOCK_STOPPED_UNKNOWN -> CcidClockStatus.STOPPED_UNKNOWN
            else ->
                throw protocolError(
                    CcidProtocolErrorKind.INVALID_CLOCK_STATUS,
                    "CCID response uses an undefined clock status",
                )
        }

    private fun parseChainParameter(value: Int): CcidChainParameter =
        when (value) {
            CcidWire.COMPLETE_CHAIN -> CcidChainParameter.COMPLETE
            CcidWire.BEGIN_CHAIN -> CcidChainParameter.BEGIN
            CcidWire.END_CHAIN -> CcidChainParameter.END
            CcidWire.CONTINUE_CHAIN -> CcidChainParameter.CONTINUE
            CcidWire.COMMAND_CONTINUATION_EXPECTED ->
                CcidChainParameter.COMMAND_CONTINUATION_EXPECTED
            else ->
                throw protocolError(
                    CcidProtocolErrorKind.INVALID_CHAIN_PARAMETER,
                    "CCID response uses an undefined chain parameter",
                )
        }

    private fun readUnsignedIntLittleEndian(
        bytes: ByteArray,
        offset: Int,
    ): Long =
        bytes.unsignedByte(offset).toLong() or
            (bytes.unsignedByte(offset + 1).toLong() shl 8) or
            (bytes.unsignedByte(offset + 2).toLong() shl 16) or
            (bytes.unsignedByte(offset + 3).toLong() shl 24)

    private fun ByteArray.unsignedByte(offset: Int): Int =
        this[offset].toInt() and CcidWire.BYTE_MAX

    private fun Int.toSignedByteValue(): Int =
        if (this <= Byte.MAX_VALUE) {
            this
        } else {
            this - (CcidWire.BYTE_MAX + 1)
        }

    private fun protocolError(
        kind: CcidProtocolErrorKind,
        message: String,
    ): CcidProtocolException = CcidProtocolException(kind, message)
}
