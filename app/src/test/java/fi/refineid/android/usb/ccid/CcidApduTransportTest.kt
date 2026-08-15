package fi.refineid.android.usb.ccid

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class CcidBlockTransportTest {
    @Test
    fun tracePolicyRedactsEveryVerifyShape() {
        val shortVerify = byteArrayOf(PLAIN_CLASS, VERIFY_INSTRUCTION)
        val completeVerify =
            byteArrayOf(
                PLAIN_CLASS,
                VERIFY_INSTRUCTION,
                SYNTHETIC_PARAMETER,
                SYNTHETIC_PARAMETER,
            )
        val publicSelect =
            byteArrayOf(
                PLAIN_CLASS,
                SELECT_INSTRUCTION,
                SYNTHETIC_PARAMETER,
                SYNTHETIC_PARAMETER,
            )

        assertEquals(CcidBlockTraceKind.SENSITIVE, CcidBlockTracePolicy.classify(shortVerify))
        assertEquals(CcidBlockTraceKind.SENSITIVE, CcidBlockTracePolicy.classify(completeVerify))
        assertEquals(CcidBlockTraceKind.PUBLIC, CcidBlockTracePolicy.classify(publicSelect))
        assertEquals(CcidBlockTraceKind.PUBLIC, CcidBlockTracePolicy.classify(byteArrayOf()))
    }

    @Test
    fun returnsCompleteBlockResponseAndClearsTransferBuffers() {
        val io =
            ScriptedBulkIo(
                responses =
                    listOf(
                        responseFrame(
                            payload =
                                byteArrayOf(
                                    SYNTHETIC_RESPONSE_BYTE,
                                    ISO_STATUS_SUCCESS_FIRST,
                                    ISO_STATUS_SUCCESS_SECOND,
                                ),
                        ),
                    ),
            )
        val transport = transport(io)
        val block = syntheticBlock()

        val result = transport.transmitPublic(block) as CcidBlockResult.Response

        assertArrayEquals(
            byteArrayOf(
                SYNTHETIC_RESPONSE_BYTE,
                ISO_STATUS_SUCCESS_FIRST,
                ISO_STATUS_SUCCESS_SECOND,
            ),
            result.copyPayload(),
        )
        assertEquals(
            "CcidBlockResult.Response(payloadLength=3)",
            result.toString(),
        )
        assertEquals(1, result.responseBodyLength)
        assertEquals(ISO_STATUS_SUCCESS, result.statusWord)
        assertArrayEquals(block, io.writtenFrames.single().blockPayload())
        assertTrue(requireNotNull(io.lastWriteBuffer).all { byte -> byte == ZERO_BYTE })
        assertTrue(requireNotNull(io.lastReadBuffer).all { byte -> byte == ZERO_BYTE })
        assertArrayEquals(syntheticBlock(), block)

        result.close()
        assertThrows(IllegalStateException::class.java) {
            result.copyPayload()
        }
        assertThrows(IllegalStateException::class.java) {
            result.statusWord
        }
        io.close()
    }

    @Test
    fun waitsForTimeExtensionsWithoutResendingTheCommand() {
        val responses =
            List(MAXIMUM_TIME_EXTENSIONS) {
                responseFrame(
                    commandStatus = CcidWire.COMMAND_STATUS_TIME_EXTENSION,
                    error = TIME_EXTENSION_MULTIPLIER,
                )
            } +
                responseFrame(
                    payload =
                        byteArrayOf(
                            ISO_STATUS_SUCCESS_FIRST,
                            ISO_STATUS_SUCCESS_SECOND,
                        ),
                )
        val io = ScriptedBulkIo(responses)

        val result = transport(io).transmitPublic(syntheticBlock())

        assertTrue(result is CcidBlockResult.Response)
        assertEquals(1, io.writtenFrames.size)
        assertEquals(MAXIMUM_TIME_EXTENSIONS + 1, io.readCount)
        (result as CcidBlockResult.Response).close()
        io.close()
    }

    @Test
    fun rejectsTimeExtensionPastTheBound() {
        val io =
            ScriptedBulkIo(
                List(MAXIMUM_TIME_EXTENSIONS + 1) {
                    responseFrame(
                        commandStatus = CcidWire.COMMAND_STATUS_TIME_EXTENSION,
                        error = TIME_EXTENSION_MULTIPLIER,
                    )
                },
            )

        val result = transport(io).transmitPublic(syntheticBlock())

        assertEquals(
            CcidBlockResult.Failure(CcidBlockFailureKind.PROTOCOL),
            result,
        )
        assertEquals(1, io.writtenFrames.size)
        io.close()
    }

    @Test
    fun credentialEntryPointClearsInputOnEveryOutcome() {
        val successfulCredential = syntheticBlock()
        val successIo =
            ScriptedBulkIo(
                listOf(
                    responseFrame(
                        payload =
                            byteArrayOf(
                                ISO_STATUS_SUCCESS_FIRST,
                                ISO_STATUS_SUCCESS_SECOND,
                            ),
                    ),
                ),
            )
        val success = transport(successIo).transmitCredential(successfulCredential)

        assertTrue(success is CcidBlockResult.Response)
        assertTrue(successfulCredential.all { byte -> byte == ZERO_BYTE })
        (success as CcidBlockResult.Response).close()
        successIo.close()

        val failedCredential = syntheticBlock()
        val failureIo = ScriptedBulkIo(responses = emptyList(), writeCount = -1)
        val failure = transport(failureIo).transmitCredential(failedCredential)

        assertEquals(
            CcidBlockResult.Failure(CcidBlockFailureKind.TRANSPORT),
            failure,
        )
        assertTrue(failedCredential.all { byte -> byte == ZERO_BYTE })
        failureIo.close()

        val rejectedCredential = ByteArray(MINIMUM_BLOCK_LENGTH - 1) { SYNTHETIC_BLOCK_BYTE }
        val rejectionIo = ScriptedBulkIo(emptyList())
        val rejection = transport(rejectionIo).transmitCredential(rejectedCredential)

        assertEquals(
            CcidBlockResult.Failure(CcidBlockFailureKind.COMMAND_REJECTED),
            rejection,
        )
        assertTrue(rejectedCredential.all { byte -> byte == ZERO_BYTE })
        assertTrue(rejectionIo.writtenFrames.isEmpty())
    }

    @Test
    fun rejectsBlockAboveValidatedReaderBoundWithoutWriting() {
        val io = ScriptedBulkIo(emptyList())
        val block = ByteArray(MAXIMUM_TRANSFER_BLOCK_LENGTH + 1) { SYNTHETIC_BLOCK_BYTE }

        val result = transport(io).transmitPublic(block)

        assertEquals(
            CcidBlockResult.Failure(CcidBlockFailureKind.COMMAND_REJECTED),
            result,
        )
        assertTrue(io.writtenFrames.isEmpty())
        assertTrue(block.all { byte -> byte == SYNTHETIC_BLOCK_BYTE })
    }

    @Test
    fun mapsShortBlockResponseToProtocolFailure() {
        val io =
            ScriptedBulkIo(
                listOf(
                    responseFrame(
                        payload = byteArrayOf(ISO_STATUS_SUCCESS_FIRST),
                    ),
                ),
            )

        val result = transport(io).transmitPublic(syntheticBlock())

        assertEquals(
            CcidBlockResult.Failure(CcidBlockFailureKind.PROTOCOL),
            result,
        )
        io.close()
    }

    @Test
    fun mapsMalformedCcidResponseToProtocolFailure() {
        val malformed = responseFrame(payload = byteArrayOf())
        malformed[CcidWire.SEQUENCE_OFFSET] = OTHER_SEQUENCE.toByte()
        val io = ScriptedBulkIo(listOf(malformed))

        val result = transport(io).transmitPublic(syntheticBlock())

        assertEquals(
            CcidBlockResult.Failure(CcidBlockFailureKind.PROTOCOL),
            result,
        )
        io.close()
    }

    @Test
    fun mapsCardAndReaderFailuresWithoutReturningPayload() {
        val inactiveIo =
            ScriptedBulkIo(
                listOf(
                    responseFrame(
                        cardStatus = CcidWire.CARD_STATUS_INACTIVE,
                        payload =
                            byteArrayOf(
                                ISO_STATUS_SUCCESS_FIRST,
                                ISO_STATUS_SUCCESS_SECOND,
                            ),
                    ),
                ),
            )
        assertEquals(
            CcidBlockResult.Failure(CcidBlockFailureKind.CARD_UNAVAILABLE),
            transport(inactiveIo).transmitPublic(syntheticBlock()),
        )
        inactiveIo.close()

        val readerFailureIo =
            ScriptedBulkIo(
                listOf(
                    responseFrame(
                        commandStatus = CcidWire.COMMAND_STATUS_FAILED,
                        error = SYNTHETIC_READER_ERROR,
                    ),
                ),
            )
        assertEquals(
            CcidBlockResult.Failure(CcidBlockFailureKind.READER),
            transport(readerFailureIo).transmitPublic(syntheticBlock()),
        )
        readerFailureIo.close()
    }

    @Test
    fun rejectsCcidResponseChainingAtBlockExchangeLevel() {
        val io =
            ScriptedBulkIo(
                listOf(
                    responseFrame(
                        responseParameter = CcidWire.BEGIN_CHAIN,
                        payload =
                            byteArrayOf(
                                ISO_STATUS_SUCCESS_FIRST,
                                ISO_STATUS_SUCCESS_SECOND,
                            ),
                    ),
                ),
            )

        val result = transport(io).transmitPublic(syntheticBlock())

        assertEquals(
            CcidBlockResult.Failure(CcidBlockFailureKind.PROTOCOL),
            result,
        )
        io.close()
    }

    private fun transport(io: CcidBulkIo): CcidBlockTransport =
        CcidBlockTransport(
            exchange =
                CcidCommandExchange(
                    bulkIo = io,
                    maximumMessageLength = MAXIMUM_CCID_MESSAGE_LENGTH,
                    maximumTimeExtensions = MAXIMUM_TIME_EXTENSIONS,
                ),
            maximumBlockLength = MAXIMUM_TRANSFER_BLOCK_LENGTH,
            sequenceCounter = CcidSequenceCounter(TEST_SEQUENCE),
        )

    private fun syntheticBlock(): ByteArray =
        ByteArray(MINIMUM_BLOCK_LENGTH) { SYNTHETIC_BLOCK_BYTE }

    private fun responseFrame(
        cardStatus: Int = CcidWire.CARD_STATUS_ACTIVE,
        commandStatus: Int = CcidWire.COMMAND_STATUS_SUCCEEDED,
        error: Int = 0,
        responseParameter: Int = CcidWire.COMPLETE_CHAIN,
        payload: ByteArray = byteArrayOf(),
    ): ByteArray =
        ByteArray(CcidWire.HEADER_SIZE + payload.size).apply {
            this[CcidWire.MESSAGE_TYPE_OFFSET] = CcidWire.RDR_TO_PC_DATA_BLOCK.toByte()
            writeLength(payload.size)
            this[CcidWire.SLOT_OFFSET] = FIRST_SLOT.toByte()
            this[CcidWire.SEQUENCE_OFFSET] = TEST_SEQUENCE.toByte()
            this[CcidWire.STATUS_OFFSET] =
                (
                    cardStatus or
                        (commandStatus shl CcidWire.COMMAND_STATUS_SHIFT)
                ).toByte()
            this[CcidWire.ERROR_OFFSET] = error.toByte()
            this[CcidWire.RESPONSE_PARAMETER_OFFSET] = responseParameter.toByte()
            payload.copyInto(this, destinationOffset = CcidWire.HEADER_SIZE)
        }

    private fun ByteArray.writeLength(length: Int) {
        repeat(LENGTH_FIELD_SIZE) { index ->
            this[CcidWire.LENGTH_OFFSET + index] =
                (length ushr (index * Byte.SIZE_BITS)).toByte()
        }
    }

    private fun ByteArray.blockPayload(): ByteArray =
        copyOfRange(CcidWire.HEADER_SIZE, size)

    private class ScriptedBulkIo(
        responses: List<ByteArray>,
        private val writeCount: Int? = null,
    ) : CcidBulkIo,
        AutoCloseable {
        private val pendingResponses = responses.map { response -> response.copyOf() }.toMutableList()

        val writtenFrames = mutableListOf<ByteArray>()
        var lastWriteBuffer: ByteArray? = null
            private set
        var lastReadBuffer: ByteArray? = null
            private set
        var readCount = 0
            private set

        override fun write(frame: ByteArray): Int {
            lastWriteBuffer = frame
            writtenFrames += frame.copyOf()
            return writeCount ?: frame.size
        }

        override fun read(frame: ByteArray): Int {
            readCount += 1
            lastReadBuffer = frame
            if (pendingResponses.isEmpty()) {
                return -1
            }

            val response = pendingResponses.removeAt(0)
            return try {
                if (response.size <= frame.size) {
                    response.copyInto(frame)
                }
                response.size
            } finally {
                response.fill(0)
            }
        }

        override fun close() {
            pendingResponses.forEach { response -> response.fill(0) }
            writtenFrames.forEach { frame -> frame.fill(0) }
        }
    }

    private companion object {
        const val FIRST_SLOT = 0
        const val TEST_SEQUENCE = 29
        const val OTHER_SEQUENCE = TEST_SEQUENCE + 1
        const val LENGTH_FIELD_SIZE = 4
        const val MINIMUM_BLOCK_LENGTH = 4
        const val MAXIMUM_TRANSFER_BLOCK_LENGTH = 261
        const val MAXIMUM_CCID_MESSAGE_LENGTH =
            CcidWire.HEADER_SIZE + MAXIMUM_TRANSFER_BLOCK_LENGTH
        const val MAXIMUM_TIME_EXTENSIONS = 8
        const val TIME_EXTENSION_MULTIPLIER = 2
        const val SYNTHETIC_BLOCK_BYTE: Byte = 0x55
        const val SYNTHETIC_RESPONSE_BYTE: Byte = 0x2A
        const val ISO_STATUS_SUCCESS_FIRST: Byte = -112
        const val ISO_STATUS_SUCCESS_SECOND: Byte = 0x00
        const val ISO_STATUS_SUCCESS = 0x9000
        const val SYNTHETIC_READER_ERROR = 1
        const val PLAIN_CLASS: Byte = 0x00
        const val VERIFY_INSTRUCTION: Byte = 0x20
        const val SELECT_INSTRUCTION: Byte = -92
        const val SYNTHETIC_PARAMETER: Byte = 0x55
        const val ZERO_BYTE: Byte = 0
    }
}
