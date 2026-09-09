package fi.refineid.android.nfc

/** Typed outcome of one contactless transceive. */
internal sealed interface NfcTransceiveResult {
    /** Raw card response including trailing SW1 and SW2. */
    class Response(
        val bytes: ByteArray,
    ) : NfcTransceiveResult {
        override fun toString(): String = "Response(length=" + bytes.size + ")"
    }

    /** The card left the field. */
    data object CardLost : NfcTransceiveResult

    /** The exchange failed with uncertain card state. */
    data object TransceiveFailed : NfcTransceiveResult
}

/** One connected contactless card, confined to the probe worker thread. */
internal interface NfcCardChannel {
    /** Largest command the channel accepts in one transceive. */
    val maximumTransceiveLength: Int

    fun transceive(command: ByteArray): NfcTransceiveResult
}
