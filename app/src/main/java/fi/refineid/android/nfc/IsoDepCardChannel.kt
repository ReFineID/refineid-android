package fi.refineid.android.nfc

import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import fi.refineid.android.diagnostics.AppTrace
import java.io.IOException

/** One discovered ISO-DEP tag, confined to the probe worker thread. */
internal class IsoDepCardChannel(
    private val isoDep: IsoDep,
) : NfcCardChannel {
    override val maximumTransceiveLength: Int
        get() = isoDep.maxTransceiveLength

    override fun transceive(command: ByteArray): NfcTransceiveResult =
        try {
            NfcTransceiveResult.Response(isoDep.transceive(command))
        } catch (_: TagLostException) {
            AppTrace.nfcTagLost()
            NfcTransceiveResult.CardLost
        } catch (_: IOException) {
            AppTrace.nfcTransceiveFailed()
            NfcTransceiveResult.TransceiveFailed
        }
}
