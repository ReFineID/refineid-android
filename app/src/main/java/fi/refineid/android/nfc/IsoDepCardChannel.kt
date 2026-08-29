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
        get() =
            try {
                isoDep.maxTransceiveLength
            } catch (_: SecurityException) {
                0
            } catch (_: IllegalStateException) {
                0
            }

    override fun transceive(command: ByteArray): NfcTransceiveResult =
        try {
            NfcTransceiveResult.Response(isoDep.transceive(command))
        } catch (_: TagLostException) {
            AppTrace.nfcTagLost()
            NfcTransceiveResult.CardLost
        } catch (_: IOException) {
            AppTrace.nfcTransceiveFailed()
            NfcTransceiveResult.TransceiveFailed
        } catch (_: SecurityException) {
            AppTrace.nfcTagLost()
            NfcTransceiveResult.CardLost
        } catch (_: IllegalStateException) {
            AppTrace.nfcTagLost()
            NfcTransceiveResult.CardLost
        }
}
