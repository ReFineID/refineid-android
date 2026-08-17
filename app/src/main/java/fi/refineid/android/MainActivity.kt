package fi.refineid.android

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.diagnostics.BuildDiagnostics
import fi.refineid.android.nfc.NfcReaderController
import fi.refineid.android.nfc.NfcReaderSnapshot
import fi.refineid.android.ui.MainScreen
import fi.refineid.android.ui.ReFineIdTheme
import fi.refineid.android.usb.UsbReaderController
import fi.refineid.android.usb.UsbReaderSnapshot

class MainActivity : ComponentActivity() {
    private var readerSnapshot by mutableStateOf(UsbReaderSnapshot())
    private var nfcSnapshot by mutableStateOf(NfcReaderSnapshot())
    private lateinit var readerController: UsbReaderController
    private lateinit var nfcReaderController: NfcReaderController
    private val readerStateListener: (UsbReaderSnapshot) -> Unit = { snapshot ->
        readerSnapshot = snapshot
    }
    private val nfcStateListener: (NfcReaderSnapshot) -> Unit = { snapshot ->
        nfcSnapshot = snapshot
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AppTrace.activityCreated()
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        if (!BuildDiagnostics.SCREEN_CAPTURE_ALLOWED) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        window.setHideOverlayWindows(true)
        window.decorView.importantForAutofill =
            View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        window.decorView.importantForContentCapture =
            View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS

        readerController = (application as ReFineIdApplication).readerController
        readerController.addStateListener(readerStateListener)
        nfcReaderController = (application as ReFineIdApplication).nfcReaderController
        nfcReaderController.addStateListener(nfcStateListener)

        setContent {
            ReFineIdTheme {
                MainScreen(
                    snapshot = readerSnapshot,
                    onRequestPermission = readerController::requestPermission,
                    onAuthenticate = readerController::authenticate,
                    browserCardService = readerController,
                    qualifiedCardService = readerController.qualifiedCardService,
                    nfcQualifiedCardService = nfcReaderController.qualifiedCardService,
                    timestampAuthorityRepository =
                        (application as ReFineIdApplication).timestampAuthorityStore,
                    nfcSnapshot = nfcSnapshot,
                    onOpenNfcSettings = ::openNfcSettings,
                    onNfcConnect = nfcReaderController::connect,
                    onForgetPrimedCard = nfcReaderController::forgetPrimedCard,
                    nfcCardService = nfcReaderController.authenticationCardService,
                    pinCache = (application as ReFineIdApplication).authenticationPinCache,
                )
            }
        }
    }

    override fun onStart() {
        super.onStart()
        nfcReaderController.attach(this)
    }

    override fun onStop() {
        nfcReaderController.detach(this)
        super.onStop()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        AppTrace.activityReceivedIntent()
        readerController.refresh()
    }

    override fun onDestroy() {
        AppTrace.activityDestroyed()
        nfcReaderController.removeStateListener(nfcStateListener)
        readerController.removeStateListener(readerStateListener)
        super.onDestroy()
    }

    private fun openNfcSettings() {
        try {
            startActivity(Intent(Settings.ACTION_NFC_SETTINGS))
        } catch (_: ActivityNotFoundException) {
            AppTrace.nfcSettingsUnavailable()
        }
    }
}
