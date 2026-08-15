package fi.refineid.android

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.view.View
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.ui.MainScreen
import fi.refineid.android.ui.ReFineIdTheme
import fi.refineid.android.usb.UsbReaderController
import fi.refineid.android.usb.UsbReaderSnapshot

class MainActivity : ComponentActivity() {
    private var readerSnapshot by mutableStateOf(UsbReaderSnapshot())
    private lateinit var readerController: UsbReaderController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AppTrace.activityCreated()
        window.addFlags(
            WindowManager.LayoutParams.FLAG_SECURE or
                WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON,
        )
        window.decorView.importantForAutofill =
            View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        window.decorView.importantForContentCapture =
            View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS

        readerController =
            UsbReaderController(this) { snapshot ->
                readerSnapshot = snapshot
            }
        readerController.start()

        setContent {
            ReFineIdTheme {
                MainScreen(
                    snapshot = readerSnapshot,
                    onRequestPermission = readerController::requestPermission,
                    onAuthenticate = readerController::authenticate,
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        AppTrace.activityReceivedIntent()
        readerController.refresh()
    }

    override fun onDestroy() {
        AppTrace.activityDestroyed()
        readerController.stop()
        super.onDestroy()
    }
}
