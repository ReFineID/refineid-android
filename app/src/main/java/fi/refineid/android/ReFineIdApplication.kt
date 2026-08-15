package fi.refineid.android

import android.app.Application
import fi.refineid.android.keychain.AndroidExternalKeyCallerLabelResolver
import fi.refineid.android.keychain.ExternalKeyPinPromptBroker
import fi.refineid.android.usb.UsbReaderController

class ReFineIdApplication : Application() {
    internal lateinit var readerController: UsbReaderController
        private set
    internal lateinit var pinPromptBroker: ExternalKeyPinPromptBroker
        private set

    override fun onCreate() {
        super.onCreate()
        readerController = UsbReaderController(this)
        pinPromptBroker =
            ExternalKeyPinPromptBroker(
                context = this,
                callerLabelResolver = AndroidExternalKeyCallerLabelResolver(packageManager),
            )
        readerController.start()
    }

    override fun onTerminate() {
        pinPromptBroker.close()
        readerController.stop()
        super.onTerminate()
    }
}
