package fi.refineid.android

import android.app.Application
import fi.refineid.android.browser.BundledIssuerCertificates
import fi.refineid.android.core.AuthenticationIssuerCertificateStore
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.keychain.AndroidExternalKeyCallerLabelResolver
import fi.refineid.android.keychain.ExternalKeyPinPromptBroker
import fi.refineid.android.keychain.ExternalKeyProviderRuntime
import fi.refineid.android.keychain.TransportSelectingCardSession
import fi.refineid.android.nfc.NfcReaderController
import fi.refineid.android.prime.PrimedCanStore
import fi.refineid.android.settings.TimestampAuthorityStore
import fi.refineid.android.usb.UsbReaderController

class ReFineIdApplication : Application() {
    internal lateinit var readerController: UsbReaderController
        private set
    internal lateinit var nfcReaderController: NfcReaderController
        private set
    internal val authenticationPinCache = AuthenticationPinCache()
    internal lateinit var pinPromptBroker: ExternalKeyPinPromptBroker
        private set
    internal lateinit var externalKeyProviderRuntime: ExternalKeyProviderRuntime
        private set
    internal lateinit var timestampAuthorityStore: TimestampAuthorityStore
        private set

    override fun onCreate() {
        super.onCreate()
        readerController = UsbReaderController(this)
        nfcReaderController =
            NfcReaderController(
                context = this,
                primedCanStore = PrimedCanStore(this),
                pinCache = authenticationPinCache,
            )
        timestampAuthorityStore = TimestampAuthorityStore(this)
        pinPromptBroker =
            ExternalKeyPinPromptBroker(
                context = this,
                callerLabelResolver = AndroidExternalKeyCallerLabelResolver(packageManager),
            )
        externalKeyProviderRuntime =
            ExternalKeyProviderRuntime(
                cardSession =
                    TransportSelectingCardSession(
                        listOf(
                            readerController.externalKeyCardSession,
                            nfcReaderController.externalKeyCardSession,
                        ),
                    ),
                pinAuthorizer = pinPromptBroker,
                issuerCertificateSource =
                    AuthenticationIssuerCertificateStore(
                        BundledIssuerCertificates.load(this),
                    ),
            )
        readerController.start()
    }

    override fun onTerminate() {
        externalKeyProviderRuntime.close()
        nfcReaderController.stop()
        readerController.stop()
        super.onTerminate()
    }
}
