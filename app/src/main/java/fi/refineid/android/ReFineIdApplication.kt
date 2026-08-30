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
    internal lateinit var rappAuthorizationInbox: fi.refineid.android.rapp.RappAuthorizationInbox
        private set
    internal lateinit var rappPairCatalog: fi.refineid.android.rapp.RappPairCatalog
        private set

    override fun onCreate() {
        super.onCreate()
        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            fi.refineid.android.diagnostics.AppTrace
                .uncaughtException(thread, throwable)
            defaultHandler?.uncaughtException(thread, throwable)
        }
        fi.refineid.android.core.CardPhotoStore
            .initialize(java.io.File(filesDir, CARD_PHOTO_CACHE_DIRECTORY))
        fi.refineid.android.core.NativeVerification
            .installCscaAnchors(loadCscaAnchorAssets())
        readerController = UsbReaderController(this)
        nfcReaderController =
            NfcReaderController(
                context = this,
                primedCanStore = PrimedCanStore(this),
                pinCache = authenticationPinCache,
            )
        timestampAuthorityStore = TimestampAuthorityStore(this)
        rappAuthorizationInbox =
            fi.refineid.android.rapp
                .RappAuthorizationInbox(this)
        rappPairCatalog =
            fi.refineid.android.rapp
                .RappPairCatalog(this)
        pinPromptBroker =
            ExternalKeyPinPromptBroker(
                context = this,
                callerLabelResolver = AndroidExternalKeyCallerLabelResolver(packageManager),
                pinCache = authenticationPinCache,
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

    // The CSCA trust anchors that close passive authentication's
    // DSC-to-CSCA hop. One DER certificate per file, grouped by issuing
    // state (csca/fi, later csca/ee); anchors ship with the app because
    // a card can never vouch for itself.
    private fun loadCscaAnchorAssets(): List<ByteArray> {
        val anchors = mutableListOf<ByteArray>()

        fun walk(path: String) {
            val children =
                try {
                    assets.list(path).orEmpty()
                } catch (_: java.io.IOException) {
                    return
                }
            if (children.isEmpty()) {
                try {
                    anchors.add(assets.open(path).use { stream -> stream.readBytes() })
                } catch (_: java.io.IOException) {
                    // A missing or unreadable anchor file surfaces as an
                    // unverified read, never as a crash.
                }
            } else {
                for (child in children) {
                    walk("$path/$child")
                }
            }
        }
        walk(CSCA_ANCHOR_ASSET_DIRECTORY)
        return anchors
    }

    private companion object {
        const val CARD_PHOTO_CACHE_DIRECTORY = "card-photos"
        const val CSCA_ANCHOR_ASSET_DIRECTORY = "csca"
    }
}
