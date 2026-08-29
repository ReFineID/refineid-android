package fi.refineid.android.nfc

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Handler
import android.os.Looper
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.CardPhotoStore
import fi.refineid.android.core.CertificateHolderName
import fi.refineid.android.core.NativeCardExchangeLevel
import fi.refineid.android.core.NativeCardSessionMaterial
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeContactlessCore
import fi.refineid.android.core.NativeContactlessOpenResult
import fi.refineid.android.core.NativeContactlessSession
import fi.refineid.android.core.NativeCore
import fi.refineid.android.core.PersonCardDetails
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.keychain.nextProviderGeneration
import fi.refineid.android.prime.PrimedCanStore
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * Contactless discovery and card sessions bound to one foreground
 * activity. Reader mode delivers each discovered tag once; recognition
 * runs a credential-free EF.CardAccess probe, and a holder-entered CAN
 * opens a contactless session whose every operation re-runs PACE inside
 * one bounded ISO-DEP connection on a dedicated worker thread.
 */
internal class NfcReaderController(
    context: Context,
    private val primedCanStore: PrimedCanStore,
    private val pinCache: AuthenticationPinCache,
) {
    private val applicationContext = context.applicationContext
    private val adapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(applicationContext)
    private val mainHandler = Handler(Looper.getMainLooper())
    private val probeExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val stateListeners = linkedSetOf<(NfcReaderSnapshot) -> Unit>()

    @Volatile
    private var latestSnapshot = NfcReaderSnapshot()

    @Volatile
    private var attachedActivity: Activity? = null

    @Volatile
    private var probeGeneration = 0

    /** Last ISO-DEP tag left resting in the field; worker-thread I/O only. */
    @Volatile
    private var latestIsoDep: IsoDep? = null

    /** Suppresses redundant recognition re-probes of a resting card. */
    private val reprobeThrottle = NfcReprobeThrottle()

    // Worker-thread confined. Main-thread state never owns a session.
    private var activeSession: ContactlessSession? = null
    private var activeProviderGeneration: Long? = null
    private val providerGenerationRandom = SecureRandom()

    @Volatile
    private var primedCardStored = primedCanStore.isPrimed()

    // Tap-to-sign: a qualified signature waits for the holder to present
    // the card instead of requiring a pre-opened session. Confined to the
    // shared worker thread for session mutation; the transient session it
    // opens is the same one the qualified card service serves.
    internal val tapToSign =
        NfcTapToSign(
            probeExecutor = probeExecutor,
            mainHandler = mainHandler,
            latestIsoDep = { latestIsoDep },
            primedCan = { primedCanStore.read() },
            activeSession = { activeSession },
            adoptSession = { session -> activeSession = session },
            closeSession = { closeActiveSession() },
        )

    internal val authenticationCardService =
        NfcAuthenticationCardService(
            probeExecutor = probeExecutor,
            mainHandler = mainHandler,
            isReady = { latestSnapshot.status == NfcReaderStatus.CARD_READY },
            currentGeneration = { probeGeneration },
            activeSession = { activeSession },
            onCardLost = { generation ->
                closeActiveSession()
                publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD)
            },
        )

    internal val qualifiedCardService =
        NfcQualifiedCardService(
            probeExecutor = probeExecutor,
            mainHandler = mainHandler,
            isReady = {
                latestSnapshot.status == NfcReaderStatus.CARD_READY || tapToSign.inProgress
            },
            currentGeneration = { probeGeneration },
            activeSession = { activeSession },
        )

    internal val externalKeyCardSession =
        NfcExternalKeyCardSession(
            probeExecutor = probeExecutor,
            isAvailable = { latestSnapshot.status == NfcReaderStatus.CARD_READY },
            activeSession = { activeSession },
            activeProviderGeneration = { activeProviderGeneration },
            onCardLost = {
                val generation = probeGeneration
                closeActiveSession()
                publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD)
            },
        )

    private val adapterStateReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(
                context: Context?,
                intent: Intent?,
            ) {
                if (intent?.action == NfcAdapter.ACTION_ADAPTER_STATE_CHANGED) {
                    AppTrace.nfcAdapterStateChanged()
                    refreshReaderMode()
                }
            }
        }

    private val readerCallback =
        NfcAdapter.ReaderCallback { tag -> onTagDiscovered(tag) }

    fun attach(activity: Activity) {
        checkMainThread()
        attachedActivity = activity
        if (adapter == null) {
            AppTrace.nfcAdapterMissing()
            publish(NfcReaderSnapshot(status = NfcReaderStatus.NOT_AVAILABLE))
            return
        }
        applicationContext.registerReceiver(
            adapterStateReceiver,
            IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED),
            Context.RECEIVER_EXPORTED,
        )
        refreshReaderMode()
    }

    // The session outlives the activity: the privileged provider serves
    // a foreground browser while this app is stopped, so only adapter
    // loss, card loss, replacement, or process stop closes it.
    fun detach(activity: Activity) {
        checkMainThread()
        if (attachedActivity !== activity) {
            return
        }
        attachedActivity = null
        if (adapter != null) {
            applicationContext.unregisterReceiver(adapterStateReceiver)
            adapter.disableReaderMode(activity)
            AppTrace.nfcReaderModeChanged(isEnabled = false)
        }
    }

    fun stop() {
        probeGeneration += 1
        latestIsoDep = null
        tapToSign.cancel()
        probeExecutor.execute(::closeActiveSession)
        probeExecutor.shutdown()
    }

    fun addStateListener(listener: (NfcReaderSnapshot) -> Unit) {
        checkMainThread()
        stateListeners += listener
        listener(latestSnapshot)
    }

    fun removeStateListener(listener: (NfcReaderSnapshot) -> Unit) {
        checkMainThread()
        stateListeners -= listener
    }

    /**
     * Open a contactless session and hold PIN1 for the session. A
     * supplied access number is minted for tap-to-open; a null one
     * reuses the minted access number for a PIN-only unlock.
     */
    fun connect(
        can: CanSubmission?,
        pin1: Pin1Submission,
    ) {
        checkMainThread()
        if (
            latestSnapshot.status != NfcReaderStatus.CARD_RECOGNIZED &&
            latestSnapshot.status != NfcReaderStatus.WRONG_CAN &&
            latestSnapshot.status != NfcReaderStatus.TRANSPORT_ERROR
        ) {
            can?.close()
            pin1.close()
            AppTrace.nfcConnectIgnored()
            return
        }
        val generation = probeGeneration
        publish(NfcReaderSnapshot(status = NfcReaderStatus.CONNECTING))
        AppTrace.nfcConnectStarted()
        can?.let { CanSessionStore.remember(it) }
        try {
            probeExecutor.execute {
                val mint = can != null
                val canBytes = can?.transfer() ?: CanSessionStore.canBytes() ?: primedCanStore.read()
                if (canBytes == null) {
                    pin1.close()
                    publishAsync(generation, NfcReaderStatus.CARD_RECOGNIZED)
                    return@execute
                }
                openSessionBytes(canBytes, generation, mintOnSuccess = mint, pin1 = pin1)
            }
        } catch (_: RejectedExecutionException) {
            can?.close()
            pin1.close()
        }
    }

    private fun refreshReaderMode() {
        checkMainThread()
        val activity = attachedActivity ?: return
        val nfcAdapter = adapter ?: return
        if (nfcAdapter.isEnabled) {
            nfcAdapter.enableReaderMode(
                activity,
                readerCallback,
                READER_MODE_FLAGS,
                null,
            )
            AppTrace.nfcReaderModeChanged(isEnabled = true)
            if (latestSnapshot.status != NfcReaderStatus.CARD_READY) {
                probeGeneration += 1
                publish(NfcReaderSnapshot(status = NfcReaderStatus.WAITING_FOR_CARD))
            }
        } else {
            nfcAdapter.disableReaderMode(activity)
            AppTrace.nfcReaderModeChanged(isEnabled = false)
            probeGeneration += 1
            try {
                probeExecutor.execute(::closeActiveSession)
            } catch (_: RejectedExecutionException) {
                // The executor only stops when the process is terminating.
            }
            publish(NfcReaderSnapshot(status = NfcReaderStatus.TURNED_OFF))
        }
    }

    /** Reader-mode callback; arrives on an NFC system thread. */
    private fun onTagDiscovered(tag: Tag) {
        val generation = probeGeneration
        val isoDep = IsoDep.get(tag)
        AppTrace.nfcTagDiscovered(isIsoDep = isoDep != null)
        // The stack re-polls a resting card after each closed connection;
        // an open session survives that by adopting the fresh handle.
        // Card substitution is safe here: every operation starts with
        // PACE against the session CAN, so a different card fails the
        // handshake before any credential could reach it.
        val isSessionActive = latestSnapshot.status == NfcReaderStatus.CARD_READY
        if (isoDep == null) {
            if (!isSessionActive) {
                publishAsync(generation, NfcReaderStatus.CARD_NOT_SUPPORTED)
            }
            return
        }
        latestIsoDep = isoDep
        // A tap-to-sign in progress claims the tag before recognition, so
        // signing never depends on a card already resting in the field.
        if (tapToSign.inProgress) {
            try {
                probeExecutor.execute {
                    tapToSign.onTag(isoDep)
                }
            } catch (_: RejectedExecutionException) {
                AppTrace.nfcProbeResultDiscarded()
            }
            return
        }
        if (isSessionActive) {
            try {
                probeExecutor.execute {
                    adoptRestingTag(isoDep, generation)
                }
            } catch (_: RejectedExecutionException) {
                AppTrace.nfcProbeResultDiscarded()
            }
            return
        }
        if (reprobeThrottle.shouldSkip(latestSnapshot.status)) {
            // The resting card is already recognized; the stack re-polls it
            // after every closed connection, so re-probing on each poll only
            // re-runs the public read to the same result. latestIsoDep above
            // stays fresh so a pending unlock uses the newest handle.
            return
        }
        publishAsync(generation, NfcReaderStatus.CHECKING)
        try {
            probeExecutor.execute {
                probe(isoDep, generation)
            }
        } catch (_: RejectedExecutionException) {
            AppTrace.nfcProbeResultDiscarded()
        }
    }

    /** Worker-thread confined; the resting card was re-polled by the stack. */
    private fun adoptRestingTag(
        isoDep: IsoDep,
        generation: Int,
    ) {
        val session = activeSession
        if (session == null || generation != probeGeneration) {
            AppTrace.nfcProbeResultDiscarded()
            return
        }
        AppTrace.nfcTagAdopted()
        session.adopt(isoDep)
    }

    /** Worker-thread confined; owns the ISO-DEP connection. */
    private fun probe(
        isoDep: IsoDep,
        generation: Int,
    ) {
        reprobeThrottle.onProbe()
        closeActiveSession()
        if (generation != probeGeneration) {
            AppTrace.nfcProbeResultDiscarded()
            return
        }
        try {
            isoDep.connect()
            isoDep.timeout = TRANSCEIVE_TIMEOUT_MILLISECONDS
        } catch (_: IOException) {
            AppTrace.nfcSessionOpenFailed()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD)
            return
        } catch (_: SecurityException) {
            AppTrace.nfcSessionOpenFailed()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD)
            return
        } catch (_: IllegalStateException) {
            AppTrace.nfcSessionOpenFailed()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD)
            return
        }
        val result =
            NativeContactlessCore.probeCardAccess(
                exchangeLevel = NativeCardExchangeLevel.APDU,
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        try {
            isoDep.close()
        } catch (_: IOException) {
            // The tag may already be gone; the probe result stands.
        } catch (_: SecurityException) {
            // The tag handle is out of date.
        } catch (_: IllegalStateException) {
            // Tag service unavailable.
        }
        AppTrace.nfcSessionClosed()
        // A primed card still needs PIN1 to unlock; the UI shows a
        // PIN-only prompt on this recognized state.
        publishAsync(generation, result.toReaderStatus())
    }

    /**
     * Worker-thread confined; runs PACE, certificate read, and
     * preflight, owning and zeroizing the transferred digits.
     */
    private fun openSessionBytes(
        canBytes: ByteArray,
        generation: Int,
        mintOnSuccess: Boolean,
        pin1: Pin1Submission,
    ) {
        closeActiveSession()
        val isoDep = latestIsoDep
        if (isoDep == null || generation != probeGeneration) {
            canBytes.fill(0)
            pin1.close()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD)
            return
        }
        try {
            if (!isoDep.isConnected) {
                isoDep.connect()
                isoDep.timeout = TRANSCEIVE_TIMEOUT_MILLISECONDS
            }
        } catch (_: IOException) {
            canBytes.fill(0)
            pin1.close()
            AppTrace.nfcSessionOpenFailed()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD)
            return
        } catch (_: SecurityException) {
            canBytes.fill(0)
            pin1.close()
            AppTrace.nfcSessionOpenFailed()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD)
            return
        } catch (_: IllegalStateException) {
            canBytes.fill(0)
            pin1.close()
            AppTrace.nfcSessionOpenFailed()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD)
            return
        }
        val exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep))
        val material = NativeCardSessionMaterial()
        val opened = NativeContactlessSession.connect(canBytes.copyOf(), exchange)
        val status =
            when (opened) {
                is NativeContactlessOpenResult.Success -> {
                    material.cacheAuthenticationCertificate(opened.certificate)
                    material.cachePin1Preflight(opened.preflight)
                    NfcReaderStatus.CARD_READY
                }

                is NativeContactlessOpenResult.Failure -> {
                    opened.kind.toConnectStatus()
                }
            }
        if (status == NfcReaderStatus.CARD_READY && generation == probeGeneration) {
            CanSessionStore.remember(String(canBytes, Charsets.US_ASCII))
            val photoBytes = NativeCore.readCardFacePhoto()
            val cardDetails: PersonCardDetails? =
                if (opened is NativeContactlessOpenResult.Success) {
                    try {
                        PersonCardDetails.fromDer(opened.certificate.copyDer(), photoBytes)
                    } catch (_: Exception) {
                        null
                    }
                } else {
                    null
                }
            val holderName =
                cardDetails?.holderName ?: if (opened is NativeContactlessOpenResult.Success) {
                    CertificateHolderName.fromCertificate(opened.certificate)
                } else {
                    null
                }
            if (photoBytes != null && photoBytes.isNotEmpty()) {
                CardPhotoStore.savePhoto(photoBytes, holderName)
            }
            if (mintOnSuccess) {
                primedCanStore.write(canBytes.copyOf())
                primedCanStore.writeHolderName(holderName)
                primedCardStored = true
                AppTrace.nfcPrimedMinted()
            }
            // Hold PIN1 for the session so browser signing needs no
            // prompt; the negative cache guards a genuinely wrong value.
            pin1.copyBytes()?.let(pinCache::recordVerified)
            pin1.close()
            // Keep the field connected: the PACE session opened just now is
            // held so the sign that follows reuses it with no second handshake.
            activeSession =
                ContactlessSession(
                    isoDep = isoDep,
                    can = canBytes,
                    material = material,
                    heldSession = true,
                )
            activeProviderGeneration = providerGenerationRandom.nextProviderGeneration()
            publishAsync(generation, status, holderName = holderName, cardDetails = cardDetails)
            return
        } else {
            pin1.close()
            if (status == NfcReaderStatus.WRONG_CAN) {
                // The access number no longer opens this card.
                CanSessionStore.drop()
                primedCanStore.clear()
                primedCardStored = false
            }
            canBytes.fill(0)
            material.close()
            // Drop any session the connect retained and release the field.
            NativeContactlessSession.close()
            try {
                isoDep.close()
            } catch (_: IOException) {
                // The tag may already be gone.
            } catch (_: SecurityException) {
                // Tag is out of date.
            } catch (_: IllegalStateException) {
                // Tag service unavailable.
            }
            AppTrace.nfcSessionClosed()
        }
        publishAsync(generation, status)
    }

    private fun closeActiveSession() {
        activeProviderGeneration = null
        activeSession?.close()
        activeSession = null
    }

    /** Forget the primed card so the next tap requires the access number again. */
    fun forgetPrimedCard() {
        checkMainThread()
        AppTrace.nfcPrimedForgotten()
        CanSessionStore.drop()
        try {
            probeExecutor.execute {
                CanSessionStore.drop()
                primedCanStore.clear()
                primedCardStored = false
                pinCache.clear()
                closeActiveSession()
                probeGeneration += 1
                mainHandler.post { publish(NfcReaderSnapshot(status = NfcReaderStatus.WAITING_FOR_CARD)) }
            }
        } catch (_: RejectedExecutionException) {
            // The executor only stops when the process is terminating.
        }
    }

    private fun publishAsync(
        generation: Int,
        status: NfcReaderStatus,
        isPrimedOpening: Boolean = false,
        holderName: String? = null,
        cardDetails: PersonCardDetails? = null,
    ) {
        mainHandler.post {
            if (generation == probeGeneration) {
                publish(
                    NfcReaderSnapshot(
                        status = status,
                        isPrimed = primedCardStored,
                        isPrimedOpening = isPrimedOpening,
                        holderName = holderName,
                        cardDetails = cardDetails,
                    ),
                )
            } else {
                AppTrace.nfcProbeResultDiscarded()
            }
        }
    }

    private fun publish(snapshot: NfcReaderSnapshot) {
        val holder = if (primedCardStored) primedCanStore.readHolderName() else snapshot.holderName
        val details = snapshot.cardDetails ?: holder?.let { PersonCardDetails.fromHolderName(it) }
        latestSnapshot = snapshot.copy(isPrimed = primedCardStored, holderName = holder, cardDetails = details)
        AppTrace.nfcSnapshotPublished(latestSnapshot.status)
        stateListeners.toList().forEach { listener -> listener(latestSnapshot) }
    }

    private fun checkMainThread() {
        check(Looper.myLooper() == Looper.getMainLooper()) {
            "NFC reader state must be changed on the main thread"
        }
    }

    private companion object {
        /** ISO-DEP over NFC-A or NFC-B; the card carries no NDEF. */
        const val READER_MODE_FLAGS =
            NfcAdapter.FLAG_READER_NFC_A or
                NfcAdapter.FLAG_READER_NFC_B or
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK

        /** Bound on one contactless exchange, PACE cryptography included. */
        const val TRANSCEIVE_TIMEOUT_MILLISECONDS = 4_000
    }
}
