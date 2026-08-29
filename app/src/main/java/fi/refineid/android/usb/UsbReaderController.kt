package fi.refineid.android.usb

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Handler
import android.os.Looper
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeContactlessOpenResult
import fi.refineid.android.core.NativeCore
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.keychain.nextProviderGeneration
import fi.refineid.android.usb.ccid.CcidSessionOpenResult
import fi.refineid.android.usb.ccid.CcidUsbSession
import fi.refineid.android.usb.ccid.CcidUsbSessionOpener
import java.io.ByteArrayInputStream
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

internal enum class ReaderConnectionStatus {
    NOT_CONNECTED,
    PERMISSION_REQUIRED,
    CHECKING,
    READY,
    PERMISSION_REQUEST_FAILED,
    CARD_ERROR,
    TRANSPORT_ERROR,

    /** A contactless card sits on the reader; PACE needs the access number. */
    ACCESS_NUMBER_REQUIRED,

    /** The entered access number did not open the contactless card. */
    WRONG_ACCESS_NUMBER,
}

internal enum class CardPresence {
    PRESENT,
    NOT_PRESENT,
}

internal enum class AuthenticationStatus {
    IDLE,
    SIGNING,
    SUCCEEDED,
    WRONG_PIN,
    PIN_LOCKED,
    REFUSED,
    ERROR,
}

internal data class UsbReaderSnapshot(
    val status: ReaderConnectionStatus = ReaderConnectionStatus.NOT_CONNECTED,
    val cardPresence: CardPresence? = null,
    val authenticationStatus: AuthenticationStatus = AuthenticationStatus.IDLE,
    val holderName: String? = null,
)

internal class UsbReaderController(
    context: Context,
) : AuthenticationCardService {
    private val applicationContext = context.applicationContext
    private val usbManager =
        requireNotNull(applicationContext.getSystemService(UsbManager::class.java))
    private val permissionAction =
        applicationContext.packageName + ".action.USB_PERMISSION"
    private val ccidSessionOpener =
        CcidUsbSessionOpener(
            usbManager = usbManager,
            validateAtr = NativeCore::validateAtr,
        )
    private val mainHandler = Handler(Looper.getMainLooper())
    private val ioExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val providerGenerationRandom = SecureRandom()
    private val stateListeners = linkedSetOf<(UsbReaderSnapshot) -> Unit>()

    @Volatile
    private var isStarted = false
    private var selectedDevice: UsbDevice? = null

    @Volatile
    private var latestSnapshot = UsbReaderSnapshot()

    @Volatile
    private var probeGeneration = 0

    // Worker-thread confined. Main-thread state never owns a USB connection.
    private var activeSession: CcidUsbSession? = null
    private var activeProviderGeneration: Long? = null

    internal val externalKeyCardSession =
        UsbExternalKeyCardSession(
            ioExecutor = ioExecutor,
            isAvailable = {
                isStarted &&
                    latestSnapshot.status == ReaderConnectionStatus.READY &&
                    latestSnapshot.cardPresence == CardPresence.PRESENT
            },
            activeSession = { activeSession },
            activeProviderGeneration = { activeProviderGeneration },
        )

    internal val qualifiedCardService =
        UsbQualifiedCardService(
            ioExecutor = ioExecutor,
            mainHandler = mainHandler,
            isReady = {
                isStarted &&
                    latestSnapshot.status == ReaderConnectionStatus.READY &&
                    latestSnapshot.cardPresence == CardPresence.PRESENT
            },
            currentGeneration = { probeGeneration },
            isCurrentGeneration = { generation ->
                isStarted && generation == probeGeneration
            },
            activeSession = { activeSession },
        )

    private val permissionReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(
                context: Context?,
                intent: Intent?,
            ) {
                if (intent?.action == permissionAction) {
                    AppTrace.usbPermissionResult(
                        isGranted =
                            intent.getBooleanExtra(
                                UsbManager.EXTRA_PERMISSION_GRANTED,
                                false,
                            ),
                    )
                    refresh()
                }
            }
        }

    private val usbEventReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(
                context: Context?,
                intent: Intent?,
            ) {
                when (intent?.action) {
                    UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                        AppTrace.usbDeviceAttached()
                        refresh()
                    }

                    UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                        AppTrace.usbDeviceDetached()
                        refresh()
                    }
                }
            }
        }

    fun start() {
        if (isStarted) {
            AppTrace.usbControllerStartIgnored()
            return
        }

        applicationContext.registerReceiver(
            permissionReceiver,
            IntentFilter(permissionAction),
            Context.RECEIVER_NOT_EXPORTED,
        )

        val usbEventFilter =
            IntentFilter().apply {
                addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
                addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
            }
        applicationContext.registerReceiver(
            usbEventReceiver,
            usbEventFilter,
            Context.RECEIVER_EXPORTED,
        )

        isStarted = true
        AppTrace.usbControllerStarted()
        refresh()
    }

    fun addStateListener(listener: (UsbReaderSnapshot) -> Unit) {
        checkMainThread()
        stateListeners += listener
        listener(latestSnapshot)
    }

    fun removeStateListener(listener: (UsbReaderSnapshot) -> Unit) {
        checkMainThread()
        stateListeners -= listener
    }

    fun stop() {
        if (!isStarted) {
            AppTrace.usbControllerStopIgnored()
            return
        }

        applicationContext.unregisterReceiver(permissionReceiver)
        applicationContext.unregisterReceiver(usbEventReceiver)
        isStarted = false
        probeGeneration += 1
        ioExecutor.execute(::closeActiveSession)
        ioExecutor.shutdown()
        AppTrace.usbControllerStopped()
    }

    fun refresh() {
        if (!isStarted) {
            AppTrace.usbRefreshIgnored()
            return
        }
        probeGeneration += 1
        val devices = usbManager.deviceList.values.toList()
        val descriptors = devices.map { device -> device.toDescriptor() }
        val match = CcidReaderClassifier.selectPreferred(descriptors)
        selectedDevice = devices.firstOrNull { it.deviceId == match?.deviceId }

        val device = selectedDevice
        AppTrace.usbReadersRefreshed(
            deviceCount = devices.size,
            hasCcidReader = match != null && device != null,
            hasPermission = device?.let(usbManager::hasPermission),
        )
        publish(
            when {
                device == null || match == null -> {
                    closeActiveSessionAsync()
                    UsbReaderSnapshot()
                }

                usbManager.hasPermission(device) -> {
                    beginSessionOpen(device, probeGeneration)
                    return
                }

                else -> {
                    closeActiveSessionAsync()
                    UsbReaderSnapshot(
                        status = ReaderConnectionStatus.PERMISSION_REQUIRED,
                    )
                }
            },
        )
    }

    fun requestPermission() {
        val device =
            selectedDevice
                ?: run {
                    AppTrace.usbPermissionRequestWithoutReader()
                    return
                }
        if (usbManager.hasPermission(device)) {
            AppTrace.usbPermissionAlreadyGranted()
            refresh()
            return
        }

        val permissionIntent =
            Intent(permissionAction).setPackage(applicationContext.packageName)
        val pendingIntent =
            PendingIntent.getBroadcast(
                applicationContext,
                USB_PERMISSION_REQUEST_CODE,
                permissionIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )

        try {
            AppTrace.usbPermissionRequested()
            usbManager.requestPermission(device, pendingIntent)
        } catch (_: SecurityException) {
            AppTrace.usbPermissionRequestFailed()
            publish(
                latestSnapshot.copy(
                    status = ReaderConnectionStatus.PERMISSION_REQUEST_FAILED,
                ),
            )
        }
    }

    fun authenticate(pin1: Pin1Submission) {
        if (
            !isStarted ||
            latestSnapshot.status != ReaderConnectionStatus.READY ||
            latestSnapshot.cardPresence != CardPresence.PRESENT
        ) {
            pin1.close()
            AppTrace.authenticationRequestIgnored()
            return
        }
        val generation = probeGeneration
        publish(
            latestSnapshot.copy(
                authenticationStatus = AuthenticationStatus.SIGNING,
            ),
        )
        AppTrace.authenticationRequestStarted()
        ioExecutor.execute {
            if (!isStarted || generation != probeGeneration) {
                pin1.close()
                return@execute
            }
            val message = DIAGNOSTIC_AUTHENTICATION_MESSAGE.encodeToByteArray()
            val result =
                activeSession?.authenticateAndSignWithDiagnosticAlgorithm(
                    pin1 = pin1,
                    message = message,
                ) ?: run {
                    pin1.close()
                    AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)
                }
            message.fill(0)
            val status = result.toAuthenticationStatus()
            if (result is AuthenticationSignResult.Success) {
                result.signature.close()
            }
            AppTrace.authenticationRequestCompleted(status)
            mainHandler.post {
                if (isStarted && generation == probeGeneration) {
                    publish(
                        latestSnapshot.copy(
                            authenticationStatus = status,
                        ),
                    )
                }
            }
        }
    }

    /**
     * Run PACE with the entered access number on the held contactless
     * session, opening the card once. On success the session is retained
     * under secure messaging so the browser and diagnostic signs reuse it
     * without a second handshake; a wrong access number stays on the CAN
     * prompt for retry.
     */
    fun connect(can: CanSubmission) {
        if (
            !isStarted ||
            (
                latestSnapshot.status != ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED &&
                    latestSnapshot.status != ReaderConnectionStatus.WRONG_ACCESS_NUMBER
            )
        ) {
            can.close()
            AppTrace.usbContactlessConnectIgnored()
            return
        }
        val generation = probeGeneration
        publish(
            UsbReaderSnapshot(
                status = ReaderConnectionStatus.CHECKING,
                cardPresence = CardPresence.PRESENT,
            ),
        )
        AppTrace.usbContactlessConnectStarted()
        ioExecutor.execute {
            if (!isStarted || generation != probeGeneration) {
                can.close()
                return@execute
            }
            can.peekDigits()?.let {
                fi.refineid.android.core.CanSessionStore
                    .remember(it)
            }
            val canBytes = can.transfer()
            val result =
                activeSession?.openContactless(canBytes) ?: run {
                    canBytes.fill(0)
                    NativeContactlessOpenResult.Failure(
                        NativeCertificateReadFailure.CARD_UNAVAILABLE,
                    )
                }
            if (result is NativeContactlessOpenResult.Success) {
                activeProviderGeneration = providerGenerationRandom.nextProviderGeneration()
            }
            val holder =
                if (result is NativeContactlessOpenResult.Success) {
                    try {
                        val cert = activeSession?.copyAuthenticationCertificate()
                        cert?.let { c ->
                            try {
                                holderNameFromCertificate(c)
                            } finally {
                                c.close()
                            }
                        }
                    } catch (_: Exception) {
                        null
                    }
                } else {
                    null
                }
            val snapshot =
                when (result) {
                    is NativeContactlessOpenResult.Success -> {
                        UsbReaderSnapshot(
                            status = ReaderConnectionStatus.READY,
                            cardPresence = CardPresence.PRESENT,
                            holderName = holder,
                        )
                    }

                    is NativeContactlessOpenResult.Failure -> {
                        val status = result.kind.toContactlessConnectStatus()
                        if (status == ReaderConnectionStatus.WRONG_ACCESS_NUMBER) {
                            fi.refineid.android.core.CanSessionStore
                                .drop()
                        }
                        UsbReaderSnapshot(
                            status = status,
                            cardPresence = CardPresence.PRESENT,
                        )
                    }
                }
            AppTrace.usbContactlessConnectCompleted(
                result is NativeContactlessOpenResult.Success,
            )
            mainHandler.post {
                if (isStarted && generation == probeGeneration) {
                    publish(snapshot)
                }
            }
        }
    }

    /** Copies the public leaf while preserving session thread confinement. */
    override fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit) {
        if (
            !isStarted ||
            latestSnapshot.status != ReaderConnectionStatus.READY ||
            latestSnapshot.cardPresence != CardPresence.PRESENT
        ) {
            onResult(null)
            return
        }
        val generation = probeGeneration
        try {
            ioExecutor.execute {
                val certificate =
                    if (isStarted && generation == probeGeneration) {
                        try {
                            activeSession?.copyAuthenticationCertificate()
                        } catch (_: IllegalStateException) {
                            null
                        }
                    } else {
                        null
                    }
                mainHandler.post {
                    if (isStarted && generation == probeGeneration) {
                        onResult(certificate)
                    } else {
                        certificate?.close()
                        onResult(null)
                    }
                }
            }
        } catch (_: RejectedExecutionException) {
            onResult(null)
        }
    }

    /** Blocks a browser crypto worker while one card operation runs on the USB owner thread. */
    override fun signAuthenticationMessage(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        message: ByteArray,
    ): AuthenticationSignResult =
        signAuthenticationInput(
            algorithm = algorithm,
            inputMode = AuthenticationSigningInputMode.MESSAGE,
            pin1 = pin1,
            input = message,
        )

    override fun signAuthenticationDigest(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        digest: ByteArray,
    ): AuthenticationSignResult =
        signAuthenticationInput(
            algorithm = algorithm,
            inputMode = AuthenticationSigningInputMode.PREHASHED,
            pin1 = pin1,
            input = digest,
        )

    private fun signAuthenticationInput(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
    ): AuthenticationSignResult {
        if (
            Looper.myLooper() == Looper.getMainLooper() ||
            !isStarted ||
            latestSnapshot.status != ReaderConnectionStatus.READY ||
            latestSnapshot.cardPresence != CardPresence.PRESENT
        ) {
            pin1.close()
            return AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)
        }
        val generation = probeGeneration
        val completion = CompletableFuture<AuthenticationSignResult>()
        try {
            ioExecutor.execute {
                val result =
                    try {
                        if (isStarted && generation == probeGeneration) {
                            activeSession?.let { session ->
                                when (inputMode) {
                                    AuthenticationSigningInputMode.MESSAGE -> {
                                        session.authenticateAndSign(
                                            algorithm = algorithm,
                                            pin1 = pin1,
                                            message = input,
                                        )
                                    }

                                    AuthenticationSigningInputMode.PREHASHED -> {
                                        session.authenticateAndSignPrehashed(
                                            algorithm = algorithm,
                                            pin1 = pin1,
                                            digest = input,
                                        )
                                    }
                                }
                            } ?: run {
                                pin1.close()
                                AuthenticationSignResult.Failure(
                                    AuthenticationSignFailure.CARD_UNAVAILABLE,
                                )
                            }
                        } else {
                            pin1.close()
                            AuthenticationSignResult.Failure(
                                AuthenticationSignFailure.CARD_UNAVAILABLE,
                            )
                        }
                    } catch (_: RuntimeException) {
                        pin1.close()
                        AuthenticationSignResult.Failure(
                            AuthenticationSignFailure.BRIDGE_ERROR,
                        )
                    }
                completion.complete(result)
            }
        } catch (_: RejectedExecutionException) {
            pin1.close()
            return AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)
        }
        return completion.awaitPreservingInterrupt()
    }

    private fun beginSessionOpen(
        device: UsbDevice,
        generation: Int,
    ) {
        AppTrace.usbSessionOpenStarted()
        publish(
            UsbReaderSnapshot(
                status = ReaderConnectionStatus.CHECKING,
            ),
        )
        ioExecutor.execute {
            closeActiveSession()
            val result = ccidSessionOpener.open(device)
            var holder: String? = null
            if (result is CcidSessionOpenResult.Ready) {
                activeSession = result.session
                activeProviderGeneration = providerGenerationRandom.nextProviderGeneration()
                holder =
                    try {
                        val cert = result.session.copyAuthenticationCertificate()
                        try {
                            holderNameFromCertificate(cert)
                        } finally {
                            cert.close()
                        }
                    } catch (_: Exception) {
                        null
                    }
            } else if (result is CcidSessionOpenResult.AccessNumberRequired) {
                // Hold the contactless session so a CAN entry can run PACE on it.
                // No provider generation until connect() actually opens the card.
                activeSession = result.session
            }
            mainHandler.post {
                if (
                    isStarted &&
                    generation == probeGeneration &&
                    selectedDevice?.deviceId == device.deviceId
                ) {
                    AppTrace.usbSessionOpenCompleted(result)
                    publish(
                        when (result) {
                            is CcidSessionOpenResult.Ready -> {
                                UsbReaderSnapshot(
                                    status = ReaderConnectionStatus.READY,
                                    cardPresence = CardPresence.PRESENT,
                                    holderName = holder,
                                )
                            }

                            is CcidSessionOpenResult.AccessNumberRequired -> {
                                UsbReaderSnapshot(
                                    status = ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED,
                                    cardPresence = CardPresence.PRESENT,
                                )
                            }

                            CcidSessionOpenResult.NoCard -> {
                                UsbReaderSnapshot(
                                    status = ReaderConnectionStatus.READY,
                                    cardPresence = CardPresence.NOT_PRESENT,
                                )
                            }

                            CcidSessionOpenResult.CardError -> {
                                UsbReaderSnapshot(
                                    status = ReaderConnectionStatus.CARD_ERROR,
                                )
                            }

                            CcidSessionOpenResult.TransportError -> {
                                UsbReaderSnapshot(
                                    status = ReaderConnectionStatus.TRANSPORT_ERROR,
                                )
                            }
                        },
                    )
                } else {
                    AppTrace.usbSessionOpenResultDiscarded()
                }
            }
        }
    }

    private fun closeActiveSessionAsync() {
        ioExecutor.execute(::closeActiveSession)
    }

    private fun closeActiveSession() {
        activeProviderGeneration = null
        activeSession?.close()
        activeSession = null
    }

    private fun publish(snapshot: UsbReaderSnapshot) {
        latestSnapshot = snapshot
        AppTrace.usbSnapshotPublished(
            status = snapshot.status,
            cardPresence = snapshot.cardPresence,
        )
        stateListeners.toList().forEach { listener -> listener(snapshot) }
    }

    private companion object {
        const val USB_PERMISSION_REQUEST_CODE = 0x5246
        const val DIAGNOSTIC_AUTHENTICATION_MESSAGE = "ReFineID signing test"
    }
}

private fun checkMainThread() {
    check(Looper.myLooper() == Looper.getMainLooper()) {
        "USB reader listeners must be changed on the main thread"
    }
}

private fun UsbDevice.toDescriptor(): UsbDeviceDescriptor =
    UsbDeviceDescriptor(
        deviceId = deviceId,
        interfaces =
            List(interfaceCount) { index ->
                UsbInterfaceDescriptor(
                    interfaceClass = getInterface(index).interfaceClass,
                )
            },
    )

internal fun <T> CompletableFuture<T>.awaitPreservingInterrupt(): T {
    var wasInterrupted = false
    while (true) {
        try {
            return get()
        } catch (_: InterruptedException) {
            wasInterrupted = true
        } finally {
            if (isDone && wasInterrupted) {
                Thread.currentThread().interrupt()
            }
        }
    }
}

private fun AuthenticationSignResult.toAuthenticationStatus(): AuthenticationStatus =
    when (this) {
        is AuthenticationSignResult.Success -> {
            AuthenticationStatus.SUCCEEDED
        }

        is AuthenticationSignResult.Failure -> {
            when (kind) {
                AuthenticationSignFailure.WRONG_PIN -> AuthenticationStatus.WRONG_PIN

                AuthenticationSignFailure.PIN_LOCKED -> AuthenticationStatus.PIN_LOCKED

                AuthenticationSignFailure.SAFETY_REFUSED -> AuthenticationStatus.REFUSED

                AuthenticationSignFailure.CARD_UNAVAILABLE,
                AuthenticationSignFailure.TRANSPORT_ERROR,
                AuthenticationSignFailure.INVALID_PIN,
                AuthenticationSignFailure.VERIFICATION_REJECTED,
                AuthenticationSignFailure.SIGNING_REJECTED,
                AuthenticationSignFailure.KEY_PROFILE_MISMATCH,
                AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED,
                AuthenticationSignFailure.BRIDGE_ERROR,
                -> AuthenticationStatus.ERROR
            }
        }
    }

/** Coarse holder-facing status for one contactless connect attempt. */
private fun NativeCertificateReadFailure.toContactlessConnectStatus(): ReaderConnectionStatus =
    when (this) {
        NativeCertificateReadFailure.PACE_REJECTED -> {
            ReaderConnectionStatus.WRONG_ACCESS_NUMBER
        }

        NativeCertificateReadFailure.CARD_UNAVAILABLE,
        NativeCertificateReadFailure.REJECTED,
        NativeCertificateReadFailure.INVALID_CERTIFICATE,
        -> {
            ReaderConnectionStatus.CARD_ERROR
        }

        NativeCertificateReadFailure.TRANSPORT_ERROR,
        NativeCertificateReadFailure.BRIDGE_ERROR,
        -> {
            ReaderConnectionStatus.TRANSPORT_ERROR
        }
    }

/**
 * Extracts the common name (CN) from the authentication certificate's
 * X.500 subject, returning the cardholder's full name or `null` on any
 * parsing failure.
 */
private fun holderNameFromCertificate(certificate: NativeAuthenticationCertificate): String? =
    try {
        val der = certificate.copyDer()
        val factory = CertificateFactory.getInstance("X.509")
        val x509 = factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        val rfc2253 = x509.subjectX500Principal.getName("RFC2253")
        "(?:^|,)\\s*CN=([^,]+)".toRegex().find(rfc2253)?.groupValues?.get(1)
    } catch (_: Exception) {
        null
    }
