package fi.refineid.android.diagnostics

import android.util.Log
import fi.refineid.android.browser.BrowserClientCertificateOutcome
import fi.refineid.android.browser.BrowserSignatureStatus
import fi.refineid.android.core.AtrValidation
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeAuthenticationSignResult
import fi.refineid.android.core.NativeCardAccessResult
import fi.refineid.android.core.NativeCardExchangeLevel
import fi.refineid.android.core.NativeCardOperationResult
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeContactlessOpenResult
import fi.refineid.android.core.NativePin1PreflightResult
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.document.QualifiedPdfArchivalResult
import fi.refineid.android.document.QualifiedPdfArchivalStage
import fi.refineid.android.document.QualifiedPdfPreparationResult
import fi.refineid.android.document.QualifiedPdfSigningResult
import fi.refineid.android.keychain.ExternalKeyPinAuthorization
import fi.refineid.android.keychain.ExternalKeySignResult
import fi.refineid.android.network.SigningTimestampAttemptOutcome
import fi.refineid.android.nfc.NfcReaderStatus
import fi.refineid.android.usb.AuthenticationStatus
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.ccid.CcidBlockFailureKind
import fi.refineid.android.usb.ccid.CcidCardStatus
import fi.refineid.android.usb.ccid.CcidDescriptorErrorKind
import fi.refineid.android.usb.ccid.CcidExchangeFailureKind
import fi.refineid.android.usb.ccid.CcidExchangeLevel
import fi.refineid.android.usb.ccid.CcidProtocolErrorKind
import fi.refineid.android.usb.ccid.CcidSessionOpenResult

/** Debug-only application trace. Arguments must already be sanitized. */
internal object AppTrace {
    fun activityCreated() {
        debug("app:activity-created")
    }

    fun activityReceivedIntent() {
        debug("app:activity-intent")
    }

    fun activityDestroyed() {
        debug("app:activity-destroyed")
    }

    fun externalKeyProviderServiceCreated() {
        debug("external-key:service-created")
    }

    fun externalKeyProviderServiceBound(isAccepted: Boolean) {
        debug("external-key:service-bind accepted=" + isAccepted)
    }

    fun externalKeyProviderServiceDestroyed() {
        debug("external-key:service-destroyed")
    }

    fun externalKeyIdentityQueried(isAvailable: Boolean) {
        debug("external-key:identity-query available=" + isAvailable)
    }

    fun externalKeySignStarted(algorithm: AuthenticationSigningAlgorithm) {
        debug("external-key:sign-started algorithm=" + algorithm)
    }

    fun externalKeySignCompleted(result: ExternalKeySignResult) {
        debug("external-key:sign-completed result=" + result)
    }

    fun externalKeyIdentityRemovalCompleted(isRemoved: Boolean) {
        debug("external-key:identity-removal removed=" + isRemoved)
    }

    fun externalKeyPinPromptDispatched() {
        debug("external-key:pin-prompt-dispatched")
    }

    fun externalKeyPinPromptCompleted(authorization: ExternalKeyPinAuthorization) {
        val outcome =
            when (authorization) {
                is ExternalKeyPinAuthorization.Approved -> "approved"
                ExternalKeyPinAuthorization.Cancelled -> "cancelled"
                ExternalKeyPinAuthorization.TimedOut -> "timed-out"
                ExternalKeyPinAuthorization.Interrupted -> "interrupted"
                ExternalKeyPinAuthorization.Unavailable -> "unavailable"
            }
        debug("external-key:pin-prompt-completed outcome=" + outcome)
    }

    fun nativeLibraryLoadCompleted(isSuccessful: Boolean) {
        debug("native:library-loaded successful=" + isSuccessful)
    }

    fun nativeAtrValidationCompleted(result: AtrValidation) {
        debug("native:atr-validation result=" + result)
    }

    fun nativePkcs15SelectionStarted(level: NativeCardExchangeLevel): Long =
        System.nanoTime().also {
            debug("native:pkcs15-select start level=" + level)
        }

    fun nativePkcs15SelectionCompleted(
        startedAt: Long,
        result: NativeCardOperationResult,
    ) {
        debug(
            "native:pkcs15-select result=" + result +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeAuthenticationCertificateReadStarted(level: NativeCardExchangeLevel): Long =
        System.nanoTime().also {
            debug("native:authentication-certificate-read start level=" + level)
        }

    fun nativeAuthenticationCertificateReadCompleted(
        startedAt: Long,
        result: NativeCertificateReadResult<NativeAuthenticationCertificate>,
    ) {
        val outcome =
            when (result) {
                is NativeCertificateReadResult.Success -> {
                    "success profile=" + result.certificate.keyProfile +
                        " length=" + result.certificate.derLength
                }

                is NativeCertificateReadResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:authentication-certificate-read " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeQualifiedCertificateReadStarted(level: NativeCardExchangeLevel): Long =
        System.nanoTime().also {
            debug("native:qualified-certificate-read start level=" + level)
        }

    fun nativeQualifiedCertificateReadCompleted(
        startedAt: Long,
        result: NativeCertificateReadResult<NativeQualifiedCertificate>,
    ) {
        val outcome =
            when (result) {
                is NativeCertificateReadResult.Success -> {
                    "success profile=" + result.certificate.keyProfile +
                        " length=" + result.certificate.derLength
                }

                is NativeCertificateReadResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:qualified-certificate-read " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativePin1StatusProbeStarted(level: NativeCardExchangeLevel): Long =
        System.nanoTime().also {
            debug("native:pin1-status-probe start level=" + level)
        }

    fun nativePin1StatusProbeCompleted(
        startedAt: Long,
        result: NativePin1PreflightResult,
    ) {
        val outcome =
            when (result) {
                is NativePin1PreflightResult.Success -> {
                    "success scheme=" + result.preflight.referenceScheme +
                        " state=" + result.preflight.state +
                        " permitted=" + result.preflight.consumerAuthenticationPermitted
                }

                is NativePin1PreflightResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:pin1-status-probe " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativePin2StatusProbeStarted(level: NativeCardExchangeLevel): Long =
        System.nanoTime().also {
            debug("native:pin2-status-probe start level=" + level)
        }

    fun nativePin2StatusProbeCompleted(
        startedAt: Long,
        result: NativePin2PreflightResult,
    ) {
        val outcome =
            when (result) {
                is NativePin2PreflightResult.Success -> {
                    "success scheme=" + result.preflight.referenceScheme +
                        " state=" + result.preflight.state +
                        " permitted=" + result.preflight.qualifiedSignaturePermitted
                }

                is NativePin2PreflightResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:pin2-status-probe " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeCardAccessProbeStarted(level: NativeCardExchangeLevel): Long =
        System.nanoTime().also {
            debug("native:card-access-probe start level=" + level)
        }

    fun nativeCardAccessProbeCompleted(
        startedAt: Long,
        result: NativeCardAccessResult,
    ) {
        debug(
            "native:card-access-probe result=" + result +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeContactlessOpenStarted(): Long =
        System.nanoTime().also {
            debug("native:contactless-open start")
        }

    fun nativeContactlessOpenCompleted(
        startedAt: Long,
        result: NativeContactlessOpenResult,
    ) {
        debug(
            "native:contactless-open result=" + result +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeContactlessSignStarted(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        inputLength: Int,
    ): Long =
        System.nanoTime().also {
            debug(
                "native:contactless-sign start algorithm=" + algorithm +
                    " mode=" + inputMode +
                    " input-length=" + inputLength,
            )
        }

    fun nativeContactlessSignCompleted(
        startedAt: Long,
        result: NativeAuthenticationSignResult,
    ) {
        debug(
            "native:contactless-sign result=" + result +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeAuthenticationSignStarted(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        inputLength: Int,
    ): Long =
        System.nanoTime().also {
            debug(
                "native:authentication-sign start algorithm=" + algorithm +
                    " input-mode=" + inputMode +
                    " input-length=" + inputLength,
            )
        }

    fun nativeAuthenticationSignCompleted(
        startedAt: Long,
        result: NativeAuthenticationSignResult,
    ) {
        val outcome =
            when (result) {
                is NativeAuthenticationSignResult.Success -> {
                    "success algorithm=" + result.signature.algorithm +
                        " length=" + result.signature.length
                }

                is NativeAuthenticationSignResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:authentication-sign " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeQualifiedSignStarted(
        algorithm: QualifiedSigningAlgorithm,
        contentLength: Int,
    ): Long =
        System.nanoTime().also {
            debug(
                "native:qualified-sign start algorithm=" + algorithm +
                    " content-length=" + contentLength,
            )
        }

    fun nativeQualifiedSignCompleted(
        startedAt: Long,
        result: NativeQualifiedSignResult,
    ) {
        val outcome =
            when (result) {
                is NativeQualifiedSignResult.Success -> {
                    "success algorithm=" + result.signature.algorithm +
                        " length=" + result.signature.length
                }

                is NativeQualifiedSignResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:qualified-sign " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun qualifiedSignatureVerificationCompleted(isVerified: Boolean) {
        debug("qualified-signature:local-verification verified=" + isVerified)
    }

    fun qualifiedPdfSigningStarted(documentLength: Int): Long =
        System.nanoTime().also {
            debug("qualified-pdf:signing-started document-length=" + documentLength)
        }

    fun qualifiedPdfSigningCompleted(
        startedAt: Long,
        result: QualifiedPdfSigningResult,
    ) {
        val outcome =
            when (result) {
                is QualifiedPdfSigningResult.Success -> {
                    "success document-length=" + result.document.length
                }

                is QualifiedPdfSigningResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "qualified-pdf:signing-completed " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun qualifiedPdfPreparationStarted(documentLength: Int): Long =
        System.nanoTime().also {
            debug("qualified-pdf:preparation-started document-length=" + documentLength)
        }

    fun qualifiedPdfPreparationCompleted(
        startedAt: Long,
        result: QualifiedPdfPreparationResult,
    ) {
        val outcome =
            when (result) {
                is QualifiedPdfPreparationResult.Success -> {
                    "success document-length=" + result.prepared.documentLength
                }

                is QualifiedPdfPreparationResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "qualified-pdf:preparation-completed " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun qualifiedPdfArchivalStarted(): Long =
        System.nanoTime().also {
            debug("qualified-pdf:archival-started")
        }

    fun qualifiedPdfArchivalStage(stage: QualifiedPdfArchivalStage) {
        debug("qualified-pdf:archival-stage stage=" + stage)
    }

    fun qualifiedPdfArchivalCompleted(
        startedAt: Long,
        result: QualifiedPdfArchivalResult,
    ) {
        val outcome =
            when (result) {
                is QualifiedPdfArchivalResult.Success -> {
                    "success document-length=" + result.document.length
                }

                is QualifiedPdfArchivalResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "qualified-pdf:archival-completed " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun signingTimestampAttemptStarted(
        authorityOrdinal: Int,
        authorityCount: Int,
    ) {
        debug(
            "signing-network:timestamp-attempt-started authority=" + authorityOrdinal +
                " of=" + authorityCount,
        )
    }

    fun signingTimestampAttemptCompleted(
        authorityOrdinal: Int,
        outcome: SigningTimestampAttemptOutcome,
    ) {
        debug(
            "signing-network:timestamp-attempt-completed authority=" + authorityOrdinal +
                " outcome=" + outcome,
        )
    }

    fun signingTimestampRetryScheduled(delaySeconds: Long) {
        debug("signing-network:timestamp-retry-scheduled delay-seconds=" + delaySeconds)
    }

    fun documentInputStarted() {
        debug("qualified-pdf:input-started")
    }

    fun documentInputCompleted(
        isAccepted: Boolean,
        documentLength: Int?,
    ) {
        debug(
            "qualified-pdf:input-completed accepted=" + isAccepted +
                " document-length=" + (documentLength ?: "none"),
        )
    }

    fun documentDestinationSelected(isAccepted: Boolean) {
        debug("qualified-pdf:destination-selected accepted=" + isAccepted)
    }

    fun documentOutputCompleted(
        isSuccessful: Boolean,
        documentLength: Int,
    ) {
        debug(
            "qualified-pdf:output-completed successful=" + isSuccessful +
                " document-length=" + documentLength,
        )
    }

    fun authenticationSignatureVerificationCompleted(
        inputMode: AuthenticationSigningInputMode,
        isVerified: Boolean,
    ) {
        debug(
            "authentication:local-verification input-mode=" + inputMode +
                " verified=" + isVerified,
        )
    }

    fun authenticationRequestIgnored() {
        debug("authentication:request ignored=not-ready")
    }

    fun authenticationRequestStarted() {
        debug("authentication:request-started")
    }

    fun authenticationRequestCompleted(status: AuthenticationStatus) {
        debug("authentication:request-completed status=" + status)
    }

    fun browserOpened() {
        debug("browser:opened")
    }

    fun browserClosed() {
        debug("browser:closed")
    }

    fun browserInitialized(
        providerReady: Boolean,
        issuerCount: Int,
    ) {
        debug(
            "browser:initialized provider-ready=" + providerReady +
                " issuer-count=" + issuerCount,
        )
    }

    fun browserNavigationBlocked() {
        debug("browser:navigation-blocked")
    }

    fun browserTlsError(
        host: String,
        primaryError: Int,
        issuedBy: String,
        issuedTo: String,
    ) {
        debug(
            "browser:tls-error host=" + host +
                " primary-error=" + primaryError +
                " issued-by=" + issuedBy +
                " issued-to=" + issuedTo,
        )
    }

    fun browserClientCertificateRequested(
        originAllowed: Boolean,
        keyTypeCount: Int,
        issuerCount: Int,
    ) {
        debug(
            "browser:client-certificate-request origin-allowed=" + originAllowed +
                " key-type-count=" + keyTypeCount +
                " issuer-count=" + issuerCount,
        )
    }

    fun browserClientCertificateUnlockRequested() {
        debug("browser:client-certificate-unlock-requested")
    }

    fun browserClientCertificateCompleted(outcome: BrowserClientCertificateOutcome) {
        debug("browser:client-certificate-completed outcome=" + outcome)
    }

    fun browserSignatureStatus(status: BrowserSignatureStatus) {
        debug("browser:signature status=" + status)
    }

    fun usbControllerStartIgnored() {
        debug("usb:controller-start ignored=already-started")
    }

    fun usbControllerStarted() {
        debug("usb:controller-started")
    }

    fun usbControllerStopIgnored() {
        debug("usb:controller-stop ignored=not-started")
    }

    fun usbControllerStopped() {
        debug("usb:controller-stopped")
    }

    fun usbRefreshIgnored() {
        debug("usb:refresh ignored=not-started")
    }

    fun usbPermissionResult(isGranted: Boolean) {
        debug("usb:permission-result granted=" + isGranted)
    }

    fun usbDeviceAttached() {
        debug("usb:device-attached")
    }

    fun usbDeviceDetached() {
        debug("usb:device-detached")
    }

    fun usbReadersRefreshed(
        deviceCount: Int,
        hasCcidReader: Boolean,
        hasPermission: Boolean?,
    ) {
        debug(
            "usb:refresh devices=" + deviceCount +
                " ccid=" + hasCcidReader +
                " permission=" + (hasPermission ?: "none"),
        )
    }

    fun usbPermissionRequestWithoutReader() {
        debug("usb:permission-request ignored=no-reader")
    }

    fun usbPermissionAlreadyGranted() {
        debug("usb:permission-request ignored=already-granted")
    }

    fun usbPermissionRequested() {
        debug("usb:permission-requested")
    }

    fun usbPermissionRequestFailed() {
        debug("usb:permission-request-failed")
    }

    fun usbSessionOpenStarted() {
        debug("usb:session-open-started")
    }

    fun usbSessionOpenCompleted(result: CcidSessionOpenResult) {
        debug("usb:session-open-completed result=" + result)
    }

    fun usbSessionOpenResultDiscarded() {
        debug("usb:session-open-result-discarded")
    }

    fun usbSnapshotPublished(
        status: ReaderConnectionStatus,
        cardPresence: CardPresence?,
    ) {
        debug(
            "usb:snapshot status=" + status +
                " card=" + (cardPresence ?: "unknown"),
        )
    }

    fun nfcAdapterMissing() {
        debug("nfc:adapter-missing")
    }

    fun nfcAdapterStateChanged() {
        debug("nfc:adapter-state-changed")
    }

    fun nfcReaderModeChanged(isEnabled: Boolean) {
        debug("nfc:reader-mode enabled=" + isEnabled)
    }

    fun nfcTagDiscovered(isIsoDep: Boolean) {
        debug("nfc:tag-discovered iso-dep=" + isIsoDep)
    }

    fun nfcSessionOpenFailed() {
        debug("nfc:session-open-failed")
    }

    fun nfcSessionClosed() {
        debug("nfc:session-closed")
    }

    fun nfcTagLost() {
        debug("nfc:tag-lost")
    }

    fun nfcTransceiveFailed() {
        debug("nfc:transceive-failed")
    }

    fun nfcProbeResultDiscarded() {
        debug("nfc:probe-result-discarded")
    }

    fun nfcSnapshotPublished(status: NfcReaderStatus) {
        debug("nfc:snapshot status=" + status)
    }

    fun nfcSettingsUnavailable() {
        debug("nfc:settings-unavailable")
    }

    fun documentValidationStarted() {
        debug("document:validation-started")
    }

    fun documentValidationCompleted(read: Boolean) {
        debug("document:validation-completed read=" + read)
    }

    fun nfcConnectStarted() {
        debug("nfc:connect-started")
    }

    fun nfcConnectIgnored() {
        debug("nfc:connect ignored=not-recognized")
    }

    fun nfcTagAdopted() {
        debug("nfc:tag-adopted")
    }

    fun nfcPrimedOpenStarted() {
        debug("nfc:primed-open-started")
    }

    fun nfcPrimedMinted() {
        debug("nfc:primed-minted")
    }

    fun nfcPrimedForgotten() {
        debug("nfc:primed-forgotten")
    }

    fun ccidEndpointsMissing() {
        debug("ccid:endpoints-missing")
    }

    fun ccidOpenFailed() {
        debug("ccid:open-failed")
    }

    fun ccidDescriptorRejected(kind: CcidDescriptorErrorKind) {
        debug("ccid:descriptor-rejected kind=" + kind)
    }

    fun ccidDescriptorAccepted(
        level: CcidExchangeLevel,
        maximumMessageLength: Int,
    ) {
        debug(
            "ccid:descriptor-accepted level=" + level +
                " max-message=" + maximumMessageLength,
        )
    }

    fun ccidClaimFailed() {
        debug("ccid:claim-failed")
    }

    fun ccidSecurityFailure() {
        debug("ccid:security-failure")
    }

    fun ccidSessionClosed(interfaceReleased: Boolean) {
        debug("ccid:session-closed interface-released=" + interfaceReleased)
    }

    fun ccidSlotExchangeFailed(kind: CcidExchangeFailureKind) {
        debug("ccid:slot-failed kind=" + kind)
    }

    fun ccidPowerExchangeFailed(kind: CcidExchangeFailureKind) {
        debug("ccid:power-failed kind=" + kind)
    }

    fun ccidCardState(state: CcidCardStatus) {
        debug("ccid:card-state " + state)
    }

    fun ccidAtrResult(
        length: Int,
        validation: AtrValidation,
        isSupported: Boolean,
    ) {
        debug(
            "ccid:atr length=" + length +
                " validation=" + validation +
                " supported=" + isSupported,
        )
    }

    fun ccidTimeExtension(
        count: Int,
        multiplier: Int,
    ) {
        debug(
            "ccid:time-extension count=" + count +
                " multiplier=" + multiplier,
        )
    }

    fun ccidResponseRejected(kind: CcidProtocolErrorKind) {
        debug("ccid:response-rejected kind=" + kind)
    }

    fun ccidCommandExchangeFailed(kind: CcidExchangeFailureKind) {
        debug("ccid:exchange-failed kind=" + kind)
    }

    fun cardPublicCommandStarted(
        classByte: Int,
        instruction: Int,
        parameterOne: Int,
        parameterTwo: Int,
        commandLength: Int,
    ): Long =
        System.nanoTime().also {
            debug(
                "card:public tx cla=" + hexByte(classByte) +
                    " ins=" + hexByte(instruction) +
                    " p1=" + hexByte(parameterOne) +
                    " p2=" + hexByte(parameterTwo) +
                    " length=" + commandLength,
            )
        }

    fun cardPublicMalformedCommandStarted(commandLength: Int): Long =
        System.nanoTime().also {
            debug("card:public tx malformed length=" + commandLength)
        }

    fun cardPublicCommandResponded(
        startedAt: Long,
        statusWord: Int,
        responseBodyLength: Int,
    ) {
        debug(
            "card:public rx sw=" + hexStatus(statusWord) +
                " body-length=" + responseBodyLength +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun cardPublicCommandFailed(
        startedAt: Long,
        kind: CcidBlockFailureKind,
    ) {
        debug(
            "card:public failed kind=" + kind +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun cardSensitiveCommandStarted(): Long =
        System.nanoTime().also {
            debug("card:sensitive tx redacted")
        }

    fun cardSensitiveCommandResponded(
        startedAt: Long,
        statusWord: Int,
    ) {
        debug(
            "card:sensitive rx sw=" + hexStatus(statusWord) +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun cardSensitiveCommandFailed(
        startedAt: Long,
        kind: CcidBlockFailureKind,
    ) {
        debug(
            "card:sensitive failed kind=" + kind +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun cardCredentialCommandStarted(): Long =
        System.nanoTime().also {
            debug("card:credential tx redacted")
        }

    fun cardCredentialCommandResponded(
        startedAt: Long,
        statusWord: Int,
    ) {
        debug(
            "card:credential rx sw=" + hexStatus(statusWord) +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun cardCredentialCommandFailed(
        startedAt: Long,
        kind: CcidBlockFailureKind,
    ) {
        debug(
            "card:credential failed kind=" + kind +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    private fun elapsedMicroseconds(startedAt: Long): Long =
        (System.nanoTime() - startedAt).coerceAtLeast(0) / NANOSECONDS_PER_MICROSECOND

    private fun hexByte(value: Int): String =
        value.and(UNSIGNED_BYTE_MASK).toString(HEX_RADIX).padStart(BYTE_HEX_DIGITS, '0')

    private fun hexStatus(value: Int): String =
        value.and(UNSIGNED_SHORT_MASK).toString(HEX_RADIX).padStart(STATUS_HEX_DIGITS, '0')

    private fun debug(message: String) {
        try {
            Log.d(TAG, message)
        } catch (_: RuntimeException) {
            // Local JVM tests use the Android stub; a device implementation logs.
        }
    }

    private const val TAG = "ReFineID"
    private const val HEX_RADIX = 16
    private const val BYTE_HEX_DIGITS = 2
    private const val STATUS_HEX_DIGITS = 4
    private const val UNSIGNED_BYTE_MASK = 0xFF
    private const val UNSIGNED_SHORT_MASK = 0xFFFF
    private const val NANOSECONDS_PER_MICROSECOND = 1_000L
}
