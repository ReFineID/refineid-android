package fi.refineid.android.diagnostics

import android.util.Log
import fi.refineid.android.browser.BrowserClientCertificateOutcome
import fi.refineid.android.browser.BrowserSignatureStatus
import fi.refineid.android.core.AtrValidation
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.NativeAuthenticationCertificateReadResult
import fi.refineid.android.core.NativeAuthenticationSignResult
import fi.refineid.android.core.NativeCardExchangeLevel
import fi.refineid.android.core.NativeCardOperationResult
import fi.refineid.android.core.NativePin1PreflightResult
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
        result: NativeAuthenticationCertificateReadResult,
    ) {
        val outcome =
            when (result) {
                is NativeAuthenticationCertificateReadResult.Success -> {
                    "success profile=" + result.certificate.keyProfile +
                        " length=" + result.certificate.derLength
                }

                is NativeAuthenticationCertificateReadResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:authentication-certificate-read " + outcome +
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

    fun browserTlsError() {
        debug("browser:tls-error")
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
