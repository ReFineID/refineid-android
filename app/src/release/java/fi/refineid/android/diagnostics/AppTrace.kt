package fi.refineid.android.diagnostics

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
import fi.refineid.android.usb.ccid.CcidExchangeLevel
import fi.refineid.android.usb.ccid.CcidExchangeFailureKind
import fi.refineid.android.usb.ccid.CcidProtocolErrorKind
import fi.refineid.android.usb.ccid.CcidSessionOpenResult

/** Release sink: deliberately empty. */
internal object AppTrace {
    fun activityCreated() = Unit

    fun activityReceivedIntent() = Unit

    fun activityDestroyed() = Unit

    fun nativeLibraryLoadCompleted(isSuccessful: Boolean) = Unit

    fun nativeAtrValidationCompleted(result: AtrValidation) = Unit

    fun nativePkcs15SelectionStarted(level: NativeCardExchangeLevel): Long = 0L

    fun nativePkcs15SelectionCompleted(
        startedAt: Long,
        result: NativeCardOperationResult,
    ) = Unit

    fun nativeAuthenticationCertificateReadStarted(level: NativeCardExchangeLevel): Long = 0L

    fun nativeAuthenticationCertificateReadCompleted(
        startedAt: Long,
        result: NativeAuthenticationCertificateReadResult,
    ) = Unit

    fun nativePin1StatusProbeStarted(level: NativeCardExchangeLevel): Long = 0L

    fun nativePin1StatusProbeCompleted(
        startedAt: Long,
        result: NativePin1PreflightResult,
    ) = Unit

    fun nativeAuthenticationSignStarted(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        inputLength: Int,
    ): Long = 0L

    fun nativeAuthenticationSignCompleted(
        startedAt: Long,
        result: NativeAuthenticationSignResult,
    ) = Unit

    fun authenticationSignatureVerificationCompleted(
        inputMode: AuthenticationSigningInputMode,
        isVerified: Boolean,
    ) = Unit

    fun authenticationRequestIgnored() = Unit

    fun authenticationRequestStarted() = Unit

    fun authenticationRequestCompleted(status: AuthenticationStatus) = Unit

    fun browserOpened() = Unit

    fun browserClosed() = Unit

    fun browserInitialized(
        providerReady: Boolean,
        issuerCount: Int,
    ) = Unit

    fun browserNavigationBlocked() = Unit

    fun browserTlsError() = Unit

    fun browserClientCertificateRequested(
        originAllowed: Boolean,
        keyTypeCount: Int,
        issuerCount: Int,
    ) = Unit

    fun browserClientCertificateCompleted(outcome: BrowserClientCertificateOutcome) = Unit

    fun browserSignatureStatus(status: BrowserSignatureStatus) = Unit

    fun usbControllerStartIgnored() = Unit

    fun usbControllerStarted() = Unit

    fun usbControllerStopIgnored() = Unit

    fun usbControllerStopped() = Unit

    fun usbRefreshIgnored() = Unit

    fun usbPermissionResult(isGranted: Boolean) = Unit

    fun usbDeviceAttached() = Unit

    fun usbDeviceDetached() = Unit

    fun usbReadersRefreshed(
        deviceCount: Int,
        hasCcidReader: Boolean,
        hasPermission: Boolean?,
    ) = Unit

    fun usbPermissionRequestWithoutReader() = Unit

    fun usbPermissionAlreadyGranted() = Unit

    fun usbPermissionRequested() = Unit

    fun usbPermissionRequestFailed() = Unit

    fun usbSessionOpenStarted() = Unit

    fun usbSessionOpenCompleted(result: CcidSessionOpenResult) = Unit

    fun usbSessionOpenResultDiscarded() = Unit

    fun usbSnapshotPublished(
        status: ReaderConnectionStatus,
        cardPresence: CardPresence?,
    ) = Unit

    fun ccidEndpointsMissing() = Unit

    fun ccidOpenFailed() = Unit

    fun ccidDescriptorRejected(kind: CcidDescriptorErrorKind) = Unit

    fun ccidDescriptorAccepted(
        level: CcidExchangeLevel,
        maximumMessageLength: Int,
    ) = Unit

    fun ccidClaimFailed() = Unit

    fun ccidSecurityFailure() = Unit

    fun ccidSessionClosed(interfaceReleased: Boolean) = Unit

    fun ccidSlotExchangeFailed(kind: CcidExchangeFailureKind) = Unit

    fun ccidPowerExchangeFailed(kind: CcidExchangeFailureKind) = Unit

    fun ccidCardState(state: CcidCardStatus) = Unit

    fun ccidAtrResult(
        length: Int,
        validation: AtrValidation,
        isSupported: Boolean,
    ) = Unit

    fun ccidTimeExtension(
        count: Int,
        multiplier: Int,
    ) = Unit

    fun ccidResponseRejected(kind: CcidProtocolErrorKind) = Unit

    fun ccidCommandExchangeFailed(kind: CcidExchangeFailureKind) = Unit

    fun cardPublicCommandStarted(
        classByte: Int,
        instruction: Int,
        parameterOne: Int,
        parameterTwo: Int,
        commandLength: Int,
    ): Long = 0L

    fun cardPublicMalformedCommandStarted(commandLength: Int): Long = 0L

    fun cardPublicCommandResponded(
        startedAt: Long,
        statusWord: Int,
        responseBodyLength: Int,
    ) = Unit

    fun cardPublicCommandFailed(
        startedAt: Long,
        kind: CcidBlockFailureKind,
    ) = Unit

    fun cardSensitiveCommandStarted(): Long = 0L

    fun cardSensitiveCommandResponded(
        startedAt: Long,
        statusWord: Int,
    ) = Unit

    fun cardSensitiveCommandFailed(
        startedAt: Long,
        kind: CcidBlockFailureKind,
    ) = Unit

    fun cardCredentialCommandStarted(): Long = 0L

    fun cardCredentialCommandResponded(
        startedAt: Long,
        statusWord: Int,
    ) = Unit

    fun cardCredentialCommandFailed(
        startedAt: Long,
        kind: CcidBlockFailureKind,
    ) = Unit
}
