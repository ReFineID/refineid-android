package fi.refineid.android.ui

import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.webkit.ClientCertRequest
import android.webkit.SslErrorHandler
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import fi.refineid.android.R
import fi.refineid.android.browser.BrowserClientCertificateMatcher
import fi.refineid.android.browser.BrowserClientCertificateOutcome
import fi.refineid.android.browser.BrowserClientIdentity
import fi.refineid.android.browser.BrowserPinCoordinator
import fi.refineid.android.browser.BrowserPinRequest
import fi.refineid.android.browser.BrowserSignatureStatus
import fi.refineid.android.browser.BundledIssuerCertificates
import fi.refineid.android.browser.ReFineIdCardProviderRegistration
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicBoolean

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun BrowserHarness(
    snapshot: UsbReaderSnapshot,
    cardService: AuthenticationCardService?,
) {
    if (
        cardService == null ||
        snapshot.status != ReaderConnectionStatus.READY ||
        snapshot.cardPresence != CardPresence.PRESENT
    ) {
        return
    }
    var isOpen by remember { mutableStateOf(false) }
    Button(
        onClick = {
            AppTrace.browserOpened()
            isOpen = true
        },
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.BROWSER_ACTION),
    ) {
        Text(stringResource(R.string.browser))
    }
    if (isOpen) {
        BrowserDialog(
            cardService = cardService,
            onClose = {
                AppTrace.browserClosed()
                isOpen = false
            },
        )
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun BrowserDialog(
    cardService: AuthenticationCardService,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val mainHandler = remember { Handler(Looper.getMainLooper()) }
    val isActive = remember { AtomicBoolean(true) }
    var pinRequest by remember { mutableStateOf<BrowserPinRequest?>(null) }
    var signatureStatus by remember { mutableStateOf(BrowserSignatureStatus.IDLE) }
    val coordinator =
        remember(cardService) {
            BrowserPinCoordinator(
                cardService = cardService,
                dispatchToUi = { action ->
                    if (Looper.myLooper() == Looper.getMainLooper()) {
                        action()
                    } else {
                        mainHandler.post {
                            if (isActive.get()) {
                                action()
                            }
                        }
                    }
                },
                onPromptChanged = { request -> pinRequest = request },
                onStatusChanged = { status ->
                    signatureStatus = status
                    AppTrace.browserSignatureStatus(status)
                },
            )
        }
    val issuerCandidates =
        remember(context) {
            runCatching { BundledIssuerCertificates.load(context) }.getOrNull()
        }
    val providerReady = remember { ReFineIdCardProviderRegistration.install() }
    LaunchedEffect(providerReady, issuerCandidates) {
        AppTrace.browserInitialized(
            providerReady = providerReady,
            issuerCount = issuerCandidates?.size ?: NO_ISSUER_CERTIFICATES,
        )
    }
    val webViewClient =
        remember(cardService, coordinator, issuerCandidates, providerReady) {
            if (issuerCandidates == null || !providerReady) {
                null
            } else {
                ReFineIdWebViewClient(
                    cardService = cardService,
                    issuerCandidates = issuerCandidates,
                    signatureOperation = coordinator,
                    allowedOrigin = DIAGNOSTIC_ORIGIN,
                )
            }
        }

    DisposableEffect(coordinator, webViewClient) {
        onDispose {
            isActive.set(false)
            webViewClient?.close()
            coordinator.close()
        }
    }

    Dialog(
        onDismissRequest = onClose,
        properties =
            DialogProperties(
                dismissOnClickOutside = false,
                usePlatformDefaultWidth = false,
                decorFitsSystemWindows = false,
            ),
    ) {
        Surface(
            modifier =
                Modifier
                    .fillMaxSize()
                    .semantics { testTagsAsResourceId = true },
            color = MaterialTheme.colorScheme.background,
        ) {
            Column(
                modifier =
                    Modifier
                        .fillMaxSize()
                        .padding(BROWSER_PADDING),
                verticalArrangement = Arrangement.spacedBy(BROWSER_ITEM_SPACING),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = stringResource(R.string.browser),
                        style = MaterialTheme.typography.titleLarge,
                    )
                    Button(
                        onClick = onClose,
                        modifier = Modifier.testTag(UiAutomationIds.BROWSER_CLOSE_ACTION),
                    ) {
                        Text(stringResource(R.string.close))
                    }
                }
                BrowserStatus(signatureStatus)
                if (webViewClient == null) {
                    Text(stringResource(R.string.error))
                } else {
                    val client = webViewClient
                    AndroidView(
                        factory = { viewContext ->
                            WebView.setWebContentsDebuggingEnabled(true)
                            WebView(viewContext).apply {
                                settings.allowContentAccess = false
                                settings.allowFileAccess = false
                                this.webViewClient = client
                                WebView.clearClientCertPreferences {
                                    if (isActive.get()) {
                                        loadUrl(DIAGNOSTIC_ORIGIN.url)
                                    }
                                }
                            }
                        },
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .weight(BROWSER_VIEW_WEIGHT)
                                .testTag(UiAutomationIds.BROWSER_VIEW),
                        onRelease = { webView ->
                            webView.stopLoading()
                            webView.webViewClient = WebViewClient()
                            webView.destroy()
                        },
                    )
                }
            }
        }
    }
    pinRequest?.let { request ->
        BrowserPinDialog(request)
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun BrowserPinDialog(request: BrowserPinRequest) {
    val pinState = remember(request) { TextFieldState() }
    var wasSubmitted by remember(request) { mutableStateOf(false) }
    DisposableEffect(pinState) {
        onDispose(pinState::clearText)
    }
    val submit = {
        if (!wasSubmitted && Pin1Submission.isComplete(pinState.text)) {
            val submission = Pin1Submission.from(pinState.text)
            pinState.clearText()
            wasSubmitted = true
            request.submit(submission)
        }
        Unit
    }

    Dialog(
        onDismissRequest = request::cancel,
        properties = DialogProperties(dismissOnClickOutside = false),
    ) {
        Surface(
            modifier = Modifier.semantics { testTagsAsResourceId = true },
            shape = MaterialTheme.shapes.large,
            color = MaterialTheme.colorScheme.surface,
        ) {
            Column(
                modifier = Modifier.padding(PIN_DIALOG_PADDING),
                verticalArrangement = Arrangement.spacedBy(PIN_DIALOG_ITEM_SPACING),
            ) {
                Text(
                    text = stringResource(R.string.pin1),
                    style = MaterialTheme.typography.titleLarge,
                )
                SecureTextField(
                    state = pinState,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.BROWSER_PIN1_FIELD),
                    enabled = !wasSubmitted,
                    inputTransformation = Pin1InputTransformation,
                    textObfuscationMode = TextObfuscationMode.Hidden,
                    keyboardOptions =
                        KeyboardOptions(
                            autoCorrectEnabled = false,
                            keyboardType = KeyboardType.NumberPassword,
                            imeAction = ImeAction.Done,
                        ),
                )
                Button(
                    onClick = submit,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.BROWSER_SIGN_ACTION),
                    enabled = !wasSubmitted && Pin1Submission.isComplete(pinState.text),
                ) {
                    Text(stringResource(R.string.sign))
                }
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun BrowserStatus(status: BrowserSignatureStatus) {
    val text =
        when (status) {
            BrowserSignatureStatus.IDLE,
            BrowserSignatureStatus.PIN_REQUIRED,
            BrowserSignatureStatus.CANCELLED,
            -> null

            BrowserSignatureStatus.SIGNING -> stringResource(R.string.signing)

            BrowserSignatureStatus.SUCCEEDED -> stringResource(R.string.signed)

            BrowserSignatureStatus.WRONG_PIN -> stringResource(R.string.wrong_pin)

            BrowserSignatureStatus.PIN_LOCKED -> stringResource(R.string.pin_locked)

            BrowserSignatureStatus.REFUSED -> stringResource(R.string.unavailable)

            BrowserSignatureStatus.TIMED_OUT,
            BrowserSignatureStatus.INTERRUPTED,
            BrowserSignatureStatus.ERROR,
            -> stringResource(R.string.error)
        }
    if (text != null) {
        Text(text)
    }
}

private class ReFineIdWebViewClient(
    private val cardService: AuthenticationCardService,
    private val issuerCandidates: List<X509Certificate>,
    private val signatureOperation: BrowserPinCoordinator,
    private val allowedOrigin: BrowserOrigin,
) : WebViewClient(),
    AutoCloseable {
    private val isClosed = AtomicBoolean(false)

    override fun shouldOverrideUrlLoading(
        view: WebView,
        request: WebResourceRequest,
    ): Boolean {
        val isBlocked = !allowedOrigin.allows(request.url)
        if (isBlocked) {
            AppTrace.browserNavigationBlocked()
        }
        return isBlocked
    }

    override fun onReceivedSslError(
        view: WebView,
        handler: SslErrorHandler,
        error: android.net.http.SslError,
    ) {
        AppTrace.browserTlsError()
        handler.cancel()
    }

    override fun onReceivedError(
        view: WebView,
        request: WebResourceRequest,
        error: WebResourceError,
    ) = Unit

    override fun onReceivedClientCertRequest(
        view: WebView,
        request: ClientCertRequest,
    ) {
        val originAllowed = allowedOrigin.allows(request.host, request.port)
        AppTrace.browserClientCertificateRequested(
            originAllowed = originAllowed,
            keyTypeCount = request.keyTypes?.size ?: NO_KEY_TYPES,
            issuerCount = request.principals?.size ?: NO_ISSUER_HINTS,
        )
        if (isClosed.get()) {
            AppTrace.browserClientCertificateCompleted(BrowserClientCertificateOutcome.CLOSED)
            request.cancel()
            return
        }
        if (!originAllowed) {
            AppTrace.browserClientCertificateCompleted(
                BrowserClientCertificateOutcome.ORIGIN_REJECTED,
            )
            request.cancel()
            return
        }
        cardService.requestAuthenticationCertificate { ownedLeaf ->
            if (ownedLeaf == null) {
                AppTrace.browserClientCertificateCompleted(
                    BrowserClientCertificateOutcome.CARD_UNAVAILABLE,
                )
                request.cancel()
                return@requestAuthenticationCertificate
            }
            val identity =
                BrowserClientIdentity.create(
                    ownedLeaf = ownedLeaf,
                    issuerCandidates = issuerCandidates,
                    operation = signatureOperation,
                )
            if (isClosed.get()) {
                AppTrace.browserClientCertificateCompleted(
                    BrowserClientCertificateOutcome.CLOSED,
                )
                request.cancel()
                return@requestAuthenticationCertificate
            }
            if (identity == null) {
                AppTrace.browserClientCertificateCompleted(
                    BrowserClientCertificateOutcome.IDENTITY_INVALID,
                )
                request.cancel()
                return@requestAuthenticationCertificate
            }
            if (
                !BrowserClientCertificateMatcher.accepts(
                    identity = identity,
                    keyTypes = request.keyTypes,
                    principals = request.principals,
                )
            ) {
                AppTrace.browserClientCertificateCompleted(
                    BrowserClientCertificateOutcome.HINT_MISMATCH,
                )
                request.cancel()
                return@requestAuthenticationCertificate
            }
            AppTrace.browserClientCertificateCompleted(
                BrowserClientCertificateOutcome.PROCEEDED,
            )
            request.proceed(
                identity.privateKey,
                identity.copyCertificateChain(),
            )
        }
    }

    override fun close() {
        isClosed.set(true)
    }
}

private data class BrowserOrigin(
    val url: String,
    val host: String,
    val port: Int,
) {
    fun allows(uri: Uri): Boolean {
        val effectivePort =
            if (uri.port == DEFAULT_URI_PORT) {
                HTTPS_DEFAULT_PORT
            } else {
                uri.port
            }
        return uri.scheme == HTTPS_SCHEME &&
            uri.host.equals(host, ignoreCase = true) &&
            effectivePort == port
    }

    fun allows(
        requestHost: String,
        requestPort: Int,
    ): Boolean = requestHost.equals(host, ignoreCase = true) && requestPort == port

    private companion object {
        const val DEFAULT_URI_PORT = -1
        const val HTTPS_DEFAULT_PORT = 443
        const val HTTPS_SCHEME = "https"
    }
}

private const val DIAGNOSTIC_BROWSER_URL = "https://card.refineid.fi/"
private const val DIAGNOSTIC_BROWSER_HOST = "card.refineid.fi"
private const val DIAGNOSTIC_BROWSER_PORT = 443
private val DIAGNOSTIC_ORIGIN =
    BrowserOrigin(
        url = DIAGNOSTIC_BROWSER_URL,
        host = DIAGNOSTIC_BROWSER_HOST,
        port = DIAGNOSTIC_BROWSER_PORT,
    )
private val BROWSER_PADDING = 16.dp
private val BROWSER_ITEM_SPACING = 12.dp
private val PIN_DIALOG_PADDING = 24.dp
private val PIN_DIALOG_ITEM_SPACING = 16.dp
private const val BROWSER_VIEW_WEIGHT = 1F
private const val NO_ISSUER_CERTIFICATES = 0
private const val NO_KEY_TYPES = 0
private const val NO_ISSUER_HINTS = 0
