@file:Suppress("UnusedParameter", "TooGenericExceptionCaught")

package fi.refineid.android.rapp

import android.content.Context
import fi.refineid.android.BuildConfig
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.QualifiedCardService
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.refineid_rapp.RappBridgeActionKind
import uniffi.refineid_rapp.RappLivenessConfiguration
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappOperationDescriptor
import uniffi.refineid_rapp.RappOperationKind
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.rappStreamSessionPreamble
import java.security.SecureRandom

/**
 * Handles incoming RAPP protocol requests from a paired Mac, coordinates user approvals,
 * and executes card signing operations via physical card services.
 */
internal class RappPhoneProxyDispatcher(
    private val context: Context,
    private val scope: CoroutineScope,
    private val inbox: RappAuthorizationInbox,
    private val pinCache: AuthenticationPinCache? = null,
    private val authCardService: () -> AuthenticationCardService?,
    private val qualifiedCardService: () -> QualifiedCardService?,
    private val isCardReady: () -> Boolean = { false },
    private val awaitCardReady: suspend () -> Boolean = { false },
) : AutoCloseable {
    private var activeListener: StreamRelayListener? = null
    private var sessionBridge: RappSessionBridge? = null
    private var sessionHandshakeDone = false
    private var operationBridge: RappOperationBridge? = null
    private var pairRecord: RappPairRecord? = null
    private var vault: AndroidRappVault? = null
    private val catalog = RappPairCatalog(context)
    private var isClosed = false

    companion object {
        /** Maximum time to wait for an NFC card certificate read before reporting card-removed. */
        private const val CERT_READ_TIMEOUT_MS = 5_000L
        private const val SHA256_DIGEST_LENGTH = 32
        private const val SHA384_DIGEST_LENGTH = 48
    }

    fun startListening(
        rendezvousName: String,
        pairRecord: RappPairRecord,
        vault: AndroidRappVault,
    ) {
        if (isClosed) return
        this.pairRecord = pairRecord
        this.vault = vault
        activeListener?.close()
        val listener =
            StreamRelayListener(context, scope) { event ->
                handleRelayEvent(event)
            }
        activeListener = listener
        listener.start(rendezvousName)
    }

    fun stopListening() {
        activeListener?.close()
        activeListener = null
        operationBridge?.close()
        operationBridge = null
        sessionBridge?.close()
        sessionBridge = null
        pairRecord = null
        vault = null
        inbox.dismissAll()
    }

    private fun handleRelayEvent(event: StreamRelayEvent) {
        when (event) {
            is StreamRelayEvent.Connected -> {
                sessionBridge?.close()
                sessionBridge = null
                sessionHandshakeDone = false
                operationBridge?.close()
                operationBridge = null
            }

            is StreamRelayEvent.Frame -> {
                val pair = pairRecord ?: return
                val vlt = vault ?: return

                val opBridge = operationBridge
                if (opBridge != null) {
                    try {
                        val action = opBridge.receiveFrame(event.data, RappClock.monotonicMs())
                        handleBridgeAction(action, opBridge)
                    } catch (_: Exception) {
                    }
                    return
                }

                val currentSession = sessionBridge
                if (currentSession == null) {
                    try {
                        val token = pair.metadata().rendezvousToken
                        val preamble = rappStreamSessionPreamble(token)
                        if (event.data.contentEquals(preamble)) {
                            sessionBridge = RappSessionBridge.beginProxy(pair = pair, vault = vlt)
                            return
                        }
                    } catch (_: Exception) {
                    }

                    // Not preamble or preamble was skipped: treat as Noise Message 1
                    try {
                        val sess = RappSessionBridge.beginProxy(pair = pair, vault = vlt)
                        sessionBridge = sess
                        sess.readHandshakeFrame(event.data)
                        val reply = sess.writeHandshakeFrame()
                        activeListener?.send(reply)
                        if (sess.handshakeComplete()) {
                            sessionHandshakeDone = true
                            sess.enterAuthentication()
                            val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
                            val ready = sess.sendReady(nonce)
                            activeListener?.send(ready)
                        }
                    } catch (_: Exception) {
                    }
                    return
                }

                if (!sessionHandshakeDone) {
                    try {
                        currentSession.readHandshakeFrame(event.data)
                        val reply = currentSession.writeHandshakeFrame()
                        activeListener?.send(reply)
                        if (currentSession.handshakeComplete()) {
                            sessionHandshakeDone = true
                            currentSession.enterAuthentication()
                            val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
                            val ready = currentSession.sendReady(nonce)
                            activeListener?.send(ready)
                        }
                    } catch (_: Exception) {
                    }
                    return
                }

                // Bilateral ready confirmation
                try {
                    currentSession.receiveReady(event.data, RappClock.wallMs())
                    currentSession.enterEstablished()

                    val liveness =
                        RappLivenessConfiguration(
                            baseIntervalMs = 5_000UL,
                            responseTimeoutMs = 10_000UL,
                            maximumIntervalMs = 60_000UL,
                            maximumJitterMs = 500UL,
                            maximumMisses = 3.toUByte(),
                        )
                    val newOpBridge =
                        RappOperationBridge.beginProxy(
                            session = currentSession,
                            vault = vlt,
                            maximumLifetimeMs = 120_000UL,
                            liveness = liveness,
                            nowMs = RappClock.wallMs(),
                        )
                    operationBridge = newOpBridge
                } catch (_: Exception) {
                }
            }

            is StreamRelayEvent.Disconnected, is StreamRelayEvent.Error -> {
                sessionBridge?.close()
                sessionBridge = null
                sessionHandshakeDone = false
                operationBridge?.close()
                operationBridge = null
                inbox.dismissAll()
            }
        }
    }

    private val pendingPins = java.util.concurrent.ConcurrentHashMap<String, String>()

    private fun handleBridgeAction(
        action: uniffi.refineid_rapp.RappBridgeAction,
        bridge: RappOperationBridge,
    ) {
        if (action.kind == RappBridgeActionKind.SEND_FRAME) {
            action.frame?.let { frame ->
                try {
                    activeListener?.send(frame)
                } catch (e: Exception) {
                    android.util.Log.e("PROXY_DISPATCH", "send frame failed", e)
                }
            }
            return
        }

        val opId = action.operationId ?: return
        val opIdHex = opId.joinToString("") { "%02x".format(it) }

        when (action.kind) {
            RappBridgeActionKind.INSPECT_PREREQUISITES -> {
                try {
                    val resp = bridge.prerequisitesComplete(opId)
                    handleBridgeAction(resp, bridge)
                } catch (e: Exception) {
                    android.util.Log.e("PROXY_DISPATCH", "prerequisitesComplete failed", e)
                }
            }

            RappBridgeActionKind.EXECUTE_SAFE_READ -> {
                handleSafeRead(action, opId, bridge)
            }

            RappBridgeActionKind.AWAIT_USER_APPROVAL -> {
                val desc = action.operation ?: return
                handleApproval(desc, opId, opIdHex, bridge)
            }

            RappBridgeActionKind.EXECUTE_CARD_COMMAND -> {
                val desc = action.operation ?: return
                handleExecute(desc, opId, opIdHex, bridge)
            }

            RappBridgeActionKind.RESULT_ACKNOWLEDGMENT -> {
                try {
                    bridge.acknowledgmentReleased(opId)
                } catch (e: Exception) {
                    android.util.Log.e("PROXY_DISPATCH", "acknowledgmentReleased failed", e)
                }
            }

            else -> {
            }
        }
    }

    private fun handleApproval(
        desc: uniffi.refineid_rapp.RappOperationDescriptor,
        opId: ByteArray,
        opIdHex: String,
        bridge: RappOperationBridge,
    ) {
        when (desc.kind) {
            RappOperationKind.BROWSER_AUTHENTICATE -> {
                val cachedPin = pinCache?.take()
                if (cachedPin != null) {
                    cachedPin.consume { pinBytes ->
                        pendingPins[opIdHex] = String(pinBytes, Charsets.US_ASCII)
                    }
                    approve(opId, bridge)
                } else {
                    val requesterName =
                        catalog
                            .listPairs()
                            .firstOrNull()
                            ?.displayName
                            ?.takeIf { it.isNotBlank() }
                            ?: "Computer"
                    inbox.ask(
                        requestId = opIdHex,
                        requester = requesterName,
                        action = RappAuthAction.BROWSER_AUTH,
                        onApproved = { pin1 ->
                            pinCache?.recordVerified(pin1.toByteArray(Charsets.US_ASCII))
                            pendingPins[opIdHex] = pin1
                            approve(opId, bridge)
                        },
                        onDenied = { deny(opId, bridge) },
                    )
                }
            }

            RappOperationKind.SIGN_DOCUMENT -> {
                val requesterName =
                    catalog
                        .listPairs()
                        .firstOrNull()
                        ?.displayName
                        ?.takeIf { it.isNotBlank() }
                        ?: "Computer"
                inbox.ask(
                    requestId = opIdHex,
                    requester = requesterName,
                    action = RappAuthAction.DOCUMENT_SIGN,
                    onApproved = { pin2 ->
                        pendingPins[opIdHex] = pin2
                        approve(opId, bridge)
                    },
                    onDenied = { deny(opId, bridge) },
                )
            }

            else -> {
                approve(opId, bridge)
            }
        }
    }

    private fun approve(
        opId: ByteArray,
        bridge: RappOperationBridge,
    ) {
        scope.launch(Dispatchers.IO) {
            try {
                val resp = bridge.approve(opId, RappClock.monotonicMs())
                handleBridgeAction(resp, bridge)
            } catch (e: Exception) {
                android.util.Log.e("PROXY_DISPATCH", "approve failed", e)
            }
        }
    }

    private fun deny(
        opId: ByteArray,
        bridge: RappOperationBridge,
    ) {
        scope.launch(Dispatchers.IO) {
            try {
                val resp = bridge.deny(opId)
                handleBridgeAction(resp, bridge)
            } catch (e: Exception) {
                android.util.Log.e("PROXY_DISPATCH", "deny failed", e)
            }
        }
    }

    private fun handleExecute(
        desc: uniffi.refineid_rapp.RappOperationDescriptor,
        opId: ByteArray,
        opIdHex: String,
        bridge: RappOperationBridge,
    ) {
        val pin = pendingPins.remove(opIdHex) ?: ""
        when (desc.kind) {
            RappOperationKind.BROWSER_AUTHENTICATE -> {
                executeBrowserAuth(opId, desc, pin, bridge)
            }

            RappOperationKind.SIGN_DOCUMENT -> {
                executeDocumentSign(opId, desc, pin, bridge)
            }

            else -> {
            }
        }
    }

    private fun handleSafeRead(
        action: uniffi.refineid_rapp.RappBridgeAction,
        opId: ByteArray,
        bridge: RappOperationBridge,
    ) {
        val desc = action.operation
        if (desc?.kind != RappOperationKind.READ_AUTHENTICATION_CERTIFICATE) return
        scope.launch(Dispatchers.IO) {
            val certDer = readAuthCertWithTimeout()
            if (certDer != null) {
                try {
                    val resp = bridge.completeCertificate(opId, certDer)
                    handleBridgeAction(resp, bridge)
                } catch (_: Exception) {
                }
            } else {
                try {
                    val resp = bridge.cardRemovedBeforeTransmit(opId)
                    handleBridgeAction(resp, bridge)
                } catch (_: Exception) {
                }
            }
        }
    }

    private suspend fun readAuthCertWithTimeout(): ByteArray? {
        val deferred = CompletableDeferred<ByteArray?>()
        authCardService()?.requestAuthenticationCertificate { cert ->
            try {
                deferred.complete(cert?.copyDer())
            } catch (_: Exception) {
                deferred.complete(null)
            }
        } ?: deferred.complete(null)
        return try {
            withTimeoutOrNull(CERT_READ_TIMEOUT_MS) { deferred.await() }
        } catch (_: Exception) {
            null
        }
    }

    private fun executeBrowserAuth(
        opId: ByteArray,
        desc: RappOperationDescriptor,
        pin1: String,
        bridge: RappOperationBridge,
    ) {
        scope.launch(Dispatchers.IO) {
            val algorithm = resolveSignAlgorithm(desc)
            if (algorithm == null) {
                try {
                    val resp = bridge.credentialRejected(opId, RappClock.monotonicMs())
                    handleBridgeAction(resp, bridge)
                } catch (_: Exception) {
                }
                return@launch
            }
            if (!isCardReady()) {
                val requesterName =
                    catalog
                        .listPairs()
                        .firstOrNull()
                        ?.displayName
                        ?.takeIf { it.isNotBlank() }
                        ?: "Computer"
                val opIdHex = opId.joinToString("") { "%02x".format(it) }
                var cancelled = false
                inbox.showTapPrompt(
                    requestId = opIdHex,
                    requester = requesterName,
                    action = RappAuthAction.BROWSER_AUTH,
                    onCancel = {
                        cancelled = true
                    },
                )
                val ready = awaitCardReady()
                inbox.dismissTapPrompt(opIdHex)
                if (!ready || cancelled) {
                    try {
                        val resp = bridge.credentialRejected(opId, RappClock.monotonicMs())
                        handleBridgeAction(resp, bridge)
                    } catch (_: Exception) {
                    }
                    return@launch
                }
            }
            val service = authCardService()
            if (service == null) {
                try {
                    val resp = bridge.credentialRejected(opId, RappClock.monotonicMs())
                    handleBridgeAction(resp, bridge)
                } catch (_: Exception) {
                }
                return@launch
            }
            val result =
                service.signAuthenticationDigest(
                    algorithm = algorithm,
                    pin1 = Pin1Submission.from(pin1),
                    digest = desc.digest,
                )
            when (result) {
                is AuthenticationSignResult.Success -> {
                    try {
                        val resp = bridge.completeSignature(opId, result.signature.copyBytes())
                        handleBridgeAction(resp, bridge)
                    } catch (_: Exception) {
                    }
                }

                else -> {
                    try {
                        val resp = bridge.credentialRejected(opId, RappClock.monotonicMs())
                        handleBridgeAction(resp, bridge)
                    } catch (_: Exception) {
                    }
                }
            }
        }
    }

    private fun resolveSignAlgorithm(desc: RappOperationDescriptor): AuthenticationSigningAlgorithm? =
        when (desc.algorithm) {
            RappSignatureAlgorithm.ECDSA_SHA256 -> AuthenticationSigningAlgorithm.ECDSA_P384_SHA256
            RappSignatureAlgorithm.ECDSA_SHA384 -> AuthenticationSigningAlgorithm.ECDSA_P384_SHA384
            RappSignatureAlgorithm.RSA_PKCS1_SHA256 -> AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256
            RappSignatureAlgorithm.RSA_PKCS1_SHA384 -> AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384
            RappSignatureAlgorithm.RSA_PKCS1_SHA512 -> AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512
            RappSignatureAlgorithm.RSA_PSS_SHA256 -> AuthenticationSigningAlgorithm.RSA_PSS_SHA256
            else -> fallbackSignAlgorithm(desc.digest.size)
        }

    private fun fallbackSignAlgorithm(digestSize: Int): AuthenticationSigningAlgorithm? =
        when (digestSize) {
            SHA256_DIGEST_LENGTH -> AuthenticationSigningAlgorithm.ECDSA_P384_SHA256
            SHA384_DIGEST_LENGTH -> AuthenticationSigningAlgorithm.ECDSA_P384_SHA384
            else -> null
        }

    private fun executeDocumentSign(
        opId: ByteArray,
        desc: RappOperationDescriptor,
        pin2: String,
        bridge: RappOperationBridge,
    ) {
        scope.launch(Dispatchers.IO) {
            try {
                val resp = bridge.credentialRejected(opId, RappClock.monotonicMs())
                handleBridgeAction(resp, bridge)
            } catch (_: Exception) {
            }
        }
    }

    override fun close() {
        isClosed = true
        activeListener?.close()
        activeListener = null
        operationBridge?.close()
        operationBridge = null
        sessionBridge?.close()
        sessionBridge = null
        inbox.dismissAll()
    }
}
