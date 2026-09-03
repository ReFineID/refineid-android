@file:Suppress("UnusedParameter", "TooGenericExceptionCaught")

package fi.refineid.android.rapp

import android.content.Context
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
) : AutoCloseable {
    private var activeListener: StreamRelayListener? = null
    private var sessionBridge: RappSessionBridge? = null
    private var sessionHandshakeDone = false
    private var operationBridge: RappOperationBridge? = null
    private var pairRecord: RappPairRecord? = null
    private var vault: AndroidRappVault? = null
    private var isClosed = false

    companion object {
        /** Maximum time to wait for an NFC card certificate read before reporting card-removed. */
        private const val CERT_READ_TIMEOUT_MS = 5_000L
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

    private fun handleBridgeAction(
        action: uniffi.refineid_rapp.RappBridgeAction,
        bridge: RappOperationBridge,
    ) {
        val opId = action.operationId ?: return
        val opIdHex = opId.joinToString("") { "%02x".format(it) }

        when (action.kind) {
            RappBridgeActionKind.SEND_FRAME -> {
                action.frame?.let { frame ->
                    try {
                        activeListener?.send(frame)
                    } catch (_: Exception) {
                    }
                }
            }

            RappBridgeActionKind.INSPECT_PREREQUISITES -> {
                try {
                    val resp = bridge.prerequisitesComplete(opId)
                    handleBridgeAction(resp, bridge)
                } catch (_: Exception) {
                }
            }

            RappBridgeActionKind.EXECUTE_SAFE_READ -> {
                handleSafeRead(action, opId, bridge)
            }

            RappBridgeActionKind.AWAIT_USER_APPROVAL -> {
                val desc = action.operation ?: return
                when (desc.kind) {
                    RappOperationKind.BROWSER_AUTHENTICATE -> {
                        // Check if PIN1 is cached
                        val cachedPin = pinCache?.take()
                        if (cachedPin != null) {
                            cachedPin.consume { pinBytes ->
                                val pinString = String(pinBytes, Charsets.US_ASCII)
                                executeBrowserAuth(opId, desc, pinString, bridge)
                            }
                        } else {
                            inbox.ask(
                                requestId = opIdHex,
                                requester = "Mac (Safari)",
                                action = RappAuthAction.BROWSER_AUTH,
                                onApproved = { pin1 ->
                                    executeBrowserAuth(opId, desc, pin1, bridge)
                                },
                                onDenied = {
                                    try {
                                        val resp = bridge.deny(opId)
                                        handleBridgeAction(resp, bridge)
                                    } catch (_: Exception) {
                                    }
                                },
                            )
                        }
                    }

                    RappOperationKind.SIGN_DOCUMENT -> {
                        inbox.ask(
                            requestId = opIdHex,
                            requester = "Mac",
                            action = RappAuthAction.DOCUMENT_SIGN,
                            onApproved = { pin2 ->
                                executeDocumentSign(opId, desc, pin2, bridge)
                            },
                            onDenied = {
                                try {
                                    val resp = bridge.deny(opId)
                                    handleBridgeAction(resp, bridge)
                                } catch (_: Exception) {
                                }
                            },
                        )
                    }

                    else -> {
                        try {
                            val resp = bridge.approve(opId, RappClock.monotonicMs())
                            handleBridgeAction(resp, bridge)
                        } catch (_: Exception) {
                        }
                    }
                }
            }

            RappBridgeActionKind.RESULT_ACKNOWLEDGMENT -> {
                try {
                    bridge.acknowledgmentReleased(opId)
                } catch (_: Exception) {
                }
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
                    algorithm = AuthenticationSigningAlgorithm.ECDSA_P384_SHA384,
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
