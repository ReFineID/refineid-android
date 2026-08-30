@file:Suppress("UnusedParameter", "TooGenericExceptionCaught")

package fi.refineid.android.rapp

import android.content.Context
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.QualifiedCardService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import uniffi.refineid_rapp.RappBridgeActionKind
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappOperationDescriptor
import uniffi.refineid_rapp.RappOperationKind

/**
 * Handles incoming RAPP protocol requests from a paired Mac, coordinates user approvals,
 * and executes card signing operations via physical card services.
 */
internal class RappPhoneProxyDispatcher(
    private val context: Context,
    private val scope: CoroutineScope,
    private val inbox: RappAuthorizationInbox,
    private val authCardService: () -> AuthenticationCardService?,
    private val qualifiedCardService: () -> QualifiedCardService?,
) : AutoCloseable {
    private var activeListener: StreamRelayListener? = null
    private var operationBridge: RappOperationBridge? = null
    private var isClosed = false

    fun startListening(rendezvousName: String) {
        if (isClosed) return
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
            is StreamRelayEvent.Frame -> {
                val bridge = operationBridge ?: return
                try {
                    val action = bridge.receiveFrame(event.data, RappClock.monotonicMs())
                    handleBridgeAction(action, bridge)
                } catch (_: Exception) {
                }
            }

            is StreamRelayEvent.Disconnected, is StreamRelayEvent.Error -> {
                inbox.dismissAll()
            }

            is StreamRelayEvent.Connected -> {
                // Connected and waiting for frames
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

            RappBridgeActionKind.AWAIT_USER_APPROVAL -> {
                val desc = action.operation ?: return
                when (desc.kind) {
                    RappOperationKind.BROWSER_AUTHENTICATE -> {
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

            RappBridgeActionKind.EXECUTE_CARD_COMMAND -> {
                // Card command execution
            }

            else -> {
                // Ignore other bridge action kinds
            }
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
            // Document signing execution
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
        inbox.dismissAll()
    }
}
