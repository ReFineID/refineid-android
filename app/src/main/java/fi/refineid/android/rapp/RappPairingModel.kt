@file:Suppress("TooGenericExceptionCaught", "MagicNumber", "MaxLineLength")

package fi.refineid.android.rapp

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import uniffi.refineid_lib_core.RappPairingBridge
import uniffi.refineid_lib_core.RappTransportCandidate

internal sealed interface PairingPhase {
    data object Idle : PairingPhase

    data class Offering(
        val code: String,
        val secondsRemaining: Int,
    ) : PairingPhase

    data object CodeEntry : PairingPhase

    data class Connecting(
        val message: String,
    ) : PairingPhase

    data class Paired(
        val peer: PairedPeer,
    ) : PairingPhase

    data class Failed(
        val reason: String,
    ) : PairingPhase
}

internal class RappPairingModel(
    private val context: Context,
    private val scope: CoroutineScope,
) : AutoCloseable {
    private val catalog = RappPairCatalog(context)
    private var listener: StreamRelayListener? = null
    private var browser: StreamRelayBrowser? = null
    private var pairingBridge: RappPairingBridge? = null
    private var timerJob: Job? = null

    var phase by mutableStateOf<PairingPhase>(PairingPhase.Idle)
        private set

    val pairedDevices: List<PairedPeer>
        get() = catalog.listPairs()

    fun createOffer() {
        reset()
        val code = RappPairingCode.generate()
        val offerId = RappPairingCode.offerIdentifier(code)
        val pairingSecret = RappPairingCode.pairingSecret(code)
        val candidates =
            listOf(
                RappTransportCandidate(
                    profile = "fi.refineid.stream.v1",
                    candidateId = "stream-1",
                    parametersCbor = byteArrayOf(0xa0.toByte()),
                ),
            )
        val profiles =
            listOf(
                "fi.refineid.card-status.v1",
                "fi.refineid.authentication.v1",
                "fi.refineid.document-signing.v1",
            )

        try {
            val bridge =
                RappPairingBridge.createRequesterOffer(
                    offerId = offerId,
                    pairingSecret = pairingSecret,
                    profiles = profiles,
                    transports = candidates,
                    offerTtlMs = RappPairingCode.DEFAULT_LIFETIME_MS.toULong(),
                )
            pairingBridge = bridge
            val offerUri = bridge.offerUri()
            val rendezvousName = StreamRendezvousName.name(sharingOfferUri = offerUri)

            phase = PairingPhase.Offering(code = code, secondsRemaining = 180)
            startCountdown()

            val relayListener =
                StreamRelayListener(context, scope) { event ->
                    handleListenerEvent(event, bridge)
                }
            listener = relayListener
            relayListener.start(rendezvousName)
        } catch (e: Exception) {
            phase = PairingPhase.Failed(e.message ?: "Failed to generate pairing offer")
        }
    }

    private fun handleListenerEvent(
        event: StreamRelayEvent,
        bridge: RappPairingBridge,
    ) {
        when (event) {
            is StreamRelayEvent.Connected -> {
                phase = PairingPhase.Connecting("Exchanging security handshake...")
                try {
                    val frame = bridge.writeHandshakeFrame()
                    if (frame.isNotEmpty()) {
                        listener?.send(frame)
                    }
                } catch (e: Exception) {
                    phase = PairingPhase.Failed("Handshake write error: ${e.message}")
                }
            }

            is StreamRelayEvent.Frame -> {
                try {
                    bridge.readHandshakeFrame(event.data)
                    if (bridge.handshakeComplete()) {
                        val nowMs = System.currentTimeMillis().toULong()
                        val hello = bridge.receiveHello(event.data, nowMs)
                        val conf =
                            bridge.sendConfirmation(
                                listOf("fi.refineid.authentication.v1", "fi.refineid.document-signing.v1"),
                            )
                        listener?.send(conf)
                        val record = bridge.finishPairing(nowMs)
                        val peer =
                            PairedPeer(
                                pairIdHex = record.metadata().pairId.joinToString("") { "%02x".format(it) },
                                displayName = hello.displayName.ifEmpty { "Mac" },
                                platform = hello.platform.ifEmpty { "macOS" },
                                createdAtMs = System.currentTimeMillis(),
                            )
                        catalog.savePair(
                            pairId = record.metadata().pairId,
                            displayName = peer.displayName,
                            platform = peer.platform,
                            createdAtMs = peer.createdAtMs,
                        )
                        phase = PairingPhase.Paired(peer)
                    } else {
                        val response = bridge.writeHandshakeFrame()
                        if (response.isNotEmpty()) {
                            listener?.send(response)
                        }
                    }
                } catch (_: Exception) {
                    // Ongoing frames
                }
            }

            is StreamRelayEvent.Disconnected -> {
                if (phase is PairingPhase.Connecting) {
                    phase = PairingPhase.Failed("Peer disconnected during pairing")
                }
            }

            is StreamRelayEvent.Error -> {
                phase = PairingPhase.Failed(event.cause.message ?: "Network error")
            }
        }
    }

    fun startCodeEntry() {
        reset()
        phase = PairingPhase.CodeEntry
    }

    fun connectWithCode(rawCode: String) {
        val code = RappPairingCode.normalize(rawCode)
        if (!RappPairingCode.isValid(code)) return

        phase = PairingPhase.Connecting("Locating Mac...")
        val offerId = RappPairingCode.offerIdentifier(code)
        val pairingSecret = RappPairingCode.pairingSecret(code)
        val candidates =
            listOf(
                RappTransportCandidate(
                    profile = "fi.refineid.stream.v1",
                    candidateId = "stream-1",
                    parametersCbor = byteArrayOf(0xa0.toByte()),
                ),
            )
        val profiles =
            listOf(
                "fi.refineid.card-status.v1",
                "fi.refineid.authentication.v1",
                "fi.refineid.document-signing.v1",
            )

        try {
            val bridge =
                RappPairingBridge.createRequesterOffer(
                    offerId = offerId,
                    pairingSecret = pairingSecret,
                    profiles = profiles,
                    transports = candidates,
                    offerTtlMs = RappPairingCode.DEFAULT_LIFETIME_MS.toULong(),
                )
            pairingBridge = bridge
            val offerUri = bridge.offerUri()
            val rendezvousName = StreamRendezvousName.name(sharingOfferUri = offerUri)

            val relayBrowser =
                StreamRelayBrowser(context, scope, rendezvousName) { event ->
                    handleBrowserEvent(event, bridge)
                }
            browser = relayBrowser
            relayBrowser.start()
        } catch (e: Exception) {
            phase = PairingPhase.Failed(e.message ?: "Failed to initiate pairing")
        }
    }

    private fun handleBrowserEvent(
        event: StreamRelayEvent,
        bridge: RappPairingBridge,
    ) {
        when (event) {
            is StreamRelayEvent.Connected -> {
                phase = PairingPhase.Connecting("Connected! Verifying credentials...")
                try {
                    val frame = bridge.writeHandshakeFrame()
                    if (frame.isNotEmpty()) {
                        browser?.send(frame)
                    }
                } catch (e: Exception) {
                    phase = PairingPhase.Failed("Handshake write error: ${e.message}")
                }
            }

            is StreamRelayEvent.Frame -> {
                try {
                    bridge.readHandshakeFrame(event.data)
                    if (bridge.handshakeComplete()) {
                        val nowMs = System.currentTimeMillis().toULong()
                        val hello = bridge.sendHello(displayName = "Samsung Galaxy", platform = "Android")
                        browser?.send(hello)
                        val record = bridge.finishPairing(nowMs)
                        val peer =
                            PairedPeer(
                                pairIdHex = record.metadata().pairId.joinToString("") { "%02x".format(it) },
                                displayName = "Mac",
                                platform = "macOS",
                                createdAtMs = System.currentTimeMillis(),
                            )
                        catalog.savePair(
                            pairId = record.metadata().pairId,
                            displayName = peer.displayName,
                            platform = peer.platform,
                            createdAtMs = peer.createdAtMs,
                        )
                        phase = PairingPhase.Paired(peer)
                    } else {
                        val response = bridge.writeHandshakeFrame()
                        if (response.isNotEmpty()) {
                            browser?.send(response)
                        }
                    }
                } catch (_: Exception) {
                }
            }

            is StreamRelayEvent.Disconnected -> {
                if (phase is PairingPhase.Connecting) {
                    phase = PairingPhase.Failed("Peer disconnected")
                }
            }

            is StreamRelayEvent.Error -> {
                phase = PairingPhase.Failed(event.cause.message ?: "Connection error")
            }
        }
    }

    private fun startCountdown() {
        timerJob?.cancel()
        timerJob =
            scope.launch(Dispatchers.Main) {
                for (sec in 180 downTo 0) {
                    val current = phase
                    if (current is PairingPhase.Offering) {
                        phase = current.copy(secondsRemaining = sec)
                    }
                    delay(1000L)
                }
                if (phase is PairingPhase.Offering) {
                    phase = PairingPhase.Failed("Pairing timed out")
                    reset()
                }
            }
    }

    fun removePair(pairIdHex: String) {
        catalog.removePair(pairIdHex)
    }

    fun reset() {
        timerJob?.cancel()
        timerJob = null
        listener?.close()
        listener = null
        browser?.close()
        browser = null
        pairingBridge?.close()
        pairingBridge = null
        phase = PairingPhase.Idle
    }

    override fun close() {
        reset()
    }
}
