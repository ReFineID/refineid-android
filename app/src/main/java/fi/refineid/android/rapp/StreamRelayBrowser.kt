@file:Suppress("TooGenericExceptionCaught", "SwallowedException", "MagicNumber", "MaxLineLength")

package fi.refineid.android.rapp

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Browses for a published RAPP stream matching a rendezvous name and connects.
 */
internal class StreamRelayBrowser(
    private val context: Context,
    private val scope: CoroutineScope,
    private val targetServiceName: String,
    private val onEvent: (StreamRelayEvent) -> Unit,
) : AutoCloseable {
    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as? NsdManager
    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private var socket: Socket? = null
    private var outputStream: DataOutputStream? = null
    private var readJob: Job? = null
    private val isClosed = AtomicBoolean(false)
    private val isConnected = AtomicBoolean(false)

    fun start() {
        if (isClosed.get()) return
        val listener =
            object : NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(regType: String) = Unit

                override fun onDiscoveryStopped(serviceType: String) = Unit

                override fun onStartDiscoveryFailed(
                    serviceType: String,
                    errorCode: Int,
                ) {
                    onEvent(StreamRelayEvent.Error(IOException("NSD discovery failed: $errorCode")))
                }

                override fun onStopDiscoveryFailed(
                    serviceType: String,
                    errorCode: Int,
                ) = Unit

                override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                    if (serviceInfo.serviceName == targetServiceName ||
                        serviceInfo.serviceName.contains(targetServiceName)
                    ) {
                        resolveAndConnect(serviceInfo)
                    }
                }

                override fun onServiceLost(serviceInfo: NsdServiceInfo) = Unit
            }
        discoveryListener = listener
        try {
            nsdManager?.discoverServices(
                StreamRelayListener.SERVICE_TYPE,
                NsdManager.PROTOCOL_DNS_SD,
                listener,
            )
        } catch (e: Exception) {
            onEvent(StreamRelayEvent.Error(e))
        }
    }

    @Suppress("DEPRECATION")
    private fun resolveAndConnect(serviceInfo: NsdServiceInfo) {
        if (isConnected.get() || isClosed.get()) return
        nsdManager?.resolveService(
            serviceInfo,
            object : NsdManager.ResolveListener {
                override fun onResolveFailed(
                    serviceInfo: NsdServiceInfo,
                    errorCode: Int,
                ) = Unit

                override fun onServiceResolved(resolved: NsdServiceInfo) {
                    if (isConnected.compareAndSet(false, true)) {
                        stopDiscovery()
                        connectToEndpoint(resolved.host.hostAddress, resolved.port)
                    }
                }
            },
        )
    }

    private fun connectToEndpoint(
        host: String?,
        port: Int,
    ) {
        if (host == null || port <= 0) return
        scope.launch(Dispatchers.IO) {
            try {
                val s = Socket()
                s.connect(InetSocketAddress(host, port), 5000)
                socket = s
                outputStream = DataOutputStream(s.getOutputStream())
                onEvent(StreamRelayEvent.Connected)

                val input = DataInputStream(s.getInputStream())
                while (scope.isActive && !isClosed.get() && !s.isClosed) {
                    val length = input.readUnsignedShort()
                    val buffer = ByteArray(length)
                    input.readFully(buffer)
                    onEvent(StreamRelayEvent.Frame(buffer))
                }
            } catch (e: IOException) {
                if (!isClosed.get()) {
                    onEvent(StreamRelayEvent.Disconnected)
                }
            }
        }
    }

    fun send(frame: ByteArray) {
        if (isClosed.get()) throw IOException("Browser is closed")
        val out = outputStream ?: throw IOException("Not connected")
        synchronized(this) {
            out.writeShort(frame.size)
            out.write(frame)
            out.flush()
        }
    }

    private fun stopDiscovery() {
        discoveryListener?.let {
            try {
                nsdManager?.stopServiceDiscovery(it)
            } catch (_: Exception) {
            }
        }
        discoveryListener = null
    }

    override fun close() {
        if (isClosed.compareAndSet(false, true)) {
            stopDiscovery()
            readJob?.cancel()
            try {
                socket?.close()
            } catch (_: Exception) {
            }
            outputStream = null
        }
    }
}
