@file:Suppress("SwallowedException", "MaxLineLength", "TooGenericExceptionCaught")

package fi.refineid.android.rapp

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import fi.refineid.android.BuildConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

internal sealed interface StreamRelayEvent {
    data object Connected : StreamRelayEvent

    data class Frame(
        val data: ByteArray,
    ) : StreamRelayEvent

    data object Disconnected : StreamRelayEvent

    data class Error(
        val cause: Throwable,
    ) : StreamRelayEvent
}

/**
 * Listens for incoming RAPP stream connections and advertises via mDNS/NSD.
 */
internal class StreamRelayListener(
    private val context: Context,
    private val scope: CoroutineScope,
    private val onEvent: (StreamRelayEvent) -> Unit,
) : AutoCloseable {
    companion object {
        const val SERVICE_TYPE = "_refineid-stream._tcp"
    }

    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as? NsdManager
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    private val multicastLock =
        wifiManager?.createMulticastLock("refineid-listener")?.apply {
            setReferenceCounted(false)
        }

    private var serverSocket: ServerSocket? = null
    private var clientSocket: Socket? = null
    private var outputStream: DataOutputStream? = null
    private var listenerJob: Job? = null
    private var readJob: Job? = null
    private val isClosed = AtomicBoolean(false)
    private var registrationListener: NsdManager.RegistrationListener? = null

    val port: Int?
        get() = serverSocket?.localPort

    fun start(displayName: String) {
        if (isClosed.get()) return
        try {
            multicastLock?.acquire()
        } catch (_: Exception) {
        }
        try {
            val server = ServerSocket(0)
            serverSocket = server
            if (BuildConfig.DEBUG) {
                android.util.Log.i("STREAM_LISTENER", "ServerSocket listening on port ${server.localPort}")
            }

            val serviceInfo =
                NsdServiceInfo().apply {
                    serviceName = displayName
                    serviceType = SERVICE_TYPE
                    port = server.localPort
                }

            val regListener =
                object : NsdManager.RegistrationListener {
                    override fun onServiceRegistered(serviceInfo: NsdServiceInfo) {
                        if (BuildConfig.DEBUG) {
                            android.util.Log.i("STREAM_LISTENER", "onServiceRegistered: ${serviceInfo.serviceName}")
                        }
                    }

                    override fun onRegistrationFailed(
                        serviceInfo: NsdServiceInfo,
                        errorCode: Int,
                    ) {
                        android.util.Log.e(
                            "STREAM_LISTENER",
                            "onRegistrationFailed: ${serviceInfo.serviceName}, errorCode: $errorCode",
                        )
                    }

                    override fun onServiceUnregistered(serviceInfo: NsdServiceInfo) {
                        if (BuildConfig.DEBUG) {
                            android.util.Log.i("STREAM_LISTENER", "onServiceUnregistered: ${serviceInfo.serviceName}")
                        }
                    }

                    override fun onUnregistrationFailed(
                        serviceInfo: NsdServiceInfo,
                        errorCode: Int,
                    ) {
                        android.util.Log.e(
                            "STREAM_LISTENER",
                            "onUnregistrationFailed: ${serviceInfo.serviceName}, errorCode: $errorCode",
                        )
                    }
                }
            registrationListener = regListener
            nsdManager?.registerService(serviceInfo, NsdManager.PROTOCOL_DNS_SD, regListener)

            listenerJob =
                scope.launch(Dispatchers.IO) {
                    while (isActive && !isClosed.get()) {
                        try {
                            val socket = server.accept()
                            if (BuildConfig.DEBUG) {
                                android.util.Log.i(
                                    "STREAM_LISTENER",
                                    "Accepted connection from ${socket.remoteSocketAddress}",
                                )
                            }
                            readJob?.cancel()
                            clientSocket?.close()
                            clientSocket = socket
                            outputStream = DataOutputStream(socket.getOutputStream())
                            onEvent(StreamRelayEvent.Connected)

                            readJob =
                                scope.launch(Dispatchers.IO) {
                                    readLoop(socket)
                                }
                        } catch (e: IOException) {
                            if (!isClosed.get()) {
                                android.util.Log.w("STREAM_LISTENER", "ServerSocket accept loop exited: ${e.message}")
                                onEvent(StreamRelayEvent.Error(e))
                            }
                            break
                        }
                    }
                }
        } catch (e: IOException) {
            android.util.Log.e("STREAM_LISTENER", "start failed", e)
            onEvent(StreamRelayEvent.Error(e))
        }
    }

    private suspend fun readLoop(socket: Socket) {
        val input = DataInputStream(socket.getInputStream())
        try {
            while (scope.isActive && !isClosed.get() && !socket.isClosed) {
                val length = input.readUnsignedShort()
                val buffer = ByteArray(length)
                input.readFully(buffer)
                if (BuildConfig.DEBUG) {
                    android.util.Log.d(
                        "STREAM_LISTENER",
                        "Received frame length=$length from ${socket.remoteSocketAddress}",
                    )
                }
                onEvent(StreamRelayEvent.Frame(buffer))
            }
        } catch (e: IOException) {
            if (BuildConfig.DEBUG) {
                android.util.Log.w("STREAM_LISTENER", "Socket read loop ended: ${e.message}")
            }
            if (!isClosed.get() && clientSocket === socket) {
                onEvent(StreamRelayEvent.Disconnected)
            }
        }
    }

    fun send(frame: ByteArray) {
        if (isClosed.get()) throw IOException("Listener is closed")
        val out = outputStream ?: throw IOException("No peer connected")
        synchronized(this) {
            if (BuildConfig.DEBUG) {
                android.util.Log.d("STREAM_LISTENER", "Sending frame size=${frame.size}")
            }
            out.writeShort(frame.size)
            out.write(frame)
            out.flush()
        }
    }

    override fun close() {
        if (isClosed.compareAndSet(false, true)) {
            if (BuildConfig.DEBUG) android.util.Log.i("STREAM_LISTENER", "close() called")
            registrationListener?.let {
                try {
                    nsdManager?.unregisterService(it)
                } catch (_: Exception) {
                }
            }
            registrationListener = null
            listenerJob?.cancel()
            readJob?.cancel()
            try {
                clientSocket?.close()
            } catch (_: Exception) {
            }
            try {
                serverSocket?.close()
            } catch (_: Exception) {
            }
            outputStream = null
            try {
                multicastLock?.release()
            } catch (_: Exception) {
            }
        }
    }
}
