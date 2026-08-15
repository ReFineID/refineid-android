package fi.refineid.android.usb.ccid

import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface

internal data class CcidUsbEndpoints(
    val usbInterface: UsbInterface,
    val bulkIn: UsbEndpoint,
    val bulkOut: UsbEndpoint,
)

internal object CcidUsbEndpointFinder {
    fun find(device: UsbDevice): CcidUsbEndpoints? {
        repeat(device.interfaceCount) { interfaceIndex ->
            val usbInterface = device.getInterface(interfaceIndex)
            if (usbInterface.interfaceClass != UsbConstants.USB_CLASS_CSCID) {
                return@repeat
            }

            var bulkIn: UsbEndpoint? = null
            var bulkOut: UsbEndpoint? = null
            repeat(usbInterface.endpointCount) { endpointIndex ->
                val endpoint = usbInterface.getEndpoint(endpointIndex)
                if (endpoint.type == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                    when (endpoint.direction) {
                        UsbConstants.USB_DIR_IN -> bulkIn = endpoint
                        UsbConstants.USB_DIR_OUT -> bulkOut = endpoint
                    }
                }
            }

            if (bulkIn != null && bulkOut != null) {
                return CcidUsbEndpoints(
                    usbInterface = usbInterface,
                    bulkIn = requireNotNull(bulkIn),
                    bulkOut = requireNotNull(bulkOut),
                )
            }
        }

        return null
    }
}

internal class AndroidCcidBulkIo(
    private val connection: UsbDeviceConnection,
    private val endpoints: CcidUsbEndpoints,
) : CcidBulkIo {
    override fun write(frame: ByteArray): Int =
        transfer(
            endpoint = endpoints.bulkOut,
            frame = frame,
        )

    override fun read(frame: ByteArray): Int =
        transfer(
            endpoint = endpoints.bulkIn,
            frame = frame,
        )

    private fun transfer(
        endpoint: UsbEndpoint,
        frame: ByteArray,
    ): Int =
        try {
            connection.bulkTransfer(
                endpoint,
                frame,
                0,
                frame.size,
                USB_TRANSFER_TIMEOUT_MILLISECONDS,
            )
        } catch (_: SecurityException) {
            -1
        }

    private companion object {
        const val USB_TRANSFER_TIMEOUT_MILLISECONDS = 2_000
    }
}
