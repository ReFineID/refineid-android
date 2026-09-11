package fi.refineid.android.usb

internal const val CCID_INTERFACE_CLASS = 0x0B

internal data class UsbInterfaceDescriptor(
    val interfaceClass: Int,
)

internal data class UsbDeviceDescriptor(
    val deviceId: Int,
    val interfaces: List<UsbInterfaceDescriptor>,
)

internal data class CcidReaderMatch(
    val deviceId: Int,
)

internal object CcidReaderClassifier {
    fun classify(device: UsbDeviceDescriptor): CcidReaderMatch? {
        if (device.interfaces.none { it.interfaceClass == CCID_INTERFACE_CLASS }) {
            return null
        }

        return CcidReaderMatch(
            deviceId = device.deviceId,
        )
    }

    fun classifyAll(devices: List<UsbDeviceDescriptor>): List<CcidReaderMatch> = devices.mapNotNull(::classify)

    fun selectPreferred(
        devices: List<UsbDeviceDescriptor>,
        preferredDeviceId: Int? = null,
    ): CcidReaderMatch? {
        val matches = classifyAll(devices)
        if (preferredDeviceId != null) {
            val preferred = matches.firstOrNull { it.deviceId == preferredDeviceId }
            if (preferred != null) {
                return preferred
            }
        }
        return matches.minByOrNull(CcidReaderMatch::deviceId)
    }
}
