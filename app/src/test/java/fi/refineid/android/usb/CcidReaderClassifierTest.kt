package fi.refineid.android.usb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CcidReaderClassifierTest {
    @Test
    fun recognizesReaderByCcidInterface() {
        val match =
            CcidReaderClassifier.classify(
                descriptor(
                    deviceId = SYNTHETIC_DEVICE_ID,
                    interfaceClasses = listOf(CCID_INTERFACE_CLASS),
                ),
            )

        assertEquals(SYNTHETIC_DEVICE_ID, match?.deviceId)
    }

    @Test
    fun rejectsDeviceWithoutCcidInterface() {
        val match =
            CcidReaderClassifier.classify(
                descriptor(
                    deviceId = SYNTHETIC_DEVICE_ID,
                    interfaceClasses = listOf(MASS_STORAGE_INTERFACE_CLASS),
                ),
            )

        assertNull(match)
    }

    @Test
    fun selectsCcidReaderDeterministically() {
        val selected =
            CcidReaderClassifier.selectPreferred(
                listOf(
                    descriptor(
                        deviceId = HIGHER_DEVICE_ID,
                        interfaceClasses = listOf(CCID_INTERFACE_CLASS),
                    ),
                    descriptor(
                        deviceId = LOWER_DEVICE_ID,
                        interfaceClasses = listOf(CCID_INTERFACE_CLASS),
                    ),
                ),
            )

        assertEquals(LOWER_DEVICE_ID, selected?.deviceId)
    }

    private fun descriptor(
        deviceId: Int,
        interfaceClasses: List<Int>,
    ) = UsbDeviceDescriptor(
        deviceId = deviceId,
        interfaces = interfaceClasses.map(::UsbInterfaceDescriptor),
    )

    private companion object {
        const val SYNTHETIC_DEVICE_ID = 7
        const val HIGHER_DEVICE_ID = 9
        const val LOWER_DEVICE_ID = 1
        const val MASS_STORAGE_INTERFACE_CLASS = 0x08
    }
}
