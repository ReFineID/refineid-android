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

    @Test
    fun classifiesAllCcidReaders() {
        val matches =
            CcidReaderClassifier.classifyAll(
                listOf(
                    descriptor(
                        deviceId = HIGHER_DEVICE_ID,
                        interfaceClasses = listOf(CCID_INTERFACE_CLASS),
                    ),
                    descriptor(
                        deviceId = SYNTHETIC_DEVICE_ID,
                        interfaceClasses = listOf(MASS_STORAGE_INTERFACE_CLASS),
                    ),
                    descriptor(
                        deviceId = LOWER_DEVICE_ID,
                        interfaceClasses = listOf(CCID_INTERFACE_CLASS),
                    ),
                ),
            )

        assertEquals(2, matches.size)
        assertEquals(listOf(HIGHER_DEVICE_ID, LOWER_DEVICE_ID), matches.map { it.deviceId })
    }

    @Test
    fun prefersExplicitDeviceId() {
        val selected =
            CcidReaderClassifier.selectPreferred(
                listOf(
                    descriptor(
                        deviceId = LOWER_DEVICE_ID,
                        interfaceClasses = listOf(CCID_INTERFACE_CLASS),
                    ),
                    descriptor(
                        deviceId = HIGHER_DEVICE_ID,
                        interfaceClasses = listOf(CCID_INTERFACE_CLASS),
                    ),
                ),
                preferredDeviceId = HIGHER_DEVICE_ID,
            )

        assertEquals(HIGHER_DEVICE_ID, selected?.deviceId)
    }

    @Test
    fun usbReaderInfoReflectsSelectionAndActivation() {
        val reader =
            UsbReaderInfo(
                deviceId = 42,
                name = "Identiv SCR3500",
                isSelected = true,
                cardPresence = CardPresence.PRESENT,
                isActivationRequired = true,
                holderName = "MALLI KORTTIHALTIJA",
            )

        val snapshot =
            UsbReaderSnapshot(
                status = ReaderConnectionStatus.ACTIVATION_REQUIRED,
                cardPresence = CardPresence.PRESENT,
                holderName = "MALLI KORTTIHALTIJA",
                availableReaders = listOf(reader),
            )

        assertEquals(1, snapshot.availableReaders.size)
        assertEquals("MALLI KORTTIHALTIJA", snapshot.availableReaders.first().holderName)
        org.junit.Assert.assertTrue(snapshot.availableReaders.first().isActivationRequired)
        org.junit.Assert.assertTrue(snapshot.availableReaders.first().isSelected)
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
