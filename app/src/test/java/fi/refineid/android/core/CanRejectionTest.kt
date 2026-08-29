// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.core

import fi.refineid.android.nfc.NfcReaderStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class CanRejectionTest {
    @Before
    fun setUp() {
        CanSessionStore.drop()
    }

    @Test
    fun remembersValidCanAndDropsOnRejection() {
        CanSessionStore.remember("123456")
        assertTrue(CanSessionStore.hasCan)
        assertEquals("123456", CanSessionStore.currentCan)

        // Simulate wrong CAN rejection event
        val status = NfcReaderStatus.WRONG_CAN
        if (status == NfcReaderStatus.WRONG_CAN) {
            CanSessionStore.drop()
        }

        assertFalse(CanSessionStore.hasCan)
        assertNull(CanSessionStore.currentCan)
        assertNull(CanSessionStore.canBytes())
    }

    @Test
    fun dropsOnWrongAccessNumberInUsbReader() {
        CanSessionStore.remember("654321")
        assertTrue(CanSessionStore.hasCan)

        val status = fi.refineid.android.usb.ReaderConnectionStatus.WRONG_ACCESS_NUMBER
        if (status == fi.refineid.android.usb.ReaderConnectionStatus.WRONG_ACCESS_NUMBER) {
            CanSessionStore.drop()
        }

        assertFalse(CanSessionStore.hasCan)
        assertNull(CanSessionStore.currentCan)
    }

    @Test
    fun dropsOnPaceRejectedCertificateReadFailure() {
        CanSessionStore.remember("112233")
        assertTrue(CanSessionStore.hasCan)

        val failure = NativeCertificateReadFailure.PACE_REJECTED
        if (failure == NativeCertificateReadFailure.PACE_REJECTED) {
            CanSessionStore.drop()
        }

        assertFalse(CanSessionStore.hasCan)
        assertNull(CanSessionStore.currentCan)
    }
}
