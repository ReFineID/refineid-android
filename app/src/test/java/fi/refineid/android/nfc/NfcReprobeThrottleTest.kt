// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NfcReprobeThrottleTest {
    private var clock = 0L
    private val throttle = NfcReprobeThrottle { clock }

    @Test
    fun aRestingRecognizedCardIsSkippedWithinTheInterval() {
        clock = PROBE_MS
        throttle.onProbe()
        clock = WITHIN_INTERVAL_MS
        assertTrue(throttle.shouldSkip(NfcReaderStatus.CARD_RECOGNIZED))
    }

    @Test
    fun theCardIsReprobedOnceTheIntervalPasses() {
        clock = PROBE_MS
        throttle.onProbe()
        clock = BEYOND_INTERVAL_MS
        assertFalse(throttle.shouldSkip(NfcReaderStatus.CARD_RECOGNIZED))
    }

    @Test
    fun onProbeStartsAFreshInterval() {
        clock = PROBE_MS
        throttle.onProbe()
        clock = WITHIN_INTERVAL_MS
        assertTrue(throttle.shouldSkip(NfcReaderStatus.CARD_RECOGNIZED))
        // A fresh probe resets the window, so a moment later still throttles.
        throttle.onProbe()
        clock = SECOND_WITHIN_MS
        assertTrue(throttle.shouldSkip(NfcReaderStatus.CARD_RECOGNIZED))
    }

    @Test
    fun aFreshCardOrOpenSessionIsNeverThrottled() {
        clock = PROBE_MS
        throttle.onProbe()
        clock = WITHIN_INTERVAL_MS
        assertFalse(throttle.shouldSkip(NfcReaderStatus.WAITING_FOR_CARD))
        assertFalse(throttle.shouldSkip(NfcReaderStatus.CARD_READY))
    }

    @Test
    fun everyRecognitionStateThrottlesWhileFresh() {
        clock = PROBE_MS
        throttle.onProbe()
        clock = WITHIN_INTERVAL_MS
        for (status in RESTING_STATES) {
            assertTrue("expected $status to be throttled", throttle.shouldSkip(status))
        }
    }

    private companion object {
        const val INTERVAL_MS = 2_000L
        const val PROBE_MS = 1_000L

        // Elapsed = INTERVAL_MS / 2, still under the throttle interval.
        const val WITHIN_INTERVAL_MS = PROBE_MS + INTERVAL_MS / 2

        // Elapsed = INTERVAL_MS + 1, just past the interval.
        const val BEYOND_INTERVAL_MS = PROBE_MS + INTERVAL_MS + 1

        // Elapsed from the reset at WITHIN_INTERVAL_MS = INTERVAL_MS / 2.
        const val SECOND_WITHIN_MS = WITHIN_INTERVAL_MS + INTERVAL_MS / 2

        val RESTING_STATES =
            listOf(
                NfcReaderStatus.CARD_RECOGNIZED,
                NfcReaderStatus.WRONG_CAN,
                NfcReaderStatus.TRANSPORT_ERROR,
                NfcReaderStatus.CARD_NOT_SUPPORTED,
            )
    }
}
