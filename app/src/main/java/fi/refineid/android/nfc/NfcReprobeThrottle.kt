// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

import android.os.SystemClock

/**
 * Throttles recognition re-probes of a resting card.
 *
 * The reader stack re-polls a card left in the field after every closed
 * connection. Once the card is recognized, re-probing on each poll only re-runs
 * the public read to the same result, so this collaborator suppresses those
 * repeats within a short interval. A probe still runs once the interval passes,
 * which is enough to notice the card leaving or a different card arriving.
 */
internal class NfcReprobeThrottle(
    private val now: () -> Long = SystemClock::elapsedRealtime,
) {
    @Volatile
    private var lastProbeAtMillis = 0L

    /** Record that a recognition probe ran, starting a new quiet interval. */
    fun onProbe() {
        lastProbeAtMillis = now()
    }

    /**
     * Whether this re-poll should be ignored: [status] is a resting recognition
     * state and the last probe is younger than the minimum interval. A fresh
     * card ([NfcReaderStatus.WAITING_FOR_CARD]) or an open session never rests
     * here, so they are never throttled.
     */
    fun shouldSkip(status: NfcReaderStatus): Boolean {
        val resting =
            when (status) {
                NfcReaderStatus.CARD_RECOGNIZED,
                NfcReaderStatus.WRONG_CAN,
                NfcReaderStatus.TRANSPORT_ERROR,
                NfcReaderStatus.CARD_NOT_SUPPORTED,
                -> true

                else -> false
            }
        return resting && now() - lastProbeAtMillis < MINIMUM_INTERVAL_MILLISECONDS
    }

    private companion object {
        /**
         * Shortest gap between recognition probes of a resting card; below it
         * the re-poll is ignored so the reader does not spin the public read.
         */
        const val MINIMUM_INTERVAL_MILLISECONDS = 2_000L
    }
}
