package fi.refineid.android.diagnostics

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The pasted diagnostics report must stay self-describing: every trace
 * line carries a UTC timestamp and the session start carries the app
 * version, so a bug report never needs a round trip for basics.
 */
@RunWith(AndroidJUnit4::class)
class AppTraceFormatInstrumentedTest {
    @Test
    fun traceLinesCarryUtcTimestamps() {
        AppTrace.clearTraceLog()
        try {
            AppTrace.nfcAwaitingCard()

            val lines = AppTrace.getTraceLog()
            assertTrue(
                "expected one trace line, got $lines",
                lines.size == 1,
            )
            assertTrue(
                "trace line lacks a UTC timestamp: ${lines[0]}",
                UTC_TRACE_LINE.matcher(lines[0]).matches(),
            )
        } finally {
            AppTrace.clearTraceLog()
        }
    }

    @Test
    fun sessionStartCarriesAppVersion() {
        AppTrace.clearTraceLog()
        try {
            AppTrace.activityCreated()

            val lines = AppTrace.getTraceLog()
            assertTrue(
                "expected one trace line, got $lines",
                lines.size == 1,
            )
            assertTrue(
                "session start lacks a version: ${lines[0]}",
                lines[0].contains("version="),
            )
        } finally {
            AppTrace.clearTraceLog()
        }
    }

    private companion object {
        val UTC_TRACE_LINE =
            Regex("^\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z nfc:awaiting-card$").toPattern()
    }
}
