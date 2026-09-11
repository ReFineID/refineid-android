package fi.refineid.android.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Test

class DiagnosticsReportTest {
    @Test
    fun generationCutoverBoundaries() {
        assertEquals(
            "Older (PUK activation code, issued before 13.1.2026)",
            cardGenerationLabel("12.1.2026"),
        )
        assertEquals(
            "Newer (preset activation PIN, issued on/after 13.1.2026)",
            cardGenerationLabel("13.1.2026"),
        )
        assertEquals(
            "Newer (preset activation PIN, issued on/after 13.1.2026)",
            cardGenerationLabel("14.1.2026"),
        )
    }

    @Test
    fun generationMissingOrUnparseable() {
        assertEquals(
            "unknown (no issue date)",
            cardGenerationLabel(null),
        )
        assertEquals(
            "unknown (unparseable issue date)",
            cardGenerationLabel("2026-01-14"),
        )
        assertEquals(
            "unknown (unparseable issue date)",
            cardGenerationLabel("not a date"),
        )
    }
}
