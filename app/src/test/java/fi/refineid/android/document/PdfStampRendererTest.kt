// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

@Suppress("MagicNumber")
class PdfStampRendererTest {
    @Test
    fun generatesValidVectorPdfStampOperators() {
        val operators = PdfStampRenderer.generateStampOperators(Locale.US)
        assertTrue(operators.startsWith("q\n"))
        assertTrue(operators.contains("0.7765 0.1569 0.1569 RG"))
        assertTrue(operators.contains("0.7765 0.1569 0.1569 rg"))
        assertTrue(operators.contains("1.8 w")) // Outer ring
        assertTrue(operators.contains("0.9 w")) // Border separator
        assertTrue(operators.contains("BT\n")) // Begin text
        assertTrue(operators.contains("ET\n")) // End text
        assertTrue(operators.endsWith("Q\n")) // Pop graphics state
    }

    @Test
    fun formatsMultilingualTextStartingWithUserLocale() {
        val enOperators = PdfStampRenderer.generateStampOperators(Locale.ENGLISH)
        assertTrue(enOperators.contains("(CHECK DOCUMENT) Tj"))

        val fiOperators = PdfStampRenderer.generateStampOperators(Locale.forLanguageTag("fi-FI"))
        assertTrue(fiOperators.contains("(TARKASTA ASIAKIRJAN) Tj"))

        val svOperators = PdfStampRenderer.generateStampOperators(Locale.forLanguageTag("sv-SE"))
        assertTrue(svOperators.contains("(KONTROLLERA DOKUMENTETS) Tj"))
    }

    @Test
    fun reachMatchesRadiusPlusBleed() {
        assertEquals(
            PdfStampRenderer.STAMP_RADIUS + PdfStampRenderer.STAMP_BLEED,
            PdfStampRenderer.STAMP_REACH,
            0.001,
        )
    }
}
