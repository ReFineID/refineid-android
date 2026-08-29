// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Locale

class ElectronicSignatureStampTest {
    @Test
    fun finnishPrimaryPlacesFinnishInCenterAndSwedishEnglishOnBorders() {
        val texts = resolveStampTexts(Locale.forLanguageTag("fi-FI"))
        assertEquals(
            listOf("TARKASTA ASIAKIRJAN", "SÄHKÖINEN", "ALLEKIRJOITUS"),
            texts.middleLines,
        )
        assertEquals("KONTROLLERA DOKUMENTETS ELEKTRONISKA SIGNATUR", texts.topBorderText)
        assertEquals("CHECK DOCUMENT ELECTRONIC SIGNATURE", texts.bottomBorderText)
    }

    @Test
    fun swedishPrimaryPlacesSwedishInCenterAndFinnishEnglishOnBorders() {
        val texts = resolveStampTexts(Locale.forLanguageTag("sv-SE"))
        assertEquals(
            listOf("KONTROLLERA DOKUMENTETS", "ELEKTRONISKA", "SIGNATUR"),
            texts.middleLines,
        )
        assertEquals("TARKASTA ASIAKIRJAN SÄHKÖINEN ALLEKIRJOITUS", texts.topBorderText)
        assertEquals("CHECK DOCUMENT ELECTRONIC SIGNATURE", texts.bottomBorderText)
    }

    @Test
    fun englishPrimaryPlacesEnglishInCenterAndFinnishSwedishOnBorders() {
        val texts = resolveStampTexts(Locale.ENGLISH)
        assertEquals(
            listOf("CHECK DOCUMENT", "ELECTRONIC", "SIGNATURE"),
            texts.middleLines,
        )
        assertEquals("TARKASTA ASIAKIRJAN SÄHKÖINEN ALLEKIRJOITUS", texts.topBorderText)
        assertEquals("KONTROLLERA DOKUMENTETS ELEKTRONISKA SIGNATUR", texts.bottomBorderText)
    }

    @Test
    fun otherLanguageDefaultsToEnglishPrimary() {
        val texts = resolveStampTexts(Locale.GERMAN)
        assertEquals(
            listOf("CHECK DOCUMENT", "ELECTRONIC", "SIGNATURE"),
            texts.middleLines,
        )
    }
}
