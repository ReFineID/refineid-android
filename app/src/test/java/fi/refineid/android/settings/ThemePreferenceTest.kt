// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ThemePreferenceTest {
    @Test
    fun systemTracksPhone() {
        assertFalse(ThemePreference.SYSTEM.resolve(systemDark = false))
        assertTrue(ThemePreference.SYSTEM.resolve(systemDark = true))
    }

    @Test
    fun explicitChoicePinsTheme() {
        assertFalse(ThemePreference.LIGHT.resolve(systemDark = false))
        assertFalse(ThemePreference.LIGHT.resolve(systemDark = true))
        assertTrue(ThemePreference.DARK.resolve(systemDark = false))
        assertTrue(ThemePreference.DARK.resolve(systemDark = true))
    }

    @Test
    fun storedNamesRoundTrip() {
        assertEquals(ThemePreference.SYSTEM, ThemePreference.fromNameOrSystem(null))
        assertEquals(ThemePreference.LIGHT, ThemePreference.fromNameOrSystem("LIGHT"))
        assertEquals(ThemePreference.DARK, ThemePreference.fromNameOrSystem("DARK"))
    }

    @Test
    fun corruptStoredNameFallsBackToSystem() {
        assertEquals(ThemePreference.SYSTEM, ThemePreference.fromNameOrSystem("midnight"))
        assertEquals(ThemePreference.SYSTEM, ThemePreference.fromNameOrSystem(""))
    }
}
