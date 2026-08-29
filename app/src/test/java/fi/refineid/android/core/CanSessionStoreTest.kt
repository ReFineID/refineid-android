// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class CanSessionStoreTest {
    @Before
    fun setUp() {
        CanSessionStore.drop()
    }

    @Test
    fun initiallyEmpty() {
        assertFalse(CanSessionStore.hasCan)
        assertNull(CanSessionStore.currentCan)
        assertNull(CanSessionStore.canBytes())
    }

    @Test
    fun remembersValidSixDigitCan() {
        CanSessionStore.remember("123456")
        assertTrue(CanSessionStore.hasCan)
        assertEquals("123456", CanSessionStore.currentCan)
        val bytes = CanSessionStore.canBytes()
        assertArrayEquals("123456".toByteArray(Charsets.US_ASCII), bytes)
    }

    @Test
    fun ignoresIncompleteOrInvalidCan() {
        CanSessionStore.remember("12345")
        assertFalse(CanSessionStore.hasCan)
        assertNull(CanSessionStore.currentCan)

        CanSessionStore.remember("1234567")
        assertFalse(CanSessionStore.hasCan)

        CanSessionStore.remember("12345A")
        assertFalse(CanSessionStore.hasCan)
    }

    @Test
    fun remembersFromCanSubmission() {
        val submission = CanSubmission.from("654321")
        CanSessionStore.remember(submission)
        assertTrue(CanSessionStore.hasCan)
        assertEquals("654321", CanSessionStore.currentCan)
        submission.close()
    }

    @Test
    fun dropClearsRememberedCan() {
        CanSessionStore.remember("123456")
        assertTrue(CanSessionStore.hasCan)
        CanSessionStore.drop()
        assertFalse(CanSessionStore.hasCan)
        assertNull(CanSessionStore.currentCan)
        assertNull(CanSessionStore.canBytes())
    }
}
