// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.settings

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

@RunWith(AndroidJUnit4::class)
internal class TimestampAuthorityStoreInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun prepareIsolatedStore() {
        clearTestState()
    }

    @After
    fun clearIsolatedStore() {
        clearTestState()
    }

    @Test
    fun orderedConfigurationRoundTripsThroughNonExportableEncryptedStorage() {
        val store = store()
        val initial = store.load()
        try {
            assertEquals(SHIPPED_AUTHORITY_COUNT, initial.size)
            assertEquals(TimestampAuthorityConfiguration.SHIPPED_AUTHORITY_ADDRESS, initial.single().address)
            assertFalse(initial.single().hasCredentials)
        } finally {
            initial.closeAll()
        }

        val password = SYNTHETIC_PASSWORD.copyOf()
        val first =
            TimestampAuthorityConfiguration.copyOf(
                address = FIRST_AUTHORITY_ADDRESS,
                username = SYNTHETIC_USERNAME,
                password = password,
            )
        val second =
            TimestampAuthorityConfiguration.copyOf(
                address = SECOND_AUTHORITY_ADDRESS,
                username = null,
                password = null,
            )
        try {
            store.save(listOf(first, second))
        } finally {
            password[FIRST_CHARACTER_INDEX] = CHANGED_CHARACTER
            first.close()
            second.close()
        }

        val loaded = store.load()
        try {
            assertEquals(EXPECTED_AUTHORITY_COUNT, loaded.size)
            assertEquals(FIRST_AUTHORITY_ADDRESS, loaded.first().address)
            assertEquals(SECOND_AUTHORITY_ADDRESS, loaded.last().address)
            assertEquals(SYNTHETIC_USERNAME, loaded.first().username)
            assertNull(loaded.last().username)
            val loadedPassword = checkNotNull(loaded.first().copyPassword())
            try {
                assertTrue(loadedPassword.contentEquals(SYNTHETIC_PASSWORD))
            } finally {
                loadedPassword.fill(CLEARED_CHARACTER)
            }
            assertNull(loaded.last().copyPassword())
        } finally {
            loaded.closeAll()
        }

        val encryptedPreferences = context.getSharedPreferences(TEST_PASSWORD_PREFERENCES, Context.MODE_PRIVATE)
        assertEquals(EXPECTED_ENCRYPTED_COMPONENT_COUNT, encryptedPreferences.all.size)
        assertTrue(
            encryptedPreferences.all.values.none { value ->
                value.toString().contains(SYNTHETIC_PASSWORD_TEXT)
            },
        )
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
        val key = checkNotNull(keyStore.getKey(TEST_KEY_ALIAS, null))
        assertNull(key.encoded)
    }

    @Test
    fun ciphertextIsRandomizedAndTamperingFailsClosed() {
        val vault = vault()
        val password = SYNTHETIC_PASSWORD.copyOf()
        try {
            vault.write(FIRST_AUTHORITY_ADDRESS, password)
            val firstEncoding = encryptedValues()
            vault.write(FIRST_AUTHORITY_ADDRESS, password)
            val secondEncoding = encryptedValues()
            assertFalse(firstEncoding == secondEncoding)

            val encryptedPreferences =
                context.getSharedPreferences(TEST_PASSWORD_PREFERENCES, Context.MODE_PRIVATE)
            val editor = encryptedPreferences.edit()
            for (key in encryptedPreferences.all.keys) {
                editor.putString(key, MALFORMED_ENCRYPTED_VALUE)
            }
            assertTrue(editor.commit())

            val failure =
                assertThrows(TimestampAuthorityPasswordVaultException::class.java) {
                    vault.read(FIRST_AUTHORITY_ADDRESS)?.fill(CLEARED_CHARACTER)
                }
            assertEquals(TimestampAuthorityPasswordVaultFailure.MALFORMED, failure.kind)
        } finally {
            password.fill(CLEARED_CHARACTER)
        }
    }

    @Test
    fun malformedPreferenceTypeFailsClosed() {
        val vault = vault()
        val password = SYNTHETIC_PASSWORD.copyOf()
        try {
            vault.write(FIRST_AUTHORITY_ADDRESS, password)
        } finally {
            password.fill(CLEARED_CHARACTER)
        }

        val encryptedPreferences =
            context.getSharedPreferences(TEST_PASSWORD_PREFERENCES, Context.MODE_PRIVATE)
        val componentKey = checkNotNull(encryptedPreferences.all.keys.firstOrNull())
        assertTrue(
            encryptedPreferences
                .edit()
                .putBoolean(componentKey, SYNTHETIC_NON_STRING_VALUE)
                .commit(),
        )

        val failure =
            assertThrows(TimestampAuthorityPasswordVaultException::class.java) {
                vault.read(FIRST_AUTHORITY_ADDRESS)?.fill(CLEARED_CHARACTER)
            }
        assertEquals(TimestampAuthorityPasswordVaultFailure.MALFORMED, failure.kind)
    }

    @Test
    fun restoreDefaultsClearsEveryStoredCredential() {
        val store = store()
        val configured =
            TimestampAuthorityConfiguration.copyOf(
                address = FIRST_AUTHORITY_ADDRESS,
                username = SYNTHETIC_USERNAME,
                password = SYNTHETIC_PASSWORD,
            )
        try {
            store.save(listOf(configured))
        } finally {
            configured.close()
        }
        assertFalse(encryptedValues().isEmpty())

        store.restoreDefaults()

        assertTrue(encryptedValues().isEmpty())
        val restored = store.load()
        try {
            assertEquals(TimestampAuthorityConfiguration.SHIPPED_AUTHORITY_ADDRESS, restored.single().address)
            assertFalse(restored.single().hasCredentials)
        } finally {
            restored.closeAll()
        }
    }

    private fun store(): TimestampAuthorityStore =
        TimestampAuthorityStore(
            context = context,
            passwordVault = vault(),
            preferenceName = TEST_PUBLIC_PREFERENCES,
        )

    private fun vault(): AndroidKeystoreTimestampAuthorityPasswordVault =
        AndroidKeystoreTimestampAuthorityPasswordVault(
            context = context,
            preferenceName = TEST_PASSWORD_PREFERENCES,
            keyAlias = TEST_KEY_ALIAS,
        )

    private fun encryptedValues(): Map<String, *> =
        context.getSharedPreferences(TEST_PASSWORD_PREFERENCES, Context.MODE_PRIVATE).all

    private fun clearTestState() {
        assertTrue(
            context
                .getSharedPreferences(TEST_PUBLIC_PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit(),
        )
        assertTrue(
            context
                .getSharedPreferences(TEST_PASSWORD_PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit(),
        )
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
        if (keyStore.containsAlias(TEST_KEY_ALIAS)) {
            keyStore.deleteEntry(TEST_KEY_ALIAS)
        }
    }

    private fun List<TimestampAuthorityConfiguration>.closeAll() {
        forEach(TimestampAuthorityConfiguration::close)
    }

    private companion object {
        const val TEST_PUBLIC_PREFERENCES = "timestamp-authorities-instrumented-test"
        const val TEST_PASSWORD_PREFERENCES = "timestamp-authority-passwords-instrumented-test"
        const val TEST_KEY_ALIAS = "fi.refineid.timestamp-authority-passwords.instrumented-test"
        const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val FIRST_AUTHORITY_ADDRESS = "https://first.timestamp.example/request"
        const val SECOND_AUTHORITY_ADDRESS = "http://second.timestamp.example/request"
        const val SYNTHETIC_USERNAME = "synthetic-account"
        const val SYNTHETIC_PASSWORD_TEXT = "synthetic-password"
        const val MALFORMED_ENCRYPTED_VALUE = "not-base64"
        const val SHIPPED_AUTHORITY_COUNT = 1
        const val EXPECTED_AUTHORITY_COUNT = 2
        const val EXPECTED_ENCRYPTED_COMPONENT_COUNT = 2
        const val FIRST_CHARACTER_INDEX = 0
        const val CHANGED_CHARACTER = 'X'
        const val CLEARED_CHARACTER = '\u0000'
        const val SYNTHETIC_NON_STRING_VALUE = true
        val SYNTHETIC_PASSWORD = SYNTHETIC_PASSWORD_TEXT.toCharArray()
    }
}
