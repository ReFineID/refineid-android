package fi.refineid.android.settings

import android.content.Context
import androidx.core.content.edit

/** Persists the appearance override in app-private preferences. */
internal class ThemeStore(
    context: Context,
    private val preferenceName: String = DEFAULT_PREFERENCE_NAME,
) {
    private val preferences =
        context.applicationContext.getSharedPreferences(preferenceName, Context.MODE_PRIVATE)

    @Synchronized
    fun read(): ThemePreference = ThemePreference.fromNameOrSystem(preferences.getString(ENTRY_NAME, null))

    @Synchronized
    fun write(preference: ThemePreference) {
        preferences.edit { putString(ENTRY_NAME, preference.name) }
    }

    private companion object {
        const val DEFAULT_PREFERENCE_NAME = "appearance"
        const val ENTRY_NAME = "theme"
    }
}
