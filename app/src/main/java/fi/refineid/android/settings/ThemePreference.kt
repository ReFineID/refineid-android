package fi.refineid.android.settings

/**
 * In-app appearance override. SYSTEM tracks the phone's dark mode schedule;
 * LIGHT and DARK pin the app regardless of what the system currently reports.
 */
internal enum class ThemePreference {
    SYSTEM,
    LIGHT,
    DARK,
    ;

    /** Resolve to the concrete dark flag for the given system state. */
    fun resolve(systemDark: Boolean): Boolean =
        when (this) {
            SYSTEM -> systemDark
            LIGHT -> false
            DARK -> true
        }

    companion object {
        /** Parse a stored name, falling back to SYSTEM for missing or corrupt values. */
        fun fromNameOrSystem(name: String?): ThemePreference =
            try {
                if (name == null) SYSTEM else valueOf(name)
            } catch (_: IllegalArgumentException) {
                SYSTEM
            }
    }
}
