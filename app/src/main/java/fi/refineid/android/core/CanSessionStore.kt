// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.core

/**
 * In-memory retention of the Card Access Number (CAN) for the lifetime of
 * the running application process. CAN is non-secret card metadata (printed
 * on the front of the identity card) needed to establish PACE.
 *
 * If the card rejects the CAN during PACE authentication (WRONG_CAN),
 * the stored CAN is immediately dropped and cleared.
 */
internal object CanSessionStore {
    @Volatile
    private var rememberedCan: String? = null

    val currentCan: String?
        get() = rememberedCan

    val hasCan: Boolean
        get() = !rememberedCan.isNullOrBlank()

    fun remember(canText: CharSequence) {
        if (CanSubmission.isComplete(canText)) {
            rememberedCan = canText.toString()
        }
    }

    fun remember(submission: CanSubmission) {
        submission.peekDigits()?.let { remember(it) }
    }

    fun canBytes(): ByteArray? {
        val digits = rememberedCan ?: return null
        return CanSubmission.from(digits).transfer()
    }

    fun drop() {
        rememberedCan = null
    }
}
