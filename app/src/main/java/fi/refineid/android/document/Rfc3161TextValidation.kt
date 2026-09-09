// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/** Bounded text checks used only for timestamp status and GeneralName fields. */
internal object Rfc3161TextValidation {
    fun isUtf8(content: ByteArray): Boolean =
        try {
            Charsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(content))
            true
        } catch (_: CharacterCodingException) {
            false
        } finally {
            content.fill(ZERO_BYTE)
        }

    fun isMailbox(content: ByteArray): Boolean {
        return try {
            if (
                content.isEmpty() ||
                content.any { byte -> byte.toUnsignedInt() !in PRINTABLE_ASCII_RANGE }
            ) {
                return false
            }
            val text = content.toString(Charsets.US_ASCII)
            val separator = text.indexOf(MAILBOX_SEPARATOR)
            separator > FIRST_TEXT_INDEX &&
                separator < text.lastIndex &&
                text.indexOf(MAILBOX_SEPARATOR, separator + TEXT_INDEX_STEP) == MISSING_INDEX
        } finally {
            content.fill(ZERO_BYTE)
        }
    }

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private const val PRINTABLE_ASCII_MINIMUM = 0x21
    private const val PRINTABLE_ASCII_MAXIMUM = 0x7E
    private const val FIRST_TEXT_INDEX = 0
    private const val TEXT_INDEX_STEP = 1
    private const val MISSING_INDEX = -1
    private const val ZERO_BYTE: Byte = 0
    private const val MAILBOX_SEPARATOR = '@'
    private val PRINTABLE_ASCII_RANGE = PRINTABLE_ASCII_MINIMUM..PRINTABLE_ASCII_MAXIMUM
}
