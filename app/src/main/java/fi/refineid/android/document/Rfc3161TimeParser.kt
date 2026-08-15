// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.time.DateTimeException
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset

/** Canonical UTC GeneralizedTime conversion for timestamp claims. */
internal object Rfc3161TimeParser {
    fun parse(encoded: ByteArray): Instant? {
        return try {
            val text =
                encoded
                    .takeIf { bytes -> bytes.all { byte -> byte.toUnsignedInt() in ASCII_RANGE } }
                    ?.toString(Charsets.US_ASCII)
                    ?: return null
            if (!text.endsWith(UTC_SUFFIX)) {
                return null
            }
            val body = text.dropLast(UTC_SUFFIX.length)
            val components = body.split(FRACTION_SEPARATOR, limit = FRACTION_COMPONENT_LIMIT)
            val digits = components.getOrNull(DATE_TIME_COMPONENT_INDEX) ?: return null
            if (digits.length != DATE_TIME_DIGIT_COUNT || !digits.all(Char::isDigit)) {
                return null
            }
            val fraction = components.getOrNull(FRACTION_COMPONENT_INDEX)
            if (!isCanonicalFraction(fraction)) {
                return null
            }
            localDateTime(digits = digits, fraction = fraction).toInstant(ZoneOffset.UTC)
        } catch (_: DateTimeException) {
            null
        } catch (_: NumberFormatException) {
            null
        } finally {
            encoded.fill(ZERO_BYTE)
        }
    }

    private fun isCanonicalFraction(fraction: String?): Boolean =
        fraction == null ||
            (
                fraction.isNotEmpty() &&
                    fraction.length <= MAXIMUM_FRACTION_DIGITS &&
                    fraction.all(Char::isDigit) &&
                    fraction.last() != FRACTION_TRAILING_ZERO
            )

    private fun localDateTime(
        digits: String,
        fraction: String?,
    ): LocalDateTime =
        LocalDateTime.of(
            digits.substring(YEAR_RANGE).toInt(),
            digits.substring(MONTH_RANGE).toInt(),
            digits.substring(DAY_RANGE).toInt(),
            digits.substring(HOUR_RANGE).toInt(),
            digits.substring(MINUTE_RANGE).toInt(),
            digits.substring(SECOND_RANGE).toInt(),
            fraction
                ?.padEnd(MAXIMUM_FRACTION_DIGITS, FRACTION_TRAILING_ZERO)
                ?.toInt()
                ?: NO_NANOSECONDS,
        )

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private const val ASCII_MINIMUM = 0
    private const val ASCII_MAXIMUM = 0x7F
    private const val DATE_TIME_DIGIT_COUNT = 14
    private const val FRACTION_COMPONENT_LIMIT = 2
    private const val DATE_TIME_COMPONENT_INDEX = 0
    private const val FRACTION_COMPONENT_INDEX = 1
    private const val MAXIMUM_FRACTION_DIGITS = 9
    private const val NO_NANOSECONDS = 0
    private const val ZERO_BYTE: Byte = 0
    private const val UTC_SUFFIX = "Z"
    private const val FRACTION_SEPARATOR = "."
    private const val FRACTION_TRAILING_ZERO = '0'
    private val ASCII_RANGE = ASCII_MINIMUM..ASCII_MAXIMUM
    private val YEAR_RANGE = 0 until 4
    private val MONTH_RANGE = 4 until 6
    private val DAY_RANGE = 6 until 8
    private val HOUR_RANGE = 8 until 10
    private val MINUTE_RANGE = 10 until 12
    private val SECOND_RANGE = 12 until 14
}
