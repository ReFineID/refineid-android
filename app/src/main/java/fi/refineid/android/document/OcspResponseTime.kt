// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.time.DateTimeException
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset

/** Strict UTC GeneralizedTime parsing and OCSP freshness policy. */
internal object OcspResponseTime {
    fun parse(
        reader: DerReader,
        element: DerReader.Element,
    ): Instant {
        if (element.tag != DerValues.TAG_GENERALIZED_TIME) {
            throw malformed()
        }
        val content = reader.content(element)
        return try {
            if (!isUtcGeneralizedTime(content)) {
                throw malformed()
            }
            try {
                LocalDateTime
                    .of(
                        decimal(content, YEAR_START, YEAR_END),
                        decimal(content, MONTH_START, MONTH_END),
                        decimal(content, DAY_START, DAY_END),
                        decimal(content, HOUR_START, HOUR_END),
                        decimal(content, MINUTE_START, MINUTE_END),
                        decimal(content, SECOND_START, SECOND_END),
                    ).toInstant(ZoneOffset.UTC)
            } catch (_: DateTimeException) {
                throw malformed()
            }
        } finally {
            content.fill(ZERO_BYTE)
        }
    }

    fun requireCurrent(
        response: ParsedOcspResponseData,
        currentTime: Instant,
    ) {
        val latestPermitted = currentTime.plusSeconds(MAXIMUM_CLOCK_SKEW_SECONDS)
        if (response.producedAt > latestPermitted || response.thisUpdate > latestPermitted) {
            throw failure(OcspResponseValidationFailure.RESPONSE_FROM_FUTURE)
        }
        if (response.thisUpdate > response.producedAt.plusSeconds(MAXIMUM_CLOCK_SKEW_SECONDS)) {
            throw failure(OcspResponseValidationFailure.RESPONSE_FROM_FUTURE)
        }
        val nextUpdate = response.nextUpdate
        if (nextUpdate != null) {
            val earliestPermitted = currentTime.minusSeconds(MAXIMUM_CLOCK_SKEW_SECONDS)
            if (nextUpdate <= response.thisUpdate || nextUpdate <= earliestPermitted) {
                throw failure(OcspResponseValidationFailure.RESPONSE_EXPIRED)
            }
        } else {
            val maximumAge = MAXIMUM_AGE_WITHOUT_NEXT_UPDATE_SECONDS + MAXIMUM_CLOCK_SKEW_SECONDS
            if (currentTime.epochSecond - response.thisUpdate.epochSecond > maximumAge) {
                throw failure(OcspResponseValidationFailure.RESPONSE_EXPIRED)
            }
        }
    }

    private fun isUtcGeneralizedTime(content: ByteArray): Boolean =
        content.size == GENERALIZED_TIME_BYTE_COUNT &&
            content[UTC_SUFFIX_OFFSET] == UTC_SUFFIX &&
            (YEAR_START until UTC_SUFFIX_OFFSET).all { index ->
                content[index].toUnsignedInt() in ASCII_DIGIT_RANGE
            }

    private fun decimal(
        content: ByteArray,
        start: Int,
        end: Int,
    ): Int {
        var value = INITIAL_DECIMAL_VALUE
        for (index in start until end) {
            value = value * DECIMAL_RADIX + content[index].toUnsignedInt() - ASCII_ZERO
        }
        return value
    }

    private fun malformed(): OcspResponseValidationException = failure(OcspResponseValidationFailure.MALFORMED)

    private fun failure(kind: OcspResponseValidationFailure): OcspResponseValidationException =
        OcspResponseValidationException(kind)

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private const val GENERALIZED_TIME_BYTE_COUNT = 15
    private const val YEAR_START = 0
    private const val YEAR_END = 4
    private const val MONTH_START = 4
    private const val MONTH_END = 6
    private const val DAY_START = 6
    private const val DAY_END = 8
    private const val HOUR_START = 8
    private const val HOUR_END = 10
    private const val MINUTE_START = 10
    private const val MINUTE_END = 12
    private const val SECOND_START = 12
    private const val SECOND_END = 14
    private const val UTC_SUFFIX_OFFSET = 14
    private const val UTC_SUFFIX: Byte = 0x5A
    private const val ASCII_ZERO = 0x30
    private const val ASCII_NINE = 0x39
    private const val DECIMAL_RADIX = 10
    private const val INITIAL_DECIMAL_VALUE = 0
    private const val MAXIMUM_CLOCK_SKEW_SECONDS = 300L
    private const val MAXIMUM_AGE_WITHOUT_NEXT_UPDATE_SECONDS = 604_800L
    private const val ZERO_BYTE: Byte = 0
    private val ASCII_DIGIT_RANGE = ASCII_ZERO..ASCII_NINE
}
