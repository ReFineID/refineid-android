// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.time.Duration
import java.time.Instant

class OcspResponseTimeTest {
    @Test
    fun acceptsFreshResponseWithoutNextUpdate() {
        response(
            thisUpdate = CURRENT_TIME.minus(FRESH_RESPONSE_AGE),
            nextUpdate = null,
        ).use { response ->
            OcspResponseTime.requireCurrent(response, CURRENT_TIME)
        }
    }

    @Test
    fun rejectsResponseWithoutNextUpdateAfterBound() {
        val failure =
            assertThrows(OcspResponseValidationException::class.java) {
                response(
                    thisUpdate = CURRENT_TIME.minus(MAXIMUM_AGE_WITHOUT_NEXT_UPDATE).minus(EXCESS_AGE),
                    nextUpdate = null,
                ).use { response ->
                    OcspResponseTime.requireCurrent(response, CURRENT_TIME)
                }
            }

        assertEquals(OcspResponseValidationFailure.RESPONSE_EXPIRED, failure.kind)
    }

    @Test
    fun rejectsNextUpdateAtThisUpdate() {
        val thisUpdate = CURRENT_TIME.minus(FRESH_RESPONSE_AGE)
        val failure =
            assertThrows(OcspResponseValidationException::class.java) {
                response(
                    thisUpdate = thisUpdate,
                    nextUpdate = thisUpdate,
                ).use { response ->
                    OcspResponseTime.requireCurrent(response, CURRENT_TIME)
                }
            }

        assertEquals(OcspResponseValidationFailure.RESPONSE_EXPIRED, failure.kind)
    }

    @Test
    fun rejectsThisUpdateBeyondClockSkew() {
        val failure =
            assertThrows(OcspResponseValidationException::class.java) {
                response(
                    thisUpdate = CURRENT_TIME.plus(MAXIMUM_CLOCK_SKEW).plus(EXCESS_AGE),
                    nextUpdate = null,
                ).use { response ->
                    OcspResponseTime.requireCurrent(response, CURRENT_TIME)
                }
            }

        assertEquals(OcspResponseValidationFailure.RESPONSE_FROM_FUTURE, failure.kind)
    }

    private fun response(
        thisUpdate: Instant,
        nextUpdate: Instant?,
    ): ParsedOcspResponseData =
        ParsedOcspResponseData(
            nextUpdate = nextUpdate,
            producedAt = thisUpdate,
            ownedRaw = byteArrayOf(TEST_RESPONSE_MARKER),
            responderId = OcspResponderId.ByKey(ByteArray(SHA1_DIGEST_BYTE_COUNT) { TEST_HASH_FILL }),
            status = OcspCertificateStatus.GOOD,
            thisUpdate = thisUpdate,
        )

    private companion object {
        const val SHA1_DIGEST_BYTE_COUNT = 20
        const val TEST_RESPONSE_MARKER: Byte = 0x31
        const val TEST_HASH_FILL: Byte = 0x5A
        val CURRENT_TIME: Instant = Instant.parse("2026-08-15T12:00:00Z")
        val FRESH_RESPONSE_AGE: Duration = Duration.ofHours(1)
        val MAXIMUM_CLOCK_SKEW: Duration = Duration.ofMinutes(5)
        val MAXIMUM_AGE_WITHOUT_NEXT_UPDATE: Duration = Duration.ofDays(7).plus(MAXIMUM_CLOCK_SKEW)
        val EXCESS_AGE: Duration = Duration.ofSeconds(1)
    }
}
