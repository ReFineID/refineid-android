// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import java.security.MessageDigest

/** Strict bounded parsing of one untrusted RFC 3161 response envelope. */
internal object Rfc3161TimestampParser {
    fun token(
        response: ByteArray,
        expectedDigest: ByteArray,
        expectedNonce: ByteArray,
    ): UnverifiedTimestampToken {
        if (response.isEmpty() || response.size > MAXIMUM_RESPONSE_BYTES) {
            throw failure(Rfc3161TimestampFailure.RESPONSE_UNUSABLE)
        }
        val encodedToken = encodedToken(response)
        var transferred = false
        try {
            val information = Rfc3161CmsTokenParser.tstInfoContent(encodedToken)
            val binding =
                try {
                    Rfc3161TstInfoParser.binding(information)
                } finally {
                    information.fill(ZERO_BYTE)
                }
            try {
                requireMatchingAlgorithm(binding.algorithm)
                requireMatchingDigest(binding.digest, expectedDigest)
                requireMatchingNonce(binding.nonce, expectedNonce)
                val result =
                    UnverifiedTimestampToken(
                        ownedEncoding = encodedToken,
                        generatedAt = binding.generatedAt,
                    )
                transferred = true
                return result
            } finally {
                binding.algorithm.fill(ZERO_BYTE)
                binding.digest.fill(ZERO_BYTE)
                binding.nonce?.fill(ZERO_BYTE)
            }
        } finally {
            if (!transferred) {
                encodedToken.fill(ZERO_BYTE)
            }
        }
    }

    private fun requireMatchingAlgorithm(algorithm: ByteArray) {
        if (!Rfc3161CmsTokenParser.isSha384(algorithm)) {
            throw failure(Rfc3161TimestampFailure.IMPRINT_ALGORITHM_MISMATCH)
        }
    }

    private fun requireMatchingDigest(
        digest: ByteArray,
        expected: ByteArray,
    ) {
        if (
            digest.size != SHA384_DIGEST_LENGTH_BYTES ||
            !MessageDigest.isEqual(digest, expected)
        ) {
            throw failure(Rfc3161TimestampFailure.IMPRINT_MISMATCH)
        }
    }

    private fun requireMatchingNonce(
        nonce: ByteArray?,
        expected: ByteArray,
    ) {
        val expectedEncoding = DerEncoder.unsignedInteger(expected)
        try {
            if (nonce == null || !MessageDigest.isEqual(nonce, expectedEncoding)) {
                throw failure(Rfc3161TimestampFailure.NONCE_MISMATCH)
            }
        } finally {
            expectedEncoding.fill(ZERO_BYTE)
        }
    }

    private fun encodedToken(response: ByteArray): ByteArray {
        val outer = DerReader(response)
        val envelope = outer.next() ?: throw malformed()
        if (envelope.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
            throw malformed()
        }
        val fields = outer.children(envelope)
        val statusInfo = fields.next() ?: throw malformed()
        if (statusInfo.tag != DerValues.TAG_SEQUENCE) {
            throw malformed()
        }
        val status = status(fields.children(statusInfo))
        val token = fields.next()
        if (!fields.isAtEnd) {
            throw malformed()
        }
        if (status !in GRANTED_STATUSES) {
            throw Rfc3161TimestampException(
                kind = Rfc3161TimestampFailure.REJECTED,
                rejectedStatus = status,
            )
        }
        if (token == null) {
            throw failure(Rfc3161TimestampFailure.TOKEN_MISSING)
        }
        if (token.tag != DerValues.TAG_SEQUENCE) {
            throw malformed()
        }
        return fields.raw(token)
    }

    private fun status(reader: DerReader): Long {
        val status = reader.next() ?: throw malformed()
        val value = Rfc3161DerValidation.nonNegativeLong(reader, status) ?: throw malformed()
        var candidate = reader.next()
        if (candidate?.tag == DerValues.TAG_SEQUENCE) {
            validateFreeText(reader.children(candidate))
            candidate = reader.next()
        }
        if (candidate?.tag == DerValues.TAG_BIT_STRING) {
            validateBitString(reader.content(candidate))
            candidate = reader.next()
        }
        if (candidate != null || !reader.isAtEnd) {
            throw malformed()
        }
        return value
    }

    private fun validateFreeText(reader: DerReader) {
        var count = EMPTY_COLLECTION_SIZE
        while (!reader.isAtEnd) {
            val text = reader.next() ?: throw malformed()
            if (
                text.tag != DerValues.TAG_UTF8_STRING ||
                !Rfc3161TextValidation.isUtf8(reader.content(text))
            ) {
                throw malformed()
            }
            count += COLLECTION_COUNT_STEP
        }
        if (count == EMPTY_COLLECTION_SIZE) {
            throw malformed()
        }
    }

    private fun validateBitString(content: ByteArray) {
        try {
            if (content.isEmpty()) {
                throw malformed()
            }
            val unusedBits = content[FIRST_CONTENT_OFFSET].toUnsignedInt()
            if (unusedBits !in MINIMUM_UNUSED_BITS..MAXIMUM_UNUSED_BITS) {
                throw malformed()
            }
            if (content.size == BIT_STRING_EMPTY_ENCODING_LENGTH) {
                if (unusedBits != MINIMUM_UNUSED_BITS) {
                    throw malformed()
                }
                return
            }
            val unusedMask =
                if (unusedBits == MINIMUM_UNUSED_BITS) {
                    EMPTY_UNUSED_BIT_MASK
                } else {
                    (SINGLE_BIT shl unusedBits) - SINGLE_BIT
                }
            if (content.last().toUnsignedInt() and unusedMask != EMPTY_UNUSED_BIT_MASK) {
                throw malformed()
            }
        } finally {
            content.fill(ZERO_BYTE)
        }
    }

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private fun failure(kind: Rfc3161TimestampFailure): Rfc3161TimestampException = Rfc3161TimestampException(kind)

    private fun malformed(): Rfc3161TimestampException = failure(Rfc3161TimestampFailure.RESPONSE_MALFORMED)

    private const val MAXIMUM_RESPONSE_BYTES = 65_536
    private const val STATUS_GRANTED = 0L
    private const val STATUS_GRANTED_WITH_MODIFICATIONS = 1L
    private const val EMPTY_COLLECTION_SIZE = 0
    private const val COLLECTION_COUNT_STEP = 1
    private const val FIRST_CONTENT_OFFSET = 0
    private const val BIT_STRING_EMPTY_ENCODING_LENGTH = 1
    private const val MINIMUM_UNUSED_BITS = 0
    private const val MAXIMUM_UNUSED_BITS = 7
    private const val EMPTY_UNUSED_BIT_MASK = 0
    private const val SINGLE_BIT = 1
    private const val ZERO_BYTE: Byte = 0
    private val GRANTED_STATUSES = setOf(STATUS_GRANTED, STATUS_GRANTED_WITH_MODIFICATIONS)
}
