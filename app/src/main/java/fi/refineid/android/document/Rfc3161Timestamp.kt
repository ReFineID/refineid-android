// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import java.time.Instant

internal enum class Rfc3161TimestampFailure {
    REQUEST_MALFORMED,
    RESPONSE_UNUSABLE,
    RESPONSE_MALFORMED,
    REJECTED,
    TOKEN_MISSING,
    IMPRINT_ALGORITHM_MISMATCH,
    IMPRINT_MISMATCH,
    NONCE_MISMATCH,
}

internal class Rfc3161TimestampException(
    val kind: Rfc3161TimestampFailure,
    val rejectedStatus: Long? = null,
) : Exception(kind.name) {
    init {
        require((kind == Rfc3161TimestampFailure.REJECTED) == (rejectedStatus != null)) {
            "a rejected timestamp status belongs only to a rejection"
        }
    }
}

/** Request-bound token claim which has not passed CMS, certificate, or trust verification. */
internal class UnverifiedTimestampToken internal constructor(
    private val ownedEncoding: ByteArray,
    val generatedAt: Instant,
) : AutoCloseable {
    private var isClosed = false

    val encodedLength: Int
        get() = ownedEncoding.size

    fun <T> useEncoding(operation: (ByteArray) -> T): T {
        check(!isClosed) {
            "unverified timestamp token is closed"
        }
        return operation(ownedEncoding)
    }

    fun copyEncoding(): ByteArray = useEncoding(ByteArray::copyOf)

    override fun close() {
        if (!isClosed) {
            ownedEncoding.fill(ZERO_BYTE)
            isClosed = true
        }
    }

    override fun toString(): String =
        "UnverifiedTimestampToken(length=" + encodedLength +
            ", generatedAt=" + generatedAt +
            ", closed=" + isClosed + ")"

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}

/** RFC 3161 SHA-384 request construction and response-to-request binding. */
internal object Rfc3161Timestamp {
    fun request(
        digest: ByteArray,
        nonce: ByteArray,
    ): ByteArray {
        requireRequestInputs(digest = digest, nonce = nonce)
        return DerEncoder.sequence(
            listOf(
                DerEncoder.integer(TIMESTAMP_REQUEST_VERSION),
                DerEncoder.sequence(
                    listOf(
                        sha384AlgorithmIdentifier(),
                        DerEncoder.octetString(digest),
                    ),
                ),
                DerEncoder.unsignedInteger(nonce),
                DerEncoder.booleanTrue(),
            ),
        )
    }

    fun token(
        response: ByteArray,
        digest: ByteArray,
        nonce: ByteArray,
    ): UnverifiedTimestampToken {
        requireRequestInputs(digest = digest, nonce = nonce)
        return Rfc3161TimestampParser.token(
            response = response,
            expectedDigest = digest,
            expectedNonce = nonce,
        )
    }

    private fun requireRequestInputs(
        digest: ByteArray,
        nonce: ByteArray,
    ) {
        if (
            digest.size != SHA384_DIGEST_LENGTH_BYTES ||
            nonce.size !in MINIMUM_NONCE_BYTES..MAXIMUM_NONCE_BYTES
        ) {
            throw Rfc3161TimestampException(Rfc3161TimestampFailure.REQUEST_MALFORMED)
        }
    }

    private fun sha384AlgorithmIdentifier(): ByteArray =
        DerEncoder.sequence(
            listOf(DerEncoder.objectIdentifier(QualifiedCmsOids.SHA384)),
        )

    private const val TIMESTAMP_REQUEST_VERSION = 1
    private const val MINIMUM_NONCE_BYTES = 1
    private const val MAXIMUM_NONCE_BYTES = 64
}

internal object Rfc3161Oids {
    const val TST_INFO = "1.2.840.113549.1.9.16.1.4"
}
