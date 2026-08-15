// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import fi.refineid.android.document.PdfValidationMaterialLimits
import fi.refineid.android.document.Rfc3161Timestamp
import fi.refineid.android.document.TimestampTokenVerifier
import fi.refineid.android.document.VerifiedTimestampToken

internal enum class TimestampAcquisitionFailure {
    AUTHORITY_CLOSED,
    RANDOM_UNAVAILABLE,
}

internal class TimestampAcquisitionException(
    val kind: TimestampAcquisitionFailure,
) : Exception(kind.name)

/** Owned timestamp-authority trust and optional Basic credentials. */
internal class SigningTimestampAuthority private constructor(
    val address: String,
    private val ownedTrustedCertificates: List<ByteArray>,
    private val credentials: SigningNetworkBasicCredentials?,
) : AutoCloseable {
    private var isClosed = false

    val trustedCertificateCount: Int
        get() = ownedTrustedCertificates.size

    val hasCredentials: Boolean
        get() = credentials != null

    fun copyTrustedCertificates(): List<ByteArray> {
        requireOpen()
        return ownedTrustedCertificates.map(ByteArray::copyOf)
    }

    fun credentials(): SigningNetworkBasicCredentials? {
        requireOpen()
        return credentials
    }

    override fun close() {
        if (!isClosed) {
            ownedTrustedCertificates.forEach { certificate -> certificate.fill(CLEARED_BYTE) }
            credentials?.close()
            isClosed = true
        }
    }

    override fun toString(): String =
        "SigningTimestampAuthority(trustedCertificates=$trustedCertificateCount, " +
            "credentials=$hasCredentials, closed=$isClosed)"

    private fun requireOpen() {
        if (isClosed) {
            throw TimestampAcquisitionException(TimestampAcquisitionFailure.AUTHORITY_CLOSED)
        }
    }

    companion object {
        fun copyOf(
            address: String,
            trustedCertificates: List<ByteArray>,
            username: String? = null,
            password: CharArray? = null,
        ): SigningTimestampAuthority {
            if (trustedCertificatesAreInvalid(trustedCertificates) || credentialsAreIncomplete(username, password)) {
                throw IllegalArgumentException("invalid timestamp-authority configuration")
            }
            val credentials =
                if (username == null || password == null) {
                    null
                } else {
                    SigningNetworkBasicCredentials.copyOf(username, password)
                }
            return SigningTimestampAuthority(
                address = address,
                ownedTrustedCertificates = trustedCertificates.map(ByteArray::copyOf),
                credentials = credentials,
            )
        }

        private fun trustedCertificatesAreInvalid(certificates: List<ByteArray>): Boolean =
            certificates.isEmpty() ||
                certificates.size > PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_COUNT ||
                certificates.any { certificate ->
                    certificate.isEmpty() ||
                        certificate.size > PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES
                }

        private fun credentialsAreIncomplete(
            username: String?,
            password: CharArray?,
        ): Boolean = (username == null) != (password == null)

        private const val CLEARED_BYTE: Byte = 0
    }
}

/** Acquires and authenticates one request-bound RFC 3161 SHA-384 token. */
internal class Rfc3161TimestampClient(
    private val transport: SigningNetworkTransport,
    private val random: SigningNetworkSecureRandom = SystemSigningNetworkSecureRandom(),
) {
    fun token(
        digest: ByteArray,
        authority: SigningTimestampAuthority,
    ): VerifiedTimestampToken {
        val ownedDigest = digest.copyOf()
        var nonce: ByteArray? = null
        var request: ByteArray? = null
        var response: ByteArray? = null
        var trustedCertificates: List<ByteArray>? = null
        try {
            val generatedNonce = randomNonce()
            nonce = generatedNonce
            request = Rfc3161Timestamp.request(digest = ownedDigest, nonce = generatedNonce)
            response =
                transport.post(
                    body = request,
                    address = authority.address,
                    contentType = TIMESTAMP_REQUEST_CONTENT_TYPE,
                    credentials = authority.credentials(),
                    maximumResponseBytes = SigningNetworkLimits.MAXIMUM_SHORT_RESPONSE_BYTES,
                    endpoint = SigningNetworkEndpoint.AUTHORITY,
                )
            val unverified =
                Rfc3161Timestamp.token(
                    response = response,
                    digest = ownedDigest,
                    nonce = generatedNonce,
                )
            return unverified.use {
                trustedCertificates = authority.copyTrustedCertificates()
                TimestampTokenVerifier.verify(
                    token = unverified,
                    trustedCertificates = checkNotNull(trustedCertificates),
                )
            }
        } finally {
            ownedDigest.fill(CLEARED_BYTE)
            nonce?.fill(CLEARED_BYTE)
            request?.fill(CLEARED_BYTE)
            response?.fill(CLEARED_BYTE)
            trustedCertificates?.forEach { certificate -> certificate.fill(CLEARED_BYTE) }
        }
    }

    private fun randomNonce(): ByteArray {
        val nonce =
            try {
                random.generate(TIMESTAMP_NONCE_BYTE_COUNT)
            } catch (_: Exception) {
                throw TimestampAcquisitionException(TimestampAcquisitionFailure.RANDOM_UNAVAILABLE)
            }
        if (nonce.size != TIMESTAMP_NONCE_BYTE_COUNT) {
            nonce.fill(CLEARED_BYTE)
            throw TimestampAcquisitionException(TimestampAcquisitionFailure.RANDOM_UNAVAILABLE)
        }
        return nonce
    }

    private companion object {
        const val TIMESTAMP_REQUEST_CONTENT_TYPE = "application/timestamp-query"
        const val TIMESTAMP_NONCE_BYTE_COUNT = 32
        const val CLEARED_BYTE: Byte = 0
    }
}
