// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import fi.refineid.android.document.PdfValidationMaterialLimits
import fi.refineid.android.document.ValidationMaterialGetResource
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class SigningNetworkAdaptersTest {
    @Test
    fun mapsCollectorResourcesToTheirExactBoundedPublicExchanges() {
        val transport = RecordingTransport()
        val dependencies =
            SigningNetworkValidationDependencies.create(
                transport = transport,
                clock = Clock.fixed(SYNTHETIC_INSTANT, ZoneOffset.UTC),
                random =
                    SigningNetworkSecureRandom { byteCount ->
                        ByteArray(byteCount) { SYNTHETIC_RANDOM_BYTE }
                    },
            )

        assertArrayEquals(
            SYNTHETIC_RESPONSE,
            dependencies.get.fetch(CERTIFICATE_ADDRESS, ValidationMaterialGetResource.CERTIFICATE),
        )
        assertArrayEquals(
            SYNTHETIC_RESPONSE,
            dependencies.get.fetch(REVOCATION_LIST_ADDRESS, ValidationMaterialGetResource.REVOCATION_LIST),
        )
        assertArrayEquals(
            SYNTHETIC_RESPONSE,
            dependencies.post.send(SYNTHETIC_REQUEST, OCSP_ADDRESS, OCSP_REQUEST_CONTENT_TYPE),
        )

        assertEquals(
            RecordedExchange.get(
                address = CERTIFICATE_ADDRESS,
                maximumResponseBytes = PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES,
            ),
            transport.exchanges[FIRST_EXCHANGE_INDEX],
        )
        assertEquals(
            RecordedExchange.get(
                address = REVOCATION_LIST_ADDRESS,
                maximumResponseBytes = PdfValidationMaterialLimits.MAXIMUM_REVOCATION_LIST_BYTES,
            ),
            transport.exchanges[SECOND_EXCHANGE_INDEX],
        )
        val post = transport.exchanges[THIRD_EXCHANGE_INDEX]
        assertEquals(SigningNetworkMethod.POST, post.method)
        assertEquals(OCSP_ADDRESS, post.address)
        assertEquals(SigningNetworkLimits.MAXIMUM_SHORT_RESPONSE_BYTES, post.maximumResponseBytes)
        assertEquals(OCSP_REQUEST_CONTENT_TYPE, post.contentType)
        assertEquals(SigningNetworkEndpoint.CERTIFICATE_MATERIAL, post.endpoint)
        assertFalse(post.carriesCredentials)
        assertArrayEquals(SYNTHETIC_REQUEST, post.body)
        assertEquals(SYNTHETIC_INSTANT, dependencies.now())
        assertArrayEquals(
            ByteArray(SYNTHETIC_RANDOM_BYTE_COUNT) { SYNTHETIC_RANDOM_BYTE },
            dependencies.random.generate(SYNTHETIC_RANDOM_BYTE_COUNT),
        )
    }

    @Test
    fun adapterAndTransportResultsAreOwnedCopies() {
        val transport = RecordingTransport()
        val dependencies = SigningNetworkValidationDependencies.create(transport)
        val first = dependencies.get.fetch(CERTIFICATE_ADDRESS, ValidationMaterialGetResource.CERTIFICATE)
        first[FIRST_BYTE_INDEX] = CHANGED_BYTE

        val second = dependencies.get.fetch(CERTIFICATE_ADDRESS, ValidationMaterialGetResource.CERTIFICATE)

        assertArrayEquals(SYNTHETIC_RESPONSE, second)
        assertArrayEquals(SYNTHETIC_RESPONSE, transport.response)
        assertFalse(transport.toString().contains(SYNTHETIC_RESPONSE.decodeToString()))
    }

    private class RecordingTransport : SigningNetworkTransport {
        val response = SYNTHETIC_RESPONSE.copyOf()
        val exchanges = mutableListOf<RecordedExchange>()

        override fun get(
            address: String,
            maximumResponseBytes: Int,
            endpoint: SigningNetworkEndpoint,
        ): ByteArray {
            exchanges +=
                RecordedExchange(
                    method = SigningNetworkMethod.GET,
                    address = address,
                    maximumResponseBytes = maximumResponseBytes,
                    contentType = null,
                    endpoint = endpoint,
                    carriesCredentials = false,
                    body = null,
                )
            return response.copyOf()
        }

        override fun post(
            body: ByteArray,
            address: String,
            contentType: String,
            credentials: SigningNetworkBasicCredentials?,
            maximumResponseBytes: Int,
            endpoint: SigningNetworkEndpoint,
        ): ByteArray {
            exchanges +=
                RecordedExchange(
                    method = SigningNetworkMethod.POST,
                    address = address,
                    maximumResponseBytes = maximumResponseBytes,
                    contentType = contentType,
                    endpoint = endpoint,
                    carriesCredentials = credentials != null,
                    body = body.copyOf(),
                )
            return response.copyOf()
        }

        override fun toString(): String = "RecordingTransport(exchanges=${exchanges.size}, bodies=[redacted])"
    }

    private data class RecordedExchange(
        val method: SigningNetworkMethod,
        val address: String,
        val maximumResponseBytes: Int,
        val contentType: String?,
        val endpoint: SigningNetworkEndpoint,
        val carriesCredentials: Boolean,
        val body: ByteArray?,
    ) {
        override fun equals(other: Any?): Boolean =
            other is RecordedExchange &&
                method == other.method &&
                address == other.address &&
                maximumResponseBytes == other.maximumResponseBytes &&
                contentType == other.contentType &&
                endpoint == other.endpoint &&
                carriesCredentials == other.carriesCredentials &&
                body.contentEqualsNullable(other.body)

        override fun hashCode(): Int =
            listOf(
                method,
                address,
                maximumResponseBytes,
                contentType,
                endpoint,
                carriesCredentials,
                body?.contentHashCode(),
            ).hashCode()

        companion object {
            fun get(
                address: String,
                maximumResponseBytes: Int,
            ): RecordedExchange =
                RecordedExchange(
                    method = SigningNetworkMethod.GET,
                    address = address,
                    maximumResponseBytes = maximumResponseBytes,
                    contentType = null,
                    endpoint = SigningNetworkEndpoint.CERTIFICATE_MATERIAL,
                    carriesCredentials = false,
                    body = null,
                )

            private fun ByteArray?.contentEqualsNullable(other: ByteArray?): Boolean =
                if (this == null || other == null) {
                    this == null && other == null
                } else {
                    contentEquals(other)
                }
        }
    }

    private companion object {
        const val CERTIFICATE_ADDRESS = "https://issuer.example/certificate"
        const val REVOCATION_LIST_ADDRESS = "http://issuer.example/list"
        const val OCSP_ADDRESS = "https://ocsp.example/status"
        const val OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request"
        const val FIRST_EXCHANGE_INDEX = 0
        const val SECOND_EXCHANGE_INDEX = 1
        const val THIRD_EXCHANGE_INDEX = 2
        const val FIRST_BYTE_INDEX = 0
        const val SYNTHETIC_RANDOM_BYTE_COUNT = 7
        const val SYNTHETIC_RANDOM_BYTE: Byte = 0x5A
        const val CHANGED_BYTE: Byte = 0x7F
        val SYNTHETIC_INSTANT: Instant = Instant.parse("2026-08-16T12:00:00Z")
        val SYNTHETIC_REQUEST = "synthetic OCSP request".encodeToByteArray()
        val SYNTHETIC_RESPONSE = "synthetic public response".encodeToByteArray()
    }
}
