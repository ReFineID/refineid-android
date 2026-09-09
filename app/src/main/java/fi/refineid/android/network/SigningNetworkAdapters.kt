// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import fi.refineid.android.document.PdfValidationMaterialLimits
import fi.refineid.android.document.ValidationMaterialCollectorDependencies
import fi.refineid.android.document.ValidationMaterialGetResource
import fi.refineid.android.document.ValidationMaterialGetter
import fi.refineid.android.document.ValidationMaterialPoster
import fi.refineid.android.document.ValidationSecureRandom
import java.security.SecureRandom
import java.time.Clock

internal fun interface SigningNetworkSecureRandom {
    /** Returns a fresh owned buffer with exactly the requested byte count. */
    fun generate(byteCount: Int): ByteArray
}

internal class SystemSigningNetworkSecureRandom(
    private val secureRandom: SecureRandom = SecureRandom(),
) : SigningNetworkSecureRandom {
    override fun generate(byteCount: Int): ByteArray {
        if (byteCount !in MINIMUM_RANDOM_BYTE_COUNT..MAXIMUM_RANDOM_BYTE_COUNT) {
            throw IllegalArgumentException("signing-network random request is outside its bound")
        }
        return ByteArray(byteCount).also(secureRandom::nextBytes)
    }

    private companion object {
        const val MINIMUM_RANDOM_BYTE_COUNT = 1
        const val MAXIMUM_RANDOM_BYTE_COUNT = 64
    }
}

/** Live, synchronous dependencies for the authenticated validation-material collector. */
internal object SigningNetworkValidationDependencies {
    fun create(
        transport: SigningNetworkTransport,
        clock: Clock = Clock.systemUTC(),
        random: SigningNetworkSecureRandom = SystemSigningNetworkSecureRandom(),
    ): ValidationMaterialCollectorDependencies =
        ValidationMaterialCollectorDependencies(
            get =
                ValidationMaterialGetter { address, resource ->
                    transport.get(
                        address = address,
                        maximumResponseBytes = maximumBytes(resource),
                        endpoint = SigningNetworkEndpoint.CERTIFICATE_MATERIAL,
                    )
                },
            post =
                ValidationMaterialPoster { request, address, contentType ->
                    transport.post(
                        body = request,
                        address = address,
                        contentType = contentType,
                        credentials = null,
                        maximumResponseBytes = SigningNetworkLimits.MAXIMUM_SHORT_RESPONSE_BYTES,
                        endpoint = SigningNetworkEndpoint.CERTIFICATE_MATERIAL,
                    )
                },
            now = clock::instant,
            random = ValidationSecureRandom(random::generate),
        )

    private fun maximumBytes(resource: ValidationMaterialGetResource): Int =
        when (resource) {
            ValidationMaterialGetResource.CERTIFICATE -> {
                PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES
            }

            ValidationMaterialGetResource.REVOCATION_LIST -> {
                PdfValidationMaterialLimits.MAXIMUM_REVOCATION_LIST_BYTES
            }
        }
}
