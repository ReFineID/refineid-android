// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.trust

import android.content.Context
import androidx.annotation.RawRes
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

internal data class PinnedCertificateResource(
    @param:RawRes val id: Int,
    val sha256: String,
)

/** Loads public certificates only when their exact resource fingerprints match. */
internal object PinnedCertificateBundle {
    fun load(
        context: Context,
        resources: List<PinnedCertificateResource>,
    ): List<X509Certificate> =
        resources.map { resource ->
            val certificate =
                context.resources.openRawResource(resource.id).use { input ->
                    CertificateFactory
                        .getInstance(X509_CERTIFICATE_TYPE)
                        .generateCertificate(input) as X509Certificate
                }
            check(certificate.sha256Fingerprint() == resource.sha256) {
                "bundled certificate fingerprint mismatch"
            }
            certificate
        }

    private fun X509Certificate.sha256Fingerprint(): String {
        val digest =
            MessageDigest
                .getInstance(SHA256_DIGEST_NAME)
                .digest(encoded)
        return try {
            digest.joinToString(separator = "") { byte ->
                byte
                    .toUByte()
                    .toInt()
                    .toString(HEX_RADIX)
                    .padStart(HEX_BYTE_WIDTH, HEX_ZERO_CHARACTER)
                    .uppercase(Locale.ROOT)
            }
        } finally {
            digest.fill(CLEARED_BYTE)
        }
    }

    private const val X509_CERTIFICATE_TYPE = "X.509"
    private const val SHA256_DIGEST_NAME = "SHA-256"
    private const val HEX_RADIX = 16
    private const val HEX_BYTE_WIDTH = 2
    private const val HEX_ZERO_CHARACTER = '0'
    private const val CLEARED_BYTE: Byte = 0
}
