package fi.refineid.android.browser

import android.content.Context
import androidx.annotation.RawRes
import fi.refineid.android.R
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

/** Loads only fingerprint-pinned public FINEID intermediate certificates. */
internal object BundledIssuerCertificates {
    fun load(context: Context): List<X509Certificate> =
        RESOURCES.map { resource ->
            val certificate =
                context.resources.openRawResource(resource.id).use { input ->
                    CertificateFactory
                        .getInstance(X509_CERTIFICATE_TYPE)
                        .generateCertificate(input) as X509Certificate
                }
            check(certificate.sha256Fingerprint() == resource.sha256) {
                "bundled issuer certificate fingerprint mismatch"
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
            digest.fill(ZERO_BYTE)
        }
    }

    private data class PinnedResource(
        @param:RawRes val id: Int,
        val sha256: String,
    )

    private const val X509_CERTIFICATE_TYPE = "X.509"
    private const val SHA256_DIGEST_NAME = "SHA-256"
    private const val HEX_RADIX = 16
    private const val HEX_BYTE_WIDTH = 2
    private const val HEX_ZERO_CHARACTER = '0'
    private const val ZERO_BYTE: Byte = 0
    private val RESOURCES =
        listOf(
            PinnedResource(
                R.raw.fineid_intermediate_00_citizen_g3,
                "39A835B14B6B6313F778371C79CB434DD518C8FD325B749D9BE669DFF20384E8",
            ),
            PinnedResource(
                R.raw.fineid_intermediate_01_citizen_g4e,
                "AAD1BEAC4696102A88BF9D518D64F8B014F78F9B152579C959998313197924D7",
            ),
            PinnedResource(
                R.raw.fineid_intermediate_02_citizen_g4r,
                "2176C05E69EE24946A140D13F9EFA222B3F1E768E1E2A67B313969CC03B82064",
            ),
            PinnedResource(
                R.raw.fineid_intermediate_03_organisation_g4r,
                "DFC3E965176F883A9CF0F68CEAEEAB663EDFD8E79DE3294373C28A856984006F",
            ),
        )
}
