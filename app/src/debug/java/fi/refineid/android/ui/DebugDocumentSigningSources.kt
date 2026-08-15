package fi.refineid.android.ui

import android.content.Context
import fi.refineid.android.R
import fi.refineid.android.browser.BundledIssuerCertificates
import fi.refineid.android.network.HttpSigningNetwork
import fi.refineid.android.network.NetworkQualifiedPdfTimestampSource
import fi.refineid.android.network.NetworkQualifiedPdfValidationSource
import fi.refineid.android.network.SigningNetworkValidationDependencies
import fi.refineid.android.network.SigningTimestampAuthority
import fi.refineid.android.trust.PinnedCertificateBundle
import fi.refineid.android.trust.PinnedCertificateResource

/** Debug-only live PAdES-B-LTA sources with explicit pinned offline trust. */
internal class DebugDocumentSigningSources private constructor(
    val timestamp: NetworkQualifiedPdfTimestampSource,
    val validation: NetworkQualifiedPdfValidationSource,
) : AutoCloseable {
    private var isClosed = false

    override fun close() {
        if (!isClosed) {
            timestamp.close()
            validation.close()
            isClosed = true
        }
    }

    companion object {
        fun create(context: Context): DebugDocumentSigningSources {
            val timestampTrust =
                PinnedCertificateBundle
                    .load(
                        context = context,
                        resources = TIMESTAMP_TRUST_RESOURCES,
                    ).single()
                    .encoded
            val signerTrust =
                BundledIssuerCertificates
                    .load(context)
                    .map { certificate -> certificate.encoded }
            var authority: SigningTimestampAuthority? = null
            var timestampSource: NetworkQualifiedPdfTimestampSource? = null
            try {
                authority =
                    SigningTimestampAuthority.copyOf(
                        address = DEFAULT_TIMESTAMP_AUTHORITY,
                        trustedCertificates = listOf(timestampTrust),
                    )
                val transport = HttpSigningNetwork()
                timestampSource =
                    NetworkQualifiedPdfTimestampSource.live(
                        transport = transport,
                        ownedAuthorities = listOf(checkNotNull(authority)),
                    )
                authority = null
                val validationSource =
                    NetworkQualifiedPdfValidationSource.copyOf(
                        dependencies = SigningNetworkValidationDependencies.create(transport),
                        signerTrustCertificates = signerTrust,
                        additionalCandidates = signerTrust,
                    )
                return DebugDocumentSigningSources(
                    timestamp = checkNotNull(timestampSource),
                    validation = validationSource,
                ).also {
                    timestampSource = null
                }
            } finally {
                authority?.close()
                timestampSource?.close()
                timestampTrust.fill(CLEARED_BYTE)
                signerTrust.clearBytes()
            }
        }

        private fun List<ByteArray>.clearBytes() {
            forEach { value -> value.fill(CLEARED_BYTE) }
        }

        private const val DEFAULT_TIMESTAMP_AUTHORITY =
            "https://timestamp.sectigo.com/qualified"
        private const val TIMESTAMP_TRUST_SHA256 =
            "F871F8976B4068D700D5F281084B4A29EAF4B8F35743330BA062FAB46F58C2ED"
        private const val CLEARED_BYTE: Byte = 0
        private val TIMESTAMP_TRUST_RESOURCES =
            listOf(
                PinnedCertificateResource(
                    id = R.raw.sectigo_qualified_timestamping_root_r45,
                    sha256 = TIMESTAMP_TRUST_SHA256,
                ),
            )
    }
}
