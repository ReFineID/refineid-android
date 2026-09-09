package fi.refineid.android.ui

import android.content.Context
import fi.refineid.android.browser.BundledIssuerCertificates
import fi.refineid.android.network.HttpSigningNetwork
import fi.refineid.android.network.NetworkQualifiedPdfTimestampSource
import fi.refineid.android.network.NetworkQualifiedPdfValidationSource
import fi.refineid.android.network.SigningNetworkValidationDependencies
import fi.refineid.android.network.SigningTimestampAuthority
import fi.refineid.android.settings.TimestampAuthorityConfiguration

/** Debug-only live PAdES-B-LTA sources with holder-configured timestamp trust. */
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
        /** Takes ownership of [transferredConfigurations]; call only from a worker thread. */
        fun create(
            context: Context,
            transferredConfigurations: List<TimestampAuthorityConfiguration>,
        ): DebugDocumentSigningSources {
            val authorities = mutableListOf<SigningTimestampAuthority>()
            var signerTrust: List<ByteArray> = emptyList()
            var timestampSource: NetworkQualifiedPdfTimestampSource? = null
            try {
                signerTrust =
                    BundledIssuerCertificates
                        .load(context)
                        .map { certificate -> certificate.encoded }
                transferredConfigurations.mapTo(authorities) { configuration ->
                    configuration.copySigningAuthority()
                }
                val transport = HttpSigningNetwork()
                timestampSource =
                    NetworkQualifiedPdfTimestampSource.live(
                        transport = transport,
                        ownedAuthorities = authorities.toList(),
                    )
                authorities.clear()
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
                transferredConfigurations.forEach(TimestampAuthorityConfiguration::close)
                authorities.forEach(SigningTimestampAuthority::close)
                timestampSource?.close()
                signerTrust.clearBytes()
            }
        }

        private fun List<ByteArray>.clearBytes() {
            forEach { value -> value.fill(CLEARED_BYTE) }
        }

        private const val CLEARED_BYTE: Byte = 0
    }
}
