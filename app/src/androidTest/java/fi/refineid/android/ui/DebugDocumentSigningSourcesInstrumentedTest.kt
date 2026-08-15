package fi.refineid.android.ui

import androidx.test.core.app.ApplicationProvider
import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import fi.refineid.android.document.QualifiedPdfTimestampSourceException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class DebugDocumentSigningSourcesInstrumentedTest {
    @Test
    fun loadsOnePinnedAuthorityAndEveryPinnedFineidIssuerWithoutNetworkAccess() {
        val sources =
            DebugDocumentSigningSources.create(ApplicationProvider.getApplicationContext())

        assertEquals(EXPECTED_AUTHORITY_COUNT, sources.timestamp.authorityCount)
        assertEquals(EXPECTED_FINEID_ISSUER_COUNT, sources.validation.signerTrustCertificateCount)
        assertEquals(EXPECTED_FINEID_ISSUER_COUNT, sources.validation.additionalCandidateCount)
        assertFalse(sources.timestamp.toString().contains(AUTHORITY_HOST))

        sources.close()

        assertThrows(QualifiedPdfTimestampSourceException::class.java) {
            sources.timestamp.acquire(ByteArray(SHA384_DIGEST_LENGTH_BYTES)).close()
        }
    }

    private companion object {
        const val EXPECTED_AUTHORITY_COUNT = 1
        const val EXPECTED_FINEID_ISSUER_COUNT = 4
        const val AUTHORITY_HOST = "timestamp.sectigo.com"
    }
}
