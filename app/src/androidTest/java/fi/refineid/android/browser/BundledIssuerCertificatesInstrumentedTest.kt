package fi.refineid.android.browser

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
internal class BundledIssuerCertificatesInstrumentedTest {
    @Test
    fun loadsThePinnedIssuerSetAsCurrentlyValidCertificateAuthorities() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val issuers = BundledIssuerCertificates.load(context)

        assertEquals(EXPECTED_ISSUER_COUNT, issuers.size)
        for (issuer in issuers) {
            issuer.checkValidity()
            assertTrue(
                issuer.basicConstraints >= CERTIFICATE_AUTHORITY_BASIC_CONSTRAINTS_MINIMUM,
            )
        }
        for (issuerIndex in issuers.indices) {
            for (otherIndex in issuerIndex + NEXT_INDEX_DISTANCE until issuers.size) {
                assertTrue(
                    !issuers[issuerIndex].encoded.contentEquals(issuers[otherIndex].encoded),
                )
            }
        }
    }

    private companion object {
        const val EXPECTED_ISSUER_COUNT = 4
        const val CERTIFICATE_AUTHORITY_BASIC_CONSTRAINTS_MINIMUM = 0
        const val NEXT_INDEX_DISTANCE = 1
    }
}
