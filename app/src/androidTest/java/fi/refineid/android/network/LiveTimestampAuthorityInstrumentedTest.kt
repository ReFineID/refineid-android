package fi.refineid.android.network

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import fi.refineid.android.settings.TimestampAuthorityConfiguration
import fi.refineid.android.ui.DebugDocumentSigningSources
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
internal class LiveTimestampAuthorityInstrumentedTest {
    @Test(timeout = LIVE_TIMEOUT_MILLISECONDS)
    fun configuredAuthorityReturnsARequestBoundVerifiedToken() {
        assumeTrue(
            "enable the opt-in live timestamp-authority check",
            InstrumentationRegistry.getArguments().getString(LIVE_TEST_ARGUMENT) ==
                LIVE_TEST_ENABLED_VALUE,
        )
        val sources =
            DebugDocumentSigningSources.create(
                context = ApplicationProvider.getApplicationContext(),
                transferredConfigurations = listOf(TimestampAuthorityConfiguration.shipped()),
            )
        val digest = ByteArray(SHA384_DIGEST_LENGTH_BYTES) { SYNTHETIC_DIGEST_FILL }
        try {
            val token = sources.timestamp.acquire(digest)
            try {
                assertTrue(token.matchesMessageImprint(digest))
                assertTrue(token.encodedLength > EMPTY_TOKEN_LENGTH)
                assertTrue(token.verifiedCertificateCount > EMPTY_CERTIFICATE_COUNT)
            } finally {
                token.close()
            }
        } finally {
            digest.fill(CLEARED_BYTE)
            sources.close()
        }
    }

    private companion object {
        const val LIVE_TEST_ARGUMENT = "refineidLiveTimestampAuthority"
        const val LIVE_TEST_ENABLED_VALUE = "true"
        const val LIVE_TIMEOUT_MILLISECONDS = 120_000L
        const val EMPTY_TOKEN_LENGTH = 0
        const val EMPTY_CERTIFICATE_COUNT = 0
        const val SYNTHETIC_DIGEST_FILL: Byte = 0x5A
        const val CLEARED_BYTE: Byte = 0
    }
}
