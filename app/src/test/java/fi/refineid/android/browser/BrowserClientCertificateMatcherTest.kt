package fi.refineid.android.browser

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.Principal
import javax.security.auth.x500.X500Principal

class BrowserClientCertificateMatcherTest {
    @Test
    fun acceptsMatchingKeyTypeAndAnyNameInTheKnownChain() {
        assertTrue(
            BrowserClientCertificateMatcher.accepts(
                keyAlgorithm = JCA_KEY_ALGORITHM_RSA,
                acceptedIssuerNames = ACCEPTED_ISSUER_NAMES,
                keyTypes = arrayOf(JCA_KEY_ALGORITHM_EC, JCA_KEY_ALGORITHM_RSA),
                principals = arrayOf(ROOT_NAME),
            ),
        )
    }

    @Test
    fun acceptsAnEmptyIssuerHintSet() {
        assertTrue(
            BrowserClientCertificateMatcher.accepts(
                keyAlgorithm = JCA_KEY_ALGORITHM_RSA,
                acceptedIssuerNames = ACCEPTED_ISSUER_NAMES,
                keyTypes = arrayOf(JCA_KEY_ALGORITHM_RSA),
                principals = emptyArray(),
            ),
        )
    }

    @Test
    fun rejectsWrongKeyTypeUnknownIssuerAndNonX500Principal() {
        assertFalse(
            BrowserClientCertificateMatcher.accepts(
                keyAlgorithm = JCA_KEY_ALGORITHM_RSA,
                acceptedIssuerNames = ACCEPTED_ISSUER_NAMES,
                keyTypes = arrayOf(JCA_KEY_ALGORITHM_EC),
                principals = arrayOf(INTERMEDIATE_NAME),
            ),
        )
        assertFalse(
            BrowserClientCertificateMatcher.accepts(
                keyAlgorithm = JCA_KEY_ALGORITHM_RSA,
                acceptedIssuerNames = ACCEPTED_ISSUER_NAMES,
                keyTypes = arrayOf(JCA_KEY_ALGORITHM_RSA),
                principals = arrayOf(UNKNOWN_NAME),
            ),
        )
        assertFalse(
            BrowserClientCertificateMatcher.accepts(
                keyAlgorithm = JCA_KEY_ALGORITHM_RSA,
                acceptedIssuerNames = ACCEPTED_ISSUER_NAMES,
                keyTypes = arrayOf(JCA_KEY_ALGORITHM_RSA),
                principals = arrayOf(Principal { NON_X500_PRINCIPAL_NAME }),
            ),
        )
    }

    private companion object {
        const val JCA_KEY_ALGORITHM_RSA = "RSA"
        const val JCA_KEY_ALGORITHM_EC = "EC"
        const val NON_X500_PRINCIPAL_NAME = "synthetic principal"
        val INTERMEDIATE_NAME = X500Principal("CN=Synthetic Intermediate")
        val ROOT_NAME = X500Principal("CN=Synthetic Root")
        val UNKNOWN_NAME = X500Principal("CN=Unknown")
        val ACCEPTED_ISSUER_NAMES = setOf(INTERMEDIATE_NAME, ROOT_NAME)
    }
}
