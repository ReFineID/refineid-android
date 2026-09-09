package fi.refineid.android.browser

import fi.refineid.android.core.AuthenticationSigningAlgorithm
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

/**
 * TLS 1.3 signs its CertificateVerify with RSA-PSS and sets an explicit
 * PSSParameterSpec on the delegated signature. The card's profile is
 * fixed, so exactly that profile must be accepted and everything else
 * refused — a mismatch silently signed would fail on the wire anyway.
 */
internal class CardSignaturePssParametersTest {
    @Test
    fun acceptsTheMatchingTlsProfilePerDigest() {
        assertTrue(
            AuthenticationSigningAlgorithm.RSA_PSS_SHA256.acceptsPssParameters(
                PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, SHA256_SALT, TRAILER),
            ),
        )
        assertTrue(
            AuthenticationSigningAlgorithm.RSA_PSS_SHA384.acceptsPssParameters(
                PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, SHA384_SALT, TRAILER),
            ),
        )
        assertTrue(
            AuthenticationSigningAlgorithm.RSA_PSS_SHA512.acceptsPssParameters(
                PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, SHA512_SALT, TRAILER),
            ),
        )
    }

    @Test
    fun acceptsTheUndashedDigestSpellingSomeStacksUse() {
        assertTrue(
            AuthenticationSigningAlgorithm.RSA_PSS_SHA256.acceptsPssParameters(
                PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec("SHA256"), SHA256_SALT, TRAILER),
            ),
        )
    }

    @Test
    fun refusesAMismatchedOuterDigest() {
        // The outer digest pins the TLS scheme, so it must agree.
        assertFalse(
            AuthenticationSigningAlgorithm.RSA_PSS_SHA256.acceptsPssParameters(
                PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, SHA384_SALT, TRAILER),
            ),
        )
    }

    @Test
    fun toleratesMgfSaltAndTrailerVariations() {
        // The card owns the PSS block; only the outer digest must match,
        // so an unusual salt or trailer is not a reason to fail the sign.
        assertTrue(
            AuthenticationSigningAlgorithm.RSA_PSS_SHA256.acceptsPssParameters(
                PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA384, SHA256_SALT - 1, TRAILER + 1),
            ),
        )
    }

    @Test
    fun refusesParametersOnNonPssVariants() {
        val spec = PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, SHA256_SALT, TRAILER)
        assertFalse(AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256.acceptsPssParameters(spec))
        assertFalse(AuthenticationSigningAlgorithm.ECDSA_P384_SHA384.acceptsPssParameters(spec))
    }

    private companion object {
        const val SHA256_SALT = 32
        const val SHA384_SALT = 48
        const val SHA512_SALT = 64
        const val TRAILER = 1
    }
}
