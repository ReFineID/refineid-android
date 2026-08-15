package fi.refineid.android.browser

import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeAuthenticationKeyProfile
import fi.refineid.android.core.P384_COORDINATE_LENGTH_BITS
import fi.refineid.android.core.RSA_3072_KEY_LENGTH_BITS
import java.security.GeneralSecurityException
import java.security.Principal
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import javax.security.auth.x500.X500Principal

/** One browser identity whose private key is a live, non-exportable card handle. */
internal class BrowserClientIdentity private constructor(
    val privateKey: CardBackedPrivateKey,
    private val chain: Array<X509Certificate>,
) {
    fun copyCertificateChain(): Array<X509Certificate> = chain.copyOf()

    fun acceptedIssuerNames(): Set<X500Principal> =
        buildSet {
            for (certificate in chain) {
                add(certificate.subjectX500Principal)
                add(certificate.issuerX500Principal)
            }
        }

    override fun toString(): String =
        "BrowserClientIdentity(keyAlgorithm=" + privateKey.algorithm +
            ", chainLength=" + chain.size + ")"

    internal companion object {
        fun create(
            ownedLeaf: NativeAuthenticationCertificate,
            issuerCandidates: List<X509Certificate>,
            operation: CardSignatureOperation,
        ): BrowserClientIdentity? {
            val leafDer = ownedLeaf.copyDer()
            val profile = ownedLeaf.keyProfile
            ownedLeaf.close()
            val leaf =
                try {
                    CertificateFactory
                        .getInstance(X509_CERTIFICATE_TYPE)
                        .generateCertificate(leafDer.inputStream()) as? X509Certificate
                } catch (_: GeneralSecurityException) {
                    null
                } finally {
                    leafDer.fill(ZERO_BYTE)
                } ?: return null
            val keyAlgorithm = profile.jcaKeyAlgorithm() ?: return null
            if (!profile.matches(leaf)) {
                return null
            }
            val issuer =
                issuerCandidates.firstOrNull { candidate ->
                    candidate.isIssuerOf(leaf)
                } ?: return null
            return BrowserClientIdentity(
                privateKey = CardBackedPrivateKey(keyAlgorithm, operation),
                chain = arrayOf(leaf, issuer),
            )
        }

        private fun NativeAuthenticationKeyProfile.jcaKeyAlgorithm(): String? =
            when (this) {
                NativeAuthenticationKeyProfile.RSA_3072 -> JCA_KEY_ALGORITHM_RSA
                NativeAuthenticationKeyProfile.ECDSA_P384 -> JCA_KEY_ALGORITHM_EC
                NativeAuthenticationKeyProfile.RSA_2048,
                NativeAuthenticationKeyProfile.ECDSA_P256,
                -> null
            }

        private fun NativeAuthenticationKeyProfile.matches(
            certificate: X509Certificate,
        ): Boolean =
            when (this) {
                NativeAuthenticationKeyProfile.RSA_3072 ->
                    (certificate.publicKey as? RSAPublicKey)?.modulus?.bitLength() ==
                        RSA_3072_KEY_LENGTH_BITS
                NativeAuthenticationKeyProfile.ECDSA_P384 ->
                    (certificate.publicKey as? ECPublicKey)
                        ?.params
                        ?.curve
                        ?.field
                        ?.fieldSize == P384_COORDINATE_LENGTH_BITS
                NativeAuthenticationKeyProfile.RSA_2048,
                NativeAuthenticationKeyProfile.ECDSA_P256,
                -> false
            }

        private fun X509Certificate.isIssuerOf(leaf: X509Certificate): Boolean {
            if (
                basicConstraints < CERTIFICATE_AUTHORITY_BASIC_CONSTRAINTS_MINIMUM ||
                subjectX500Principal != leaf.issuerX500Principal
            ) {
                return false
            }
            return try {
                leaf.verify(publicKey)
                true
            } catch (_: GeneralSecurityException) {
                false
            } catch (_: RuntimeException) {
                false
            }
        }

        private const val X509_CERTIFICATE_TYPE = "X.509"
        private const val JCA_KEY_ALGORITHM_RSA = "RSA"
        private const val JCA_KEY_ALGORITHM_EC = "EC"
        private const val CERTIFICATE_AUTHORITY_BASIC_CONSTRAINTS_MINIMUM = 0
        private const val ZERO_BYTE: Byte = 0
    }
}

/** Applies the key-type and acceptable-issuer hints from one TLS request. */
internal object BrowserClientCertificateMatcher {
    fun accepts(
        identity: BrowserClientIdentity,
        keyTypes: Array<String>,
        principals: Array<out Principal>?,
    ): Boolean {
        if (keyTypes.none { requested -> requested == identity.privateKey.algorithm }) {
            return false
        }
        if (principals.isNullOrEmpty()) {
            return true
        }
        val acceptedIssuerNames = identity.acceptedIssuerNames()
        return principals.any { principal ->
            principal is X500Principal && principal in acceptedIssuerNames
        }
    }
}
