package fi.refineid.android.core

import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

/** Local proof that a card response matches the selected authentication certificate. */
internal object AuthenticationSignatureVerifier {
    fun verify(
        certificate: NativeAuthenticationCertificate,
        message: ByteArray,
        signature: NativeAuthenticationSignature,
    ): Boolean {
        if (certificate.keyProfile != signature.algorithm.keyProfile) {
            return false
        }
        val certificateDer = certificate.copyDer()
        return try {
            val parsedCertificate =
                CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(certificateDer.inputStream()) as? X509Certificate
                    ?: return false
            signature.useBytes { signatureBytes ->
                verify(
                    publicKey = parsedCertificate.publicKey,
                    algorithm = signature.algorithm,
                    message = message,
                    signature = signatureBytes,
                )
            }
        } catch (_: RuntimeException) {
            false
        } catch (_: java.security.GeneralSecurityException) {
            false
        } finally {
            certificateDer.fill(0)
        }
    }

    internal fun verify(
        publicKey: PublicKey,
        algorithm: AuthenticationSigningAlgorithm,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean {
        if (signature.size != algorithm.signatureLength) {
            return false
        }
        val verifier = Signature.getInstance(algorithm.jcaName())
        if (algorithm == AuthenticationSigningAlgorithm.RSA_PSS_SHA256) {
            verifier.setParameter(RSA_PSS_SHA256_PARAMETERS)
        }
        verifier.initVerify(publicKey)
        verifier.update(message)
        return when (algorithm) {
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA256,
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA384,
            -> {
                val derSignature = P384EcdsaSignature.toDer(signature)
                try {
                    verifier.verify(derSignature)
                } finally {
                    derSignature.fill(0)
                }
            }
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA256,
            -> verifier.verify(signature)
        }
    }

    private fun AuthenticationSigningAlgorithm.jcaName(): String =
        when (this) {
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256 -> "SHA256withRSA"
            AuthenticationSigningAlgorithm.RSA_PSS_SHA256 -> "RSASSA-PSS"
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA256 -> "SHA256withECDSA"
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA384 -> "SHA384withECDSA"
        }

    private val RSA_PSS_SHA256_PARAMETERS =
        PSSParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            SHA256_DIGEST_LENGTH_BYTES,
            PSSParameterSpec.DEFAULT.trailerField,
        )

    private const val SHA256_DIGEST_LENGTH_BITS = 256
    private const val SHA256_DIGEST_LENGTH_BYTES = SHA256_DIGEST_LENGTH_BITS / Byte.SIZE_BITS
}
