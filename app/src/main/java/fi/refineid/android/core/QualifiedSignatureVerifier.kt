package fi.refineid.android.core

import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Local proof that a qualified signature matches its exact card certificate. */
internal object QualifiedSignatureVerifier {
    fun verify(
        certificate: NativeQualifiedCertificate,
        content: ByteArray,
        signature: NativeQualifiedSignature,
    ): Boolean {
        if (certificate.keyProfile != signature.algorithm.keyProfile) {
            return false
        }
        val certificateDer = certificate.copyDer()
        return try {
            val parsedCertificate =
                CertificateFactory
                    .getInstance(X509_CERTIFICATE_TYPE)
                    .generateCertificate(certificateDer.inputStream()) as? X509Certificate
                    ?: return false
            signature.useBytes { signatureBytes ->
                verify(
                    publicKey = parsedCertificate.publicKey,
                    algorithm = signature.algorithm,
                    content = content,
                    signature = signatureBytes,
                )
            }
        } catch (_: RuntimeException) {
            false
        } catch (_: java.security.GeneralSecurityException) {
            false
        } finally {
            certificateDer.fill(ZERO_BYTE)
        }
    }

    internal fun verify(
        publicKey: PublicKey,
        algorithm: QualifiedSigningAlgorithm,
        content: ByteArray,
        signature: ByteArray,
    ): Boolean {
        if (signature.size != algorithm.signatureLength) {
            return false
        }
        val verifier =
            Signature.getInstance(
                when (algorithm) {
                    QualifiedSigningAlgorithm.RSA_PKCS1_SHA384 -> JCA_SHA384_WITH_RSA
                    QualifiedSigningAlgorithm.ECDSA_P384_SHA384 -> JCA_SHA384_WITH_ECDSA
                },
            )
        verifier.initVerify(publicKey)
        verifier.update(content)
        return when (algorithm) {
            QualifiedSigningAlgorithm.RSA_PKCS1_SHA384 -> {
                verifier.verify(signature)
            }

            QualifiedSigningAlgorithm.ECDSA_P384_SHA384 -> {
                val derSignature = P384EcdsaSignature.toDer(signature)
                try {
                    verifier.verify(derSignature)
                } finally {
                    derSignature.fill(ZERO_BYTE)
                }
            }
        }
    }

    private const val X509_CERTIFICATE_TYPE = "X.509"
    private const val JCA_SHA384_WITH_RSA = "SHA384withRSA"
    private const val JCA_SHA384_WITH_ECDSA = "SHA384withECDSA"
    private const val ZERO_BYTE: Byte = 0
}
