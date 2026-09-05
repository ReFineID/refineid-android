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
    ): Boolean =
        verifyWithCertificate(certificate, signature) { publicKey, algorithm, signatureBytes ->
            verify(
                publicKey = publicKey,
                algorithm = algorithm,
                content = content,
                signature = signatureBytes,
            )
        }

    fun verifyPrehashed(
        certificate: NativeQualifiedCertificate,
        digest: ByteArray,
        signature: NativeQualifiedSignature,
    ): Boolean =
        verifyWithCertificate(certificate, signature) { publicKey, algorithm, signatureBytes ->
            verifyPrehashed(
                publicKey = publicKey,
                algorithm = algorithm,
                digest = digest,
                signature = signatureBytes,
            )
        }

    private fun verifyWithCertificate(
        certificate: NativeQualifiedCertificate,
        signature: NativeQualifiedSignature,
        verification: (PublicKey, QualifiedSigningAlgorithm, ByteArray) -> Boolean,
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
                verification(parsedCertificate.publicKey, signature.algorithm, signatureBytes)
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

    internal fun verifyPrehashed(
        publicKey: PublicKey,
        algorithm: QualifiedSigningAlgorithm,
        digest: ByteArray,
        signature: ByteArray,
    ): Boolean {
        if (digest.size != algorithm.digestLength || signature.size != algorithm.signatureLength) {
            return false
        }
        return when (algorithm) {
            QualifiedSigningAlgorithm.RSA_PKCS1_SHA384 -> {
                verifyPrehashedRsaPkcs1(publicKey, digest, signature)
            }

            QualifiedSigningAlgorithm.ECDSA_P384_SHA384 -> {
                verifyPrehashedEcdsa(publicKey, digest, signature)
            }
        }
    }

    private fun verifyPrehashedRsaPkcs1(
        publicKey: PublicKey,
        digest: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val digestInfo = SHA384_DIGEST_INFO_PREFIX + digest
        return try {
            Signature
                .getInstance(JCA_NONE_WITH_RSA)
                .apply {
                    initVerify(publicKey)
                    update(digestInfo)
                }.verify(signature)
        } finally {
            digestInfo.fill(ZERO_BYTE)
        }
    }

    private fun verifyPrehashedEcdsa(
        publicKey: PublicKey,
        digest: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val derSignature = P384EcdsaSignature.toDer(signature)
        return try {
            Signature
                .getInstance(JCA_NONE_WITH_ECDSA)
                .apply {
                    initVerify(publicKey)
                    update(digest)
                }.verify(derSignature)
        } finally {
            derSignature.fill(ZERO_BYTE)
        }
    }

    // RFC 8017 Appendix B.1: DER DigestInfo prefix for id-sha384 with NULL parameters.
    private val SHA384_DIGEST_INFO_PREFIX =
        byteArrayOf(
            0x30,
            0x41,
            0x30,
            0x0D,
            0x06,
            0x09,
            0x60,
            0x86.toByte(),
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            0x02,
            0x05,
            0x00,
            0x04,
            0x30,
        )

    private const val X509_CERTIFICATE_TYPE = "X.509"
    private const val JCA_NONE_WITH_RSA = "NONEwithRSA"
    private const val JCA_NONE_WITH_ECDSA = "NONEwithECDSA"
    private const val JCA_SHA384_WITH_RSA = "SHA384withRSA"
    private const val JCA_SHA384_WITH_ECDSA = "SHA384withECDSA"
    private const val ZERO_BYTE: Byte = 0
}
