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
    ): Boolean =
        verifyWithCertificate(certificate, signature) { publicKey, algorithm, signatureBytes ->
            verify(
                publicKey = publicKey,
                algorithm = algorithm,
                message = message,
                signature = signatureBytes,
            )
        }

    fun verifyPrehashed(
        certificate: NativeAuthenticationCertificate,
        digest: ByteArray,
        signature: NativeAuthenticationSignature,
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
        certificate: NativeAuthenticationCertificate,
        signature: NativeAuthenticationSignature,
        verification: (PublicKey, AuthenticationSigningAlgorithm, ByteArray) -> Boolean,
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
                verification(parsedCertificate.publicKey, signature.algorithm, signatureBytes)
            }
        } catch (_: RuntimeException) {
            false
        } catch (_: java.security.GeneralSecurityException) {
            false
        } finally {
            certificateDer.fill(0)
        }
    }

    internal fun verifyPrehashed(
        publicKey: PublicKey,
        algorithm: AuthenticationSigningAlgorithm,
        digest: ByteArray,
        signature: ByteArray,
    ): Boolean {
        if (digest.size != algorithm.digestLength || signature.size != algorithm.signatureLength) {
            return false
        }
        return when (algorithm) {
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384,
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512,
            -> {
                verifyPrehashedRsaPkcs1(
                    publicKey = publicKey,
                    digest = digest,
                    signature = signature,
                    digestInfoPrefix = algorithm.digest.rsaDigestInfoPrefix(),
                )
            }

            AuthenticationSigningAlgorithm.RSA_PSS_SHA256,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA384,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA512,
            -> {
                RsaPssPrehashedVerifier.verify(
                    publicKey = publicKey,
                    digestAlgorithm = algorithm.digest,
                    digest = digest,
                    signature = signature,
                )
            }

            AuthenticationSigningAlgorithm.ECDSA_P384_SHA256,
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA384,
            -> {
                verifyPrehashedEcdsa(publicKey, digest, signature)
            }
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
        val verifier = algorithm.newVerifier()
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
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA384,
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA512,
            -> {
                verifier.verify(signature)
            }
        }
    }

    private fun AuthenticationSigningAlgorithm.newVerifier(): Signature =
        when (this) {
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256 -> {
                Signature.getInstance(JCA_SHA256_WITH_RSA)
            }

            AuthenticationSigningAlgorithm.RSA_PSS_SHA256 -> {
                newRsaPssVerifier(JCA_SHA256_WITH_RSA_PSS, digest)
            }

            AuthenticationSigningAlgorithm.ECDSA_P384_SHA256 -> {
                Signature.getInstance(JCA_SHA256_WITH_ECDSA)
            }

            AuthenticationSigningAlgorithm.ECDSA_P384_SHA384 -> {
                Signature.getInstance(JCA_SHA384_WITH_ECDSA)
            }

            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384 -> {
                Signature.getInstance(JCA_SHA384_WITH_RSA)
            }

            AuthenticationSigningAlgorithm.RSA_PSS_SHA384 -> {
                newRsaPssVerifier(JCA_SHA384_WITH_RSA_PSS, digest)
            }

            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512 -> {
                Signature.getInstance(JCA_SHA512_WITH_RSA)
            }

            AuthenticationSigningAlgorithm.RSA_PSS_SHA512 -> {
                newRsaPssVerifier(JCA_SHA512_WITH_RSA_PSS, digest)
            }
        }

    private fun newRsaPssVerifier(
        namedAlgorithm: String,
        digest: AuthenticationDigest,
    ): Signature =
        try {
            Signature.getInstance(namedAlgorithm)
        } catch (_: java.security.NoSuchAlgorithmException) {
            Signature.getInstance(JCA_GENERIC_RSA_PSS).apply {
                setParameter(digest.rsaPssParameters())
            }
        }

    private fun verifyPrehashedRsaPkcs1(
        publicKey: PublicKey,
        digest: ByteArray,
        signature: ByteArray,
        digestInfoPrefix: ByteArray,
    ): Boolean {
        val digestInfo = digestInfoPrefix + digest
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

    private fun AuthenticationDigest.rsaPssParameters(): PSSParameterSpec =
        PSSParameterSpec(
            jcaName,
            MASK_GENERATION_FUNCTION_NAME,
            mgfSpecification(),
            length,
            PSSParameterSpec.DEFAULT.trailerField,
        )

    private fun AuthenticationDigest.mgfSpecification(): MGF1ParameterSpec =
        when (this) {
            AuthenticationDigest.SHA256 -> MGF1ParameterSpec.SHA256
            AuthenticationDigest.SHA384 -> MGF1ParameterSpec.SHA384
            AuthenticationDigest.SHA512 -> MGF1ParameterSpec.SHA512
        }

    private fun AuthenticationDigest.rsaDigestInfoPrefix(): ByteArray =
        when (this) {
            AuthenticationDigest.SHA256 -> SHA256_DIGEST_INFO_PREFIX
            AuthenticationDigest.SHA384 -> SHA384_DIGEST_INFO_PREFIX
            AuthenticationDigest.SHA512 -> SHA512_DIGEST_INFO_PREFIX
        }

    // RFC 8017 Appendix B.1: DER DigestInfo prefix for id-sha256 with NULL parameters.
    private val SHA256_DIGEST_INFO_PREFIX =
        byteArrayOf(
            0x30,
            0x31,
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
            0x01,
            0x05,
            0x00,
            0x04,
            0x20,
        )

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

    // RFC 8017 Appendix B.1: DER DigestInfo prefix for id-sha512 with NULL parameters.
    private val SHA512_DIGEST_INFO_PREFIX =
        byteArrayOf(
            0x30,
            0x51,
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
            0x03,
            0x05,
            0x00,
            0x04,
            0x40,
        )

    private const val JCA_NONE_WITH_RSA = "NONEwithRSA"
    private const val JCA_NONE_WITH_ECDSA = "NONEwithECDSA"
    private const val JCA_SHA256_WITH_RSA = "SHA256withRSA"
    private const val JCA_SHA256_WITH_RSA_PSS = "SHA256withRSA/PSS"
    private const val JCA_SHA384_WITH_RSA = "SHA384withRSA"
    private const val JCA_SHA384_WITH_RSA_PSS = "SHA384withRSA/PSS"
    private const val JCA_SHA512_WITH_RSA = "SHA512withRSA"
    private const val JCA_SHA512_WITH_RSA_PSS = "SHA512withRSA/PSS"
    private const val JCA_GENERIC_RSA_PSS = "RSASSA-PSS"
    private const val MASK_GENERATION_FUNCTION_NAME = "MGF1"
    private const val JCA_SHA256_WITH_ECDSA = "SHA256withECDSA"
    private const val JCA_SHA384_WITH_ECDSA = "SHA384withECDSA"
    private const val ZERO_BYTE: Byte = 0
}
