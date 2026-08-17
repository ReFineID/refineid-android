package fi.refineid.android.document

import java.math.BigInteger
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** One signature's independent verdict over a signed PDF. */
internal data class DocumentSignatureVerdict(
    val signerCommonName: String?,
    val signingTime: String?,
    val coversWholeDocument: Boolean,
    val digestMatches: Boolean,
    val signatureValid: Boolean,
    val chainTrusted: Boolean,
    val hasSignatureTimestamp: Boolean,
) {
    /** The cryptographic core: intact bytes, a valid signature, a trusted signer. */
    val isValid: Boolean
        get() = digestMatches && signatureValid && chainTrusted
}

internal sealed interface DocumentValidationResult {
    data class Completed(
        val signatures: List<DocumentSignatureVerdict>,
    ) : DocumentValidationResult {
        val isValid: Boolean
            get() = signatures.isNotEmpty() && signatures.all { it.isValid }
    }

    /** No signature dictionary was found in the document. */
    data object Unsigned : DocumentValidationResult

    /** The bytes were not a parseable PDF signature structure. */
    data object Malformed : DocumentValidationResult
}

/**
 * Independent PAdES-B-B validation. For each signature it recomputes the
 * signed digest over the byte range, verifies the CMS signature over the
 * signed attributes with the signer's own certificate, and confirms the
 * signer chains to a pinned trust anchor. Long-term validation material
 * (timestamp and revocation at signing time) is reported as present but
 * not yet cryptographically checked here.
 */
internal class DocumentValidator(
    private val trustAnchors: List<X509Certificate>,
) {
    fun validate(pdf: ByteArray): DocumentValidationResult {
        val signatures = PdfSignatureLocator.locate(pdf)
        if (signatures.isEmpty()) {
            return DocumentValidationResult.Unsigned
        }
        val verdicts =
            signatures.map { signature ->
                verifySignature(pdf, signature) ?: return DocumentValidationResult.Malformed
            }
        return DocumentValidationResult.Completed(verdicts)
    }

    private fun verifySignature(
        pdf: ByteArray,
        signature: PdfSignatureLocation,
    ): DocumentSignatureVerdict? {
        val signedBytes = signature.signedBytes(pdf) ?: return null
        val cms = CmsSignedData.parse(signature.cms) ?: return null
        val signerCertificate = cms.signerCertificate() ?: return null

        val digestMatches =
            cms.messageDigest != null &&
                MessageDigest.getInstance(cms.digestJcaName).digest(signedBytes).contentEquals(cms.messageDigest)

        val signatureValid = verifyCmsSignature(cms, signerCertificate)
        val chainTrusted = isChainTrusted(signerCertificate)

        return DocumentSignatureVerdict(
            signerCommonName = commonNameOf(signerCertificate),
            signingTime = cms.signingTime,
            coversWholeDocument = signature.coversWholeDocument(pdf.size),
            digestMatches = digestMatches,
            signatureValid = signatureValid,
            chainTrusted = chainTrusted,
            hasSignatureTimestamp = cms.hasSignatureTimestamp,
        )
    }

    private fun verifyCmsSignature(
        cms: CmsSignedData,
        signerCertificate: X509Certificate,
    ): Boolean =
        try {
            val jcaName = cms.signatureJcaName ?: return false
            val verifier = Signature.getInstance(jcaName)
            verifier.initVerify(signerCertificate.publicKey)
            verifier.update(cms.signedAttributesForVerification)
            verifier.verify(cms.signatureBytes)
        } catch (_: RuntimeException) {
            false
        } catch (_: java.security.GeneralSecurityException) {
            false
        }

    private fun isChainTrusted(signerCertificate: X509Certificate): Boolean =
        trustAnchors.any { anchor ->
            signerCertificate.issuerX500Principal == anchor.subjectX500Principal &&
                runCatching { signerCertificate.verify(anchor.publicKey) }.isSuccess
        }

    private fun commonNameOf(certificate: X509Certificate): String? {
        val rfc2253 = certificate.subjectX500Principal.getName("RFC2253")
        return COMMON_NAME_PATTERN
            .find(rfc2253)
            ?.groupValues
            ?.getOrNull(1)
            ?.trim()
    }

    private companion object {
        val COMMON_NAME_PATTERN = Regex("""CN=([^,]+)""")
    }
}

/** Where one signature lives in the file: its byte range and CMS blob. */
internal data class PdfSignatureLocation(
    val rangeStart: Int,
    val rangeFirstLength: Int,
    val rangeSecondStart: Int,
    val rangeSecondLength: Int,
    val cms: ByteArray,
) {
    fun signedBytes(pdf: ByteArray): ByteArray? {
        val firstEnd = rangeStart.toLong() + rangeFirstLength
        val secondEnd = rangeSecondStart.toLong() + rangeSecondLength
        if (rangeStart < 0 || rangeFirstLength < 0) {
            return null
        }
        if (rangeSecondStart < rangeStart || rangeSecondLength < 0) {
            return null
        }
        if (firstEnd > rangeSecondStart) {
            return null
        }
        if (firstEnd > pdf.size || secondEnd > pdf.size) {
            return null
        }
        val first = pdf.copyOfRange(rangeStart, firstEnd.toInt())
        val second = pdf.copyOfRange(rangeSecondStart, secondEnd.toInt())
        return first + second
    }

    /** Whether the signed range spans the file from its start to its end. */
    fun coversWholeDocument(fileLength: Int): Boolean =
        rangeStart == 0 && rangeSecondStart.toLong() + rangeSecondLength == fileLength.toLong()

    override fun equals(other: Any?): Boolean = this === other

    override fun hashCode(): Int = System.identityHashCode(this)
}
