package fi.refineid.android.document

import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedSignature
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class QualifiedPdfSigningCoordinatorTest {
    @Test
    fun signsBothSupportedProfilesAndClearsEveryIntermediateOwner() {
        for (case in SUPPORTED_PROFILE_CASES) {
            val certificate = certificate(case.profile)
            val card = FakeQualifiedCardService(NativeCertificateReadResult.Success(certificate))
            val cryptography = FakeQualifiedPdfCryptography()
            val pin2 = Pin2Submission.from(SYNTHETIC_PIN2)
            val expectedPlaceholder =
                PdfIncrementalSigner.prepare(
                    document = PdfTestDocuments.minimalClassic().document,
                    revision = PdfSignatureRevision.Signature(VALID_CLAIM),
                )

            val result = sign(card = card, cryptography = cryptography, pin2 = pin2)

            val success = result as QualifiedPdfSigningResult.Success
            assertEquals(case.algorithm, card.observedAlgorithm)
            assertSame(certificate, card.observedCertificate)
            assertArrayEquals(SYNTHETIC_PIN2.encodeToByteArray(), card.observedPin2)
            assertArrayEquals(SYNTHETIC_SIGNED_ATTRIBUTES, card.observedContent)
            assertArrayEquals(expectedPlaceholder.digest(), cryptography.observedDigest)
            assertEquals(case.profile, cryptography.observedProfile)
            success.document.useBytes { bytes ->
                assertTrue(bytes.size > PdfTestDocuments.minimalClassic().document.size)
                PdfDocumentIndex.parse(bytes)
                assertTrue(String(bytes, Charsets.ISO_8859_1).contains(SYNTHETIC_CMS_HEX))
            }
            assertAllZero(cryptography.returnedAttributes)
            assertAllZero(cryptography.returnedCms)
            assertCertificateClosed(certificate)
            assertSignatureClosed(checkNotNull(card.returnedSignature))
            assertSubmissionClosed(pin2)
            success.document.close()
        }
    }

    @Test
    fun refusesMalformedPdfBeforeReadingTheCard() {
        val card = FakeQualifiedCardService(certificateResult())
        val pin2 = Pin2Submission.from(SYNTHETIC_PIN2)

        val result =
            sign(
                card = card,
                cryptography = FakeQualifiedPdfCryptography(),
                pin2 = pin2,
                document = NOT_A_PDF.encodeToByteArray(),
            )

        assertEquals(
            QualifiedPdfSigningResult.Failure(
                QualifiedPdfSigningFailure.Document(PdfSigningFailure.NOT_A_PDF),
            ),
            result,
        )
        assertEquals(NO_REQUESTS, card.certificateRequestCount)
        assertEquals(NO_REQUESTS, card.signatureRequestCount)
        assertSubmissionClosed(pin2)
    }

    @Test
    fun mapsCertificateFailureWithoutEnteringTheCredentialPath() {
        val card =
            FakeQualifiedCardService(
                NativeCertificateReadResult.Failure(
                    NativeCertificateReadFailure.CARD_UNAVAILABLE,
                ),
            )
        val pin2 = Pin2Submission.from(SYNTHETIC_PIN2)

        val result = sign(card = card, cryptography = FakeQualifiedPdfCryptography(), pin2 = pin2)

        assertEquals(
            QualifiedPdfSigningResult.Failure(
                QualifiedPdfSigningFailure.Certificate(
                    NativeCertificateReadFailure.CARD_UNAVAILABLE,
                ),
            ),
            result,
        )
        assertEquals(SINGLE_REQUEST, card.certificateRequestCount)
        assertEquals(NO_REQUESTS, card.signatureRequestCount)
        assertSubmissionClosed(pin2)
    }

    @Test
    fun refusesUnsupportedQualifiedKeyProfileBeforeCredentialUse() {
        val certificate = certificate(NativeCardKeyProfile.RSA_2048)
        val card = FakeQualifiedCardService(NativeCertificateReadResult.Success(certificate))
        val pin2 = Pin2Submission.from(SYNTHETIC_PIN2)

        val result = sign(card = card, cryptography = FakeQualifiedPdfCryptography(), pin2 = pin2)

        assertEquals(
            QualifiedPdfSigningResult.Failure(QualifiedPdfSigningFailure.KeyProfileUnsupported),
            result,
        )
        assertEquals(NO_REQUESTS, card.signatureRequestCount)
        assertCertificateClosed(certificate)
        assertSubmissionClosed(pin2)
    }

    @Test
    fun mapsCardFailureAndClearsCertificateAndAttributes() {
        val certificate = certificate(NativeCardKeyProfile.RSA_3072)
        val card =
            FakeQualifiedCardService(
                certificateResult = NativeCertificateReadResult.Success(certificate),
                signingFailure = QualifiedSignFailure.WRONG_PIN,
            )
        val cryptography = FakeQualifiedPdfCryptography()
        val pin2 = Pin2Submission.from(SYNTHETIC_PIN2)

        val result = sign(card = card, cryptography = cryptography, pin2 = pin2)

        assertEquals(
            QualifiedPdfSigningResult.Failure(
                QualifiedPdfSigningFailure.Card(QualifiedSignFailure.WRONG_PIN),
            ),
            result,
        )
        assertEquals(SINGLE_REQUEST, card.signatureRequestCount)
        assertAllZero(cryptography.returnedAttributes)
        assertCertificateClosed(certificate)
        assertSubmissionClosed(pin2)
    }

    @Test
    fun mapsAttributeAndAssemblyFailuresAtTheirExactBoundaries() {
        val attributeCertificate = certificate(NativeCardKeyProfile.RSA_3072)
        val attributeCard =
            FakeQualifiedCardService(NativeCertificateReadResult.Success(attributeCertificate))
        val attributePin2 = Pin2Submission.from(SYNTHETIC_PIN2)
        val attributeFailure = QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE

        val attributeResult =
            sign(
                card = attributeCard,
                cryptography = FakeQualifiedPdfCryptography(attributeFailure = attributeFailure),
                pin2 = attributePin2,
            )

        assertEquals(
            QualifiedPdfSigningResult.Failure(QualifiedPdfSigningFailure.Cms(attributeFailure)),
            attributeResult,
        )
        assertEquals(NO_REQUESTS, attributeCard.signatureRequestCount)
        assertCertificateClosed(attributeCertificate)
        assertSubmissionClosed(attributePin2)

        val assemblyCertificate = certificate(NativeCardKeyProfile.ECDSA_P384)
        val assemblyCard =
            FakeQualifiedCardService(NativeCertificateReadResult.Success(assemblyCertificate))
        val assemblyPin2 = Pin2Submission.from(SYNTHETIC_PIN2)
        val assemblyFailure = QualifiedDocumentCmsFailure.SIGNATURE_MALFORMED
        val assemblyCryptography =
            FakeQualifiedPdfCryptography(assemblyFailure = assemblyFailure)

        val assemblyResult =
            sign(
                card = assemblyCard,
                cryptography = assemblyCryptography,
                pin2 = assemblyPin2,
            )

        assertEquals(
            QualifiedPdfSigningResult.Failure(QualifiedPdfSigningFailure.Cms(assemblyFailure)),
            assemblyResult,
        )
        assertAllZero(assemblyCryptography.returnedAttributes)
        assertCertificateClosed(assemblyCertificate)
        assertSignatureClosed(checkNotNull(assemblyCard.returnedSignature))
        assertSubmissionClosed(assemblyPin2)
    }

    @Test
    fun signedDocumentOwnsAndClearsItsBytes() {
        val owned = SYNTHETIC_SIGNED_DOCUMENT.copyOf()
        val document = SignedPdfDocument(owned)

        assertEquals(SYNTHETIC_SIGNED_DOCUMENT.size, document.length)
        assertArrayEquals(SYNTHETIC_SIGNED_DOCUMENT, document.copyBytes())
        assertFalse(document.toString().contains(SYNTHETIC_DOCUMENT_TEXT))

        document.close()

        assertAllZero(owned)
        assertThrows(IllegalStateException::class.java) {
            document.useBytes(ByteArray::size)
        }
    }

    private fun sign(
        card: QualifiedCardService,
        cryptography: QualifiedPdfCryptography,
        pin2: Pin2Submission,
        document: ByteArray = PdfTestDocuments.minimalClassic().document,
    ): QualifiedPdfSigningResult {
        var completion: QualifiedPdfSigningResult? = null
        QualifiedPdfSigningCoordinator(
            cardService = card,
            cryptography = cryptography,
        ).sign(
            document = document,
            claim = VALID_CLAIM,
            pin2 = pin2,
        ) { result ->
            check(completion == null)
            completion = result
        }
        return checkNotNull(completion)
    }

    private fun certificate(profile: NativeCardKeyProfile): NativeQualifiedCertificate =
        NativeQualifiedCertificate(
            keyProfile = profile,
            ownedDer = SYNTHETIC_CERTIFICATE.copyOf(),
        )

    private fun certificateResult(): NativeCertificateReadResult<NativeQualifiedCertificate> =
        NativeCertificateReadResult.Success(certificate(NativeCardKeyProfile.RSA_3072))

    private fun assertSubmissionClosed(pin2: Pin2Submission) {
        assertThrows(IllegalStateException::class.java) {
            pin2.consume(ByteArray::size)
        }
    }

    private fun assertCertificateClosed(certificate: NativeQualifiedCertificate) {
        assertThrows(IllegalStateException::class.java, certificate::copyDer)
    }

    private fun assertSignatureClosed(signature: NativeQualifiedSignature) {
        assertThrows(IllegalStateException::class.java, signature::copyBytes)
    }

    private fun assertAllZero(bytes: ByteArray?) {
        assertTrue(checkNotNull(bytes).all { byte -> byte == ZERO_BYTE })
    }

    private class FakeQualifiedCardService(
        private val certificateResult: NativeCertificateReadResult<NativeQualifiedCertificate>,
        private val signingFailure: QualifiedSignFailure? = null,
    ) : QualifiedCardService {
        var certificateRequestCount = NO_REQUESTS
            private set
        var signatureRequestCount = NO_REQUESTS
            private set
        var observedAlgorithm: QualifiedSigningAlgorithm? = null
            private set
        var observedCertificate: NativeQualifiedCertificate? = null
            private set
        var observedContent: ByteArray? = null
            private set
        var observedPin2: ByteArray? = null
            private set
        var returnedSignature: NativeQualifiedSignature? = null
            private set

        override fun requestQualifiedCertificate(
            onResult: (NativeCertificateReadResult<NativeQualifiedCertificate>) -> Unit,
        ) {
            certificateRequestCount += REQUEST_COUNT_STEP
            onResult(certificateResult)
        }

        override fun requestPin2Preflight(onResult: (NativePin2PreflightResult) -> Unit) {
            error("PIN2 preflight was not requested")
        }

        override fun requestQualifiedSignature(
            algorithm: QualifiedSigningAlgorithm,
            pin2: Pin2Submission,
            content: ByteArray,
            expectedCertificate: NativeQualifiedCertificate,
            onResult: (QualifiedSignResult) -> Unit,
        ) {
            signatureRequestCount += REQUEST_COUNT_STEP
            observedAlgorithm = algorithm
            observedCertificate = expectedCertificate
            observedContent = content.copyOf()
            pin2.consume { bytes -> observedPin2 = bytes.copyOf() }
            val failure = signingFailure
            if (failure != null) {
                onResult(QualifiedSignResult.Failure(failure))
                return
            }
            val signature =
                NativeQualifiedSignature(
                    algorithm = algorithm,
                    ownedBytes = ByteArray(algorithm.signatureLength) { SYNTHETIC_SIGNATURE_FILL },
                )
            returnedSignature = signature
            onResult(QualifiedSignResult.Success(signature))
        }
    }

    private class FakeQualifiedPdfCryptography(
        private val attributeFailure: QualifiedDocumentCmsFailure? = null,
        private val assemblyFailure: QualifiedDocumentCmsFailure? = null,
    ) : QualifiedPdfCryptography {
        var observedDigest: ByteArray? = null
            private set
        var observedProfile: NativeCardKeyProfile? = null
            private set
        var returnedAttributes: ByteArray? = null
            private set
        var returnedCms: ByteArray? = null
            private set

        override fun signedAttributes(
            byteRangeDigest: ByteArray,
            signerCertificate: NativeQualifiedCertificate,
        ): ByteArray {
            attributeFailure?.let { failure -> throw QualifiedDocumentCmsException(failure) }
            assertEquals(SHA384_DIGEST_LENGTH_BYTES, byteRangeDigest.size)
            observedDigest = byteRangeDigest.copyOf()
            observedProfile = signerCertificate.keyProfile
            return SYNTHETIC_SIGNED_ATTRIBUTES.copyOf().also { attributes ->
                returnedAttributes = attributes
            }
        }

        override fun assemble(
            signedAttributes: ByteArray,
            signature: NativeQualifiedSignature,
            signerCertificate: NativeQualifiedCertificate,
        ): ByteArray {
            assemblyFailure?.let { failure -> throw QualifiedDocumentCmsException(failure) }
            assertArrayEquals(SYNTHETIC_SIGNED_ATTRIBUTES, signedAttributes)
            assertEquals(signerCertificate.keyProfile, signature.algorithm.keyProfile)
            return SYNTHETIC_CMS.copyOf().also { cms -> returnedCms = cms }
        }
    }

    private data class SupportedProfileCase(
        val profile: NativeCardKeyProfile,
        val algorithm: QualifiedSigningAlgorithm,
    )

    private companion object {
        const val SYNTHETIC_PIN2 = "123456"
        const val NOT_A_PDF = "not a PDF"
        const val SYNTHETIC_DOCUMENT_TEXT = "synthetic signed PDF"
        const val SYNTHETIC_CMS_TEXT = "synthetic CMS"
        const val SYNTHETIC_CMS_HEX = "73796E74686574696320434D53"
        const val NO_REQUESTS = 0
        const val SINGLE_REQUEST = 1
        const val REQUEST_COUNT_STEP = 1
        const val SYNTHETIC_SIGNATURE_FILL: Byte = 0x5A
        const val ZERO_BYTE: Byte = 0
        val VALID_CLAIM =
            PdfSignatureClaim(
                signedAt = Instant.parse("2026-08-15T12:34:56Z"),
                reason = null,
                location = null,
            )
        val SYNTHETIC_CERTIFICATE = "synthetic qualified certificate".encodeToByteArray()
        val SYNTHETIC_SIGNED_ATTRIBUTES = "synthetic signed attributes".encodeToByteArray()
        val SYNTHETIC_CMS = SYNTHETIC_CMS_TEXT.encodeToByteArray()
        val SYNTHETIC_SIGNED_DOCUMENT = SYNTHETIC_DOCUMENT_TEXT.encodeToByteArray()
        val SUPPORTED_PROFILE_CASES =
            listOf(
                SupportedProfileCase(
                    profile = NativeCardKeyProfile.RSA_3072,
                    algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                ),
                SupportedProfileCase(
                    profile = NativeCardKeyProfile.ECDSA_P384,
                    algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
                ),
            )
    }
}
