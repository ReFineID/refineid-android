package fi.refineid.android.ui

import android.content.ComponentName
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.uiAutomator
import fi.refineid.android.ReFineIdApplication
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import fi.refineid.android.document.QualifiedDocumentCms
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Opt-in live check that a holder-opened contactless session both reads
 * the qualified certificate (proving the EF.4332 traversal survives the
 * PACE secure-messaging channel — ADR 0013) and produces a qualified
 * signature over PIN2. UI Automator opens the session by typing the
 * access number and PIN1 into the tagged fields; the credentials arrive
 * as instrumentation arguments and never live in the repository.
 */
@RunWith(AndroidJUnit4::class)
internal class LiveNfcQualifiedSigningUiAutomatorTest {
    @Test(timeout = LIVE_TEST_TIMEOUT_MILLISECONDS)
    fun liveContactlessSessionReadsTheQualifiedCertificateAndSignsWithPin2() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(
            "enable the opt-in live NFC qualified-signing check",
            arguments.getString(LIVE_TEST_ARGUMENT) == LIVE_TEST_ENABLED_VALUE,
        )
        val can = arguments.getString(CAN_ARGUMENT)
        val pin1 = arguments.getString(PIN1_ARGUMENT)
        val pin2 = arguments.getString(PIN2_ARGUMENT)
        assumeTrue("supply the contactless access number", !can.isNullOrEmpty())
        assumeTrue("supply PIN1 to open the contactless session", !pin1.isNullOrEmpty())
        assumeTrue("supply PIN2 to sign", !pin2.isNullOrEmpty())

        val launchIntent =
            Intent
                .makeMainActivity(
                    ComponentName(instrumentation.targetContext, TARGET_ACTIVITY_CLASS),
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        instrumentation.targetContext.startActivity(launchIntent)

        uiAutomator {
            waitForAppToBeVisible(TARGET_PACKAGE)
            // The connect action appears only once the card is recognized.
            onElement(CARD_RECOGNIZED_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.NFC_CONNECT_ACTION
            }
            // A minted card shows only the PIN1 field; a fresh one also
            // shows the access-number field.
            onElementOrNull(FIELD_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.NFC_CAN_FIELD
            }?.setText(checkNotNull(can))
            onElement(FIELD_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.NFC_PIN1_FIELD
            }.setText(checkNotNull(pin1))
            // Connect is enabled only once both credentials read complete.
            onElement(FIELD_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.NFC_CONNECT_ACTION && isEnabled
            }.click()
        }

        val application =
            instrumentation.targetContext.applicationContext as ReFineIdApplication
        val cardService = application.nfcReaderController.qualifiedCardService

        awaitOpenedCertificate(cardService).use { certificate ->
            assertTrue(
                "qualified certificate must not be empty",
                certificate.derLength > EMPTY_LENGTH,
            )
            val algorithm =
                QualifiedSigningAlgorithm.entries.first { entry ->
                    entry.keyProfile == certificate.keyProfile
                }

            val digest = ByteArray(SHA384_DIGEST_LENGTH_BYTES) { SYNTHETIC_DIGEST_FILL }
            val signedAttributes =
                try {
                    QualifiedDocumentCms.signedAttributes(
                        byteRangeDigest = digest,
                        signerCertificate = certificate,
                    )
                } finally {
                    digest.fill(CLEARED_BYTE)
                }
            try {
                when (
                    val result =
                        awaitSignature(cardService, algorithm, checkNotNull(pin2), signedAttributes, certificate)
                ) {
                    is QualifiedSignResult.Success -> {
                        try {
                            assertTrue(
                                "qualified signature must not be empty",
                                result.signature.length > EMPTY_LENGTH,
                            )
                        } finally {
                            result.signature.close()
                        }
                    }

                    is QualifiedSignResult.Failure -> {
                        fail("contactless qualified sign failed: " + result.kind)
                    }
                }
            } finally {
                signedAttributes.fill(CLEARED_BYTE)
            }
        }
    }

    /**
     * Read the qualified certificate, retrying while the session is still
     * opening; a ready session returns the certificate over the freshly
     * re-run PACE channel.
     */
    private fun awaitOpenedCertificate(cardService: QualifiedCardService): NativeQualifiedCertificate {
        var lastFailure: String? = null
        repeat(CERTIFICATE_ATTEMPTS) { attempt ->
            val completion = CountDownLatch(SINGLE_COMPLETION)
            val holder = AtomicReference<NativeCertificateReadResult<NativeQualifiedCertificate>>()
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                cardService.requestQualifiedCertificate { result ->
                    holder.set(result)
                    completion.countDown()
                }
            }
            assertTrue(
                "qualified-certificate read timed out",
                completion.await(CERTIFICATE_TIMEOUT_SECONDS, TimeUnit.SECONDS),
            )
            when (val result = holder.get()) {
                is NativeCertificateReadResult.Success -> return result.certificate
                is NativeCertificateReadResult.Failure -> lastFailure = result.kind.toString()
                null -> lastFailure = "no result"
            }
            if (attempt < CERTIFICATE_ATTEMPTS - 1) {
                Thread.sleep(CERTIFICATE_RETRY_DELAY_MILLISECONDS)
            }
        }
        fail("contactless session never opened for the qualified read: " + lastFailure)
        error("unreachable")
    }

    private fun awaitSignature(
        cardService: QualifiedCardService,
        algorithm: QualifiedSigningAlgorithm,
        pin2: String,
        content: ByteArray,
        certificate: NativeQualifiedCertificate,
    ): QualifiedSignResult {
        val completion = CountDownLatch(SINGLE_COMPLETION)
        val holder = AtomicReference<QualifiedSignResult>()
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            cardService.requestQualifiedSignature(
                algorithm = algorithm,
                pin2 = Pin2Submission.from(pin2),
                content = content,
                expectedCertificate = certificate,
            ) { result ->
                holder.set(result)
                completion.countDown()
            }
        }
        assertTrue(
            "contactless qualified sign timed out",
            completion.await(SIGN_TIMEOUT_SECONDS, TimeUnit.SECONDS),
        )
        return holder.get() ?: QualifiedSignResult.Failure(QualifiedSignFailure.BRIDGE_ERROR)
    }

    private companion object {
        const val TARGET_PACKAGE = "fi.refineid.android"
        const val TARGET_ACTIVITY_CLASS = "$TARGET_PACKAGE.MainActivity"
        const val LIVE_TEST_ARGUMENT = "refineidLiveNfcSigning"
        const val LIVE_TEST_ENABLED_VALUE = "true"
        const val CAN_ARGUMENT = "refineidNfcCan"
        const val PIN1_ARGUMENT = "refineidNfcPin1"
        const val PIN2_ARGUMENT = "refineidNfcPin2"
        const val CARD_RECOGNIZED_TIMEOUT_MILLISECONDS = 150_000L
        const val FIELD_TIMEOUT_MILLISECONDS = 15_000L
        const val CERTIFICATE_TIMEOUT_SECONDS = 30L
        const val SIGN_TIMEOUT_SECONDS = 30L
        const val CERTIFICATE_ATTEMPTS = 15
        const val CERTIFICATE_RETRY_DELAY_MILLISECONDS = 1_000L
        const val LIVE_TEST_TIMEOUT_MILLISECONDS = 300_000L
        const val SINGLE_COMPLETION = 1
        const val EMPTY_LENGTH = 0
        const val SYNTHETIC_DIGEST_FILL: Byte = 0x5A
        const val CLEARED_BYTE: Byte = 0
    }
}
