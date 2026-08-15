package fi.refineid.android.ui

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import fi.refineid.android.R
import fi.refineid.android.browser.BrowserCardService
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.PIN1_MAXIMUM_LENGTH
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.usb.AuthenticationStatus
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
internal class MainScreenTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun readyCardAcceptsOneSyntheticSubmissionAndClearsTheField() {
        var submissionCount = 0
        var submittedBytes: ByteArray? = null
        show(
            snapshot = READY_WITH_CARD,
            onAuthenticate = { submission ->
                submissionCount += 1
                submittedBytes = submission.consume { bytes -> bytes.copyOf() }
            },
        )

        val pinField = composeRule.onNodeWithTag(UiAutomationIds.PIN1_FIELD)
        assertTrue(
            "PIN1 field must carry password semantics",
            pinField.fetchSemanticsNode().config.contains(SemanticsProperties.Password),
        )
        composeRule
            .onNodeWithTag(UiAutomationIds.AUTHENTICATION_ACTION)
            .assertIsNotEnabled()
        composeRule.onNodeWithTag(UiAutomationIds.BROWSER_ACTION).assertDoesNotExist()

        pinField.performTextInput(SYNTHETIC_PIN1)
        composeRule
            .onNodeWithTag(UiAutomationIds.AUTHENTICATION_ACTION)
            .assertIsEnabled()
            .performClick()

        val expectedBytes = SYNTHETIC_PIN1.encodeToByteArray()
        try {
            composeRule.runOnIdle {
                assertEquals(EXPECTED_SUBMISSION_COUNT, submissionCount)
                assertArrayEquals(expectedBytes, requireNotNull(submittedBytes))
            }
            composeRule
                .onNodeWithTag(UiAutomationIds.AUTHENTICATION_ACTION)
                .assertIsNotEnabled()
        } finally {
            expectedBytes.fill(CLEARED_BYTE)
            submittedBytes?.fill(CLEARED_BYTE)
        }
    }

    @Test
    fun pinFieldRejectsNonDecimalAndOverlengthInput() {
        show(snapshot = READY_WITH_CARD)

        val pinField = composeRule.onNodeWithTag(UiAutomationIds.PIN1_FIELD)
        val authenticationAction =
            composeRule.onNodeWithTag(UiAutomationIds.AUTHENTICATION_ACTION)

        pinField.performTextInput(NON_DECIMAL_PIN1)
        authenticationAction.assertIsNotEnabled()
        pinField.performTextInput(OVERLENGTH_PIN1)
        authenticationAction.assertIsNotEnabled()
    }

    @Test
    fun signingStateDisablesCredentialControls() {
        show(
            snapshot =
                READY_WITH_CARD.copy(
                    authenticationStatus = AuthenticationStatus.SIGNING,
                ),
        )

        composeRule.onNodeWithTag(UiAutomationIds.PIN1_FIELD).assertIsNotEnabled()
        composeRule
            .onNodeWithTag(UiAutomationIds.AUTHENTICATION_ACTION)
            .assertIsNotEnabled()
        composeRule
            .onNodeWithTag(UiAutomationIds.AUTHENTICATION_STATUS)
            .assertTextEquals(
                InstrumentationRegistry
                    .getInstrumentation()
                    .targetContext
                    .getString(R.string.signing),
            )
    }

    @Test
    fun readerFailureActionInvokesThePermissionHandler() {
        var requestCount = 0
        show(
            snapshot =
                UsbReaderSnapshot(
                    status = ReaderConnectionStatus.PERMISSION_REQUIRED,
                ),
            onRequestPermission = { requestCount += 1 },
        )

        composeRule
            .onNodeWithTag(UiAutomationIds.READER_ACTION)
            .assertIsDisplayed()
            .performClick()
        composeRule.runOnIdle {
            assertEquals(EXPECTED_PERMISSION_REQUEST_COUNT, requestCount)
        }
    }

    @Test
    fun readyReaderWithoutCardHidesAuthenticationControls() {
        show(
            snapshot =
                UsbReaderSnapshot(
                    status = ReaderConnectionStatus.READY,
                    cardPresence = CardPresence.NOT_PRESENT,
                ),
        )

        composeRule
            .onNodeWithTag(UiAutomationIds.READER_CARD)
            .assertIsDisplayed()
        composeRule
            .onNodeWithTag(UiAutomationIds.AUTHENTICATION_CARD)
            .assertDoesNotExist()
    }

    @Test
    fun readyCardServiceExposesTheTerseBrowserAction() {
        show(
            snapshot = READY_WITH_CARD,
            browserCardService = INERT_BROWSER_CARD_SERVICE,
        )

        composeRule
            .onNodeWithTag(UiAutomationIds.BROWSER_ACTION)
            .assertIsDisplayed()
            .assertIsEnabled()
    }

    private fun show(
        snapshot: UsbReaderSnapshot,
        onRequestPermission: () -> Unit = {},
        onAuthenticate: (Pin1Submission) -> Unit = Pin1Submission::close,
        browserCardService: BrowserCardService? = null,
    ) {
        composeRule.setContent {
            ReFineIdTheme {
                MainScreen(
                    snapshot = snapshot,
                    onRequestPermission = onRequestPermission,
                    onAuthenticate = onAuthenticate,
                    browserCardService = browserCardService,
                )
            }
        }
    }

    private companion object {
        const val SYNTHETIC_PIN1 = "1357"
        const val NON_DECIMAL_PIN1 = "12A4"
        const val EXPECTED_SUBMISSION_COUNT = 1
        const val EXPECTED_PERMISSION_REQUEST_COUNT = 1
        const val CLEARED_BYTE: Byte = 0
        const val DECIMAL_FILL_CHARACTER = '0'
        const val SINGLE_EXCESS_CHARACTER_COUNT = 1

        val OVERLENGTH_PIN1 =
            DECIMAL_FILL_CHARACTER
                .toString()
                .repeat(PIN1_MAXIMUM_LENGTH + SINGLE_EXCESS_CHARACTER_COUNT)

        val READY_WITH_CARD =
            UsbReaderSnapshot(
                status = ReaderConnectionStatus.READY,
                cardPresence = CardPresence.PRESENT,
            )

        val INERT_BROWSER_CARD_SERVICE =
            object : BrowserCardService {
                override fun requestAuthenticationCertificate(
                    onResult: (NativeAuthenticationCertificate?) -> Unit,
                ) {
                    onResult(null)
                }

                override fun signAuthenticationMessage(
                    algorithm: AuthenticationSigningAlgorithm,
                    pin1: Pin1Submission,
                    message: ByteArray,
                ): AuthenticationSignResult {
                    pin1.close()
                    return AuthenticationSignResult.Failure(
                        AuthenticationSignFailure.CARD_UNAVAILABLE,
                    )
                }
            }
    }
}
