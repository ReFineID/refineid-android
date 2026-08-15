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
import fi.refineid.android.core.PIN2_MAXIMUM_LENGTH
import fi.refineid.android.core.Pin2Submission
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
internal class DocumentSigningCardTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun emptyCardOffersOnlyPdfSelection() {
        var chooseCount = NO_ACTIONS
        show(onChooseDocument = { chooseCount += ACTION_COUNT_STEP })

        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_CHOOSE_ACTION)
            .assertIsDisplayed()
            .assertIsEnabled()
            .performClick()
        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_DESTINATION_ACTION).assertDoesNotExist()
        composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD).assertDoesNotExist()
        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION).assertDoesNotExist()
        composeRule.runOnIdle {
            assertEquals(SINGLE_ACTION, chooseCount)
        }
    }

    @Test
    fun selectedPdfRequiresDestinationBeforePin2() {
        var destinationCount = NO_ACTIONS
        show(
            hasDocument = true,
            onChooseDestination = { destinationCount += ACTION_COUNT_STEP },
        )

        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SELECTED_STATUS).assertIsDisplayed()
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_DESTINATION_ACTION)
            .assertIsDisplayed()
            .assertIsEnabled()
            .performClick()
        composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD).assertDoesNotExist()
        composeRule.runOnIdle {
            assertEquals(SINGLE_ACTION, destinationCount)
        }
    }

    @Test
    fun securePin2SubmitsOnceAndClearsImmediately() {
        var submissionCount = NO_ACTIONS
        var submittedBytes: ByteArray? = null
        show(
            hasDocument = true,
            hasDestination = true,
            onSign = { submission ->
                submissionCount += ACTION_COUNT_STEP
                submittedBytes = submission.consume { bytes -> bytes.copyOf() }
            },
        )
        val pinField = composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD)
        val signAction = composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION)

        assertTrue(
            "PIN2 field must carry password semantics",
            pinField.fetchSemanticsNode().config.contains(SemanticsProperties.Password),
        )
        signAction.assertIsNotEnabled()
        pinField.performTextInput(SYNTHETIC_PIN2)
        signAction.assertIsEnabled().performClick()

        val expected = SYNTHETIC_PIN2.encodeToByteArray()
        try {
            composeRule.runOnIdle {
                assertEquals(SINGLE_ACTION, submissionCount)
                assertArrayEquals(expected, checkNotNull(submittedBytes))
            }
            signAction.assertIsNotEnabled()
        } finally {
            expected.fill(CLEARED_BYTE)
            submittedBytes?.fill(CLEARED_BYTE)
        }
    }

    @Test
    fun pin2InputRejectsNonDecimalAndOverlengthValues() {
        show(hasDocument = true, hasDestination = true)
        val pinField = composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD)
        val signAction = composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION)

        pinField.performTextInput(NON_DECIMAL_PIN2)
        signAction.assertIsNotEnabled()
        pinField.performTextInput(OVERLENGTH_PIN2)
        signAction.assertIsNotEnabled()
    }

    @Test
    fun signingDisablesEveryMutableControlAndShowsTerseStatus() {
        show(
            hasDocument = true,
            hasDestination = true,
            status = DocumentSigningStatus.SIGNING,
        )

        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_CHOOSE_ACTION).assertIsNotEnabled()
        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_DESTINATION_ACTION).assertIsNotEnabled()
        composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD).assertIsNotEnabled()
        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION).assertIsNotEnabled()
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_SIGNING_STATUS)
            .assertTextEquals(
                InstrumentationRegistry
                    .getInstrumentation()
                    .targetContext
                    .getString(R.string.signing),
            )
    }

    private fun show(
        hasDocument: Boolean = false,
        hasDestination: Boolean = false,
        status: DocumentSigningStatus = DocumentSigningStatus.IDLE,
        onChooseDocument: () -> Unit = {},
        onChooseDestination: () -> Unit = {},
        onSign: (Pin2Submission) -> Unit = Pin2Submission::close,
    ) {
        composeRule.setContent {
            ReFineIdTheme {
                DocumentSigningCard(
                    hasDocument = hasDocument,
                    hasDestination = hasDestination,
                    status = status,
                    onChooseDocument = onChooseDocument,
                    onChooseDestination = onChooseDestination,
                    onSign = onSign,
                )
            }
        }
    }

    private companion object {
        const val SYNTHETIC_PIN2 = "246810"
        const val NON_DECIMAL_PIN2 = "24A810"
        const val NO_ACTIONS = 0
        const val SINGLE_ACTION = 1
        const val ACTION_COUNT_STEP = 1
        const val SINGLE_EXCESS_CHARACTER_COUNT = 1
        const val DECIMAL_FILL_CHARACTER = '0'
        const val CLEARED_BYTE: Byte = 0
        val OVERLENGTH_PIN2 =
            DECIMAL_FILL_CHARACTER
                .toString()
                .repeat(PIN2_MAXIMUM_LENGTH + SINGLE_EXCESS_CHARACTER_COUNT)
    }
}
