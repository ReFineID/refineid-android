package fi.refineid.android.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
internal class MainScreenTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun readyReaderWithCardHidesCardSectionAndExposesBrowserAndIdentity() {
        show(
            snapshot =
                READY_WITH_CARD.copy(
                    holderName = SYNTHETIC_HOLDER_NAME,
                ),
            browserCardService = INERT_BROWSER_CARD_SERVICE,
        )

        composeRule.onNodeWithTag(UiAutomationIds.READER_CARD).assertDoesNotExist()
        composeRule
            .onNodeWithTag(UiAutomationIds.BROWSER_ACTION)
            .performScrollTo()
            .assertIsDisplayed()
            .assertIsEnabled()
        composeRule
            .onNodeWithTag(UiAutomationIds.IDENTITY_ROW)
            .performScrollTo()
            .assertIsDisplayed()
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
            .performScrollTo()
            .assertIsDisplayed()
            .performClick()
        composeRule.runOnIdle {
            assertEquals(EXPECTED_PERMISSION_REQUEST_COUNT, requestCount)
        }
    }

    @Test
    fun readyReaderWithoutCardShowsReaderCard() {
        show(
            snapshot =
                UsbReaderSnapshot(
                    status = ReaderConnectionStatus.READY,
                    cardPresence = CardPresence.NOT_PRESENT,
                ),
        )

        composeRule
            .onNodeWithTag(UiAutomationIds.READER_CARD)
            .performScrollTo()
            .assertIsDisplayed()
        composeRule
            .onNodeWithTag(UiAutomationIds.IDENTITY_ROW)
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
            .performScrollTo()
            .assertIsDisplayed()
            .assertIsEnabled()
    }

    private fun show(
        snapshot: UsbReaderSnapshot,
        onRequestPermission: () -> Unit = {},
        browserCardService: AuthenticationCardService? = null,
    ) {
        composeRule.setContent {
            ReFineIdTheme {
                MainScreen(
                    snapshot = snapshot,
                    onRequestPermission = onRequestPermission,
                    browserCardService = browserCardService,
                )
            }
        }
    }

    private companion object {
        const val SYNTHETIC_HOLDER_NAME = "MEIKALAINEN MATTI SAKARI"
        const val EXPECTED_PERMISSION_REQUEST_COUNT = 1

        val READY_WITH_CARD =
            UsbReaderSnapshot(
                status = ReaderConnectionStatus.READY,
                cardPresence = CardPresence.PRESENT,
            )

        val INERT_BROWSER_CARD_SERVICE =
            object : AuthenticationCardService {
                override fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit) {
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

                override fun signAuthenticationDigest(
                    algorithm: AuthenticationSigningAlgorithm,
                    pin1: Pin1Submission,
                    digest: ByteArray,
                ): AuthenticationSignResult {
                    pin1.close()
                    return AuthenticationSignResult.Failure(
                        AuthenticationSignFailure.CARD_UNAVAILABLE,
                    )
                }
            }
    }
}
