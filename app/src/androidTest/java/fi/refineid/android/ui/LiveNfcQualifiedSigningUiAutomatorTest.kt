package fi.refineid.android.ui

import android.content.ComponentName
import android.content.Intent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.Direction
import androidx.test.uiautomator.StaleObjectException
import androidx.test.uiautomator.UiAutomatorTestScope
import androidx.test.uiautomator.uiAutomator
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Opt-in live check that a holder can sign a document over NFC through
 * the real UI — no service back door. UI Automator drives the Document
 * section exactly as a person would: choose the PDF, type the signature
 * PIN inline, commit, tap the card when the hold prompt waits for it,
 * and save the signed file. A `Signed` status is the pass.
 *
 * The document is a PDF pushed to the shared Downloads folder before the
 * run; the signature PIN (and access number, when the card is not
 * primed) arrive as instrumentation arguments and never live in the
 * repository.
 */
@RunWith(AndroidJUnit4::class)
internal class LiveNfcQualifiedSigningUiAutomatorTest {
    @Test(timeout = LIVE_TEST_TIMEOUT_MILLISECONDS)
    fun liveHolderSignsADocumentOverNfcThroughTheUi() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(
            "enable the opt-in live NFC document-signing check",
            arguments.getString(LIVE_TEST_ARGUMENT) == LIVE_TEST_ENABLED_VALUE,
        )
        val pin2 = arguments.getString(PIN2_ARGUMENT)
        val can = arguments.getString(CAN_ARGUMENT)
        assumeTrue("supply PIN2 to sign", !pin2.isNullOrEmpty())

        val launchIntent =
            Intent
                .makeMainActivity(
                    ComponentName(instrumentation.targetContext, TARGET_ACTIVITY_CLASS),
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        instrumentation.targetContext.startActivity(launchIntent)

        uiAutomator {
            waitForAppToBeVisible(TARGET_PACKAGE)

            // The grouped home pushes signing to its own screen; open it
            // from the Document section's Sign row.
            revealBySwiping(UiAutomationIds.SIGN_ROW)
            onElement(ELEMENT_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.SIGN_ROW
            }.click()

            // Choose the document through the system file picker. The
            // media-scanned document shows in the picker's default view, so
            // no fragile folder navigation is needed; a list layout makes
            // each file a full-width clickable row, so tapping the name
            // reliably selects it rather than a grid tile.
            onElement(ELEMENT_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.DOCUMENT_CHOOSE_ACTION
            }.click()
            onElementOrNull(SHORT_TIMEOUT_MILLISECONDS) {
                contentDescription?.toString() == LIST_VIEW_LABEL
            }?.click()
            clickStable(PICKER_TIMEOUT_MILLISECONDS) {
                text?.toString()?.contains(DOCUMENT_NAME) == true
            }

            // The selected document reveals the inline credential fields.
            // Scroll the whole card up so its fields sit above the keyboard.
            onElement(ELEMENT_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.DOCUMENT_SELECTED_STATUS
            }
            revealBySwiping(UiAutomationIds.DOCUMENT_SIGN_ACTION)
            if (!can.isNullOrEmpty()) {
                onElementOrNull(SHORT_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.DOCUMENT_CAN_FIELD
                }?.setText(can)
            }
            onElement(ELEMENT_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.PIN2_FIELD
            }.setText(checkNotNull(pin2))

            // Commit; the hold prompt then waits for the card tap.
            onElement(ELEMENT_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.DOCUMENT_SIGN_ACTION && isEnabled
            }.click()

            // After the tap the card computes its signature. A valid
            // certificate reaches the save panel; a revoked one — every test
            // card, since DVV centrally revoked the pre-2023 signature
            // certificates — must stop with the certificate-revoked refusal
            // and hand out no file. Both outcomes exercise the card path;
            // only the refusal is reachable with these cards.
            val terminal =
                onElement(SIGN_TIMEOUT_MILLISECONDS) {
                    text?.toString()?.equals(SAVE_LABEL, ignoreCase = true) == true ||
                        (
                            viewIdResourceName == UiAutomationIds.DOCUMENT_SIGNING_STATUS &&
                                text?.toString() == REVOKED_STATUS
                        )
                }
            if (terminal.text?.equals(SAVE_LABEL, ignoreCase = true) == true) {
                terminal.click()
                onElement(SAVE_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.DOCUMENT_SIGNING_STATUS &&
                        text?.toString()?.equals(SIGNED_LABEL, ignoreCase = true) == true
                }
            }
        }
    }

    /** Click the matched element, re-finding it if it goes stale mid-tap. */
    private fun UiAutomatorTestScope.clickStable(
        timeout: Long,
        predicate: AccessibilityNodeInfo.() -> Boolean,
    ) {
        repeat(STALE_RETRIES) {
            try {
                onElement(timeout) { predicate() }.click()
                return
            } catch (_: StaleObjectException) {
                // The element changed between find and click; re-find below.
            }
        }
        onElement(timeout) { predicate() }.click()
    }

    /** Swipe the scrollable home up until the tagged control is on screen. */
    private fun UiAutomatorTestScope.revealBySwiping(resourceId: String) {
        var found =
            onElementOrNull(SHORT_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == resourceId
            }
        var scrolls = 0
        while (found == null && scrolls < MAX_SCROLLS) {
            onElement(ELEMENT_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.MAIN_SCREEN
            }.swipe(Direction.UP, SCROLL_PERCENT)
            scrolls += 1
            found =
                onElementOrNull(SHORT_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == resourceId
                }
        }
    }

    private companion object {
        const val TARGET_PACKAGE = "fi.refineid.android"
        const val TARGET_ACTIVITY_CLASS = "$TARGET_PACKAGE.MainActivity"
        const val LIVE_TEST_ARGUMENT = "refineidLiveNfcSigning"
        const val LIVE_TEST_ENABLED_VALUE = "true"
        const val PIN2_ARGUMENT = "refineidNfcPin2"
        const val CAN_ARGUMENT = "refineidNfcCan"
        const val DOCUMENT_NAME = "refineid-test"
        const val LIST_VIEW_LABEL = "List view"
        const val STALE_RETRIES = 3
        const val SAVE_LABEL = "Save"
        const val SIGNED_LABEL = "Signed"
        const val REVOKED_STATUS = "Signature certificate revoked — no valid signature"
        const val ELEMENT_TIMEOUT_MILLISECONDS = 15_000L
        const val SHORT_TIMEOUT_MILLISECONDS = 3_000L
        const val PICKER_TIMEOUT_MILLISECONDS = 20_000L
        const val SIGN_TIMEOUT_MILLISECONDS = 60_000L
        const val SAVE_TIMEOUT_MILLISECONDS = 120_000L
        const val LIVE_TEST_TIMEOUT_MILLISECONDS = 300_000L
        const val MAX_SCROLLS = 4
        const val SCROLL_PERCENT = 0.6f
    }
}
