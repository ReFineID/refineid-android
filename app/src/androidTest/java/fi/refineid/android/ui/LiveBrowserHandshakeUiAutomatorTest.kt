package fi.refineid.android.ui

import android.content.ComponentName
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.uiAutomator
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
internal class LiveBrowserHandshakeUiAutomatorTest {
    @Test
    fun liveCardReachesTheBrowserPinPromptWithoutSubmittingIt() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        assumeTrue(
            "enable the opt-in live browser handshake",
            InstrumentationRegistry.getArguments().getString(LIVE_TEST_ARGUMENT) ==
                LIVE_TEST_ENABLED_VALUE,
        )
        val launchIntent =
            Intent
                .makeMainActivity(
                    ComponentName(
                        instrumentation.targetContext,
                        TARGET_ACTIVITY_CLASS,
                    ),
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        instrumentation.targetContext.startActivity(launchIntent)

        uiAutomator {
            try {
                waitForAppToBeVisible(TARGET_PACKAGE)
                val readerState =
                    onElement(CARD_READY_TIMEOUT_MILLISECONDS) {
                        viewIdResourceName == UiAutomationIds.AUTHENTICATION_CARD ||
                            viewIdResourceName == UiAutomationIds.READER_ACTION
                    }
                if (readerState.resourceName == UiAutomationIds.READER_ACTION) {
                    readerState.click()
                    onElement(USB_PERMISSION_TIMEOUT_MILLISECONDS) {
                        packageName?.toString() == SYSTEM_UI_PACKAGE &&
                            viewIdResourceName == ANDROID_CONFIRM_BUTTON_RESOURCE
                    }.click()
                }
                onElement(CARD_READY_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.AUTHENTICATION_CARD
                }
                onElement(CARD_READY_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.BROWSER_ACTION
                }.click()
                onElement(CLIENT_CERTIFICATE_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.BROWSER_PIN1_FIELD
                }
            } finally {
                if (
                    onElementOrNull(CLEANUP_TIMEOUT_MILLISECONDS) {
                        viewIdResourceName == UiAutomationIds.BROWSER_PIN1_FIELD
                    } != null
                ) {
                    pressBack()
                }
                onElementOrNull(CLEANUP_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.BROWSER_CLOSE_ACTION
                }?.click()
            }
        }
    }

    private companion object {
        const val TARGET_PACKAGE = "fi.refineid.android"
        const val TARGET_ACTIVITY_CLASS = "$TARGET_PACKAGE.MainActivity"
        const val SYSTEM_UI_PACKAGE = "com.android.systemui"
        const val ANDROID_CONFIRM_BUTTON_RESOURCE = "android:id/button1"
        const val LIVE_TEST_ARGUMENT = "refineidLiveBrowserHandshake"
        const val LIVE_TEST_ENABLED_VALUE = "true"
        const val CARD_READY_TIMEOUT_MILLISECONDS = 15_000L
        const val USB_PERMISSION_TIMEOUT_MILLISECONDS = 10_000L
        const val CLIENT_CERTIFICATE_TIMEOUT_MILLISECONDS = 30_000L
        const val CLEANUP_TIMEOUT_MILLISECONDS = 2_000L
    }
}
