package fi.refineid.android.ui

import android.content.ComponentName
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.uiAutomator
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
internal class MainActivityUiAutomatorTest {
    @Test
    fun launchesAndExposesTheStableAutomationSurface() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
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
            waitForAppToBeVisible(TARGET_PACKAGE)
            onElement { viewIdResourceName == UiAutomationIds.MAIN_SCREEN }
            onElement { viewIdResourceName == UiAutomationIds.READER_CARD }
        }
    }

    private companion object {
        const val TARGET_PACKAGE = "fi.refineid.android"
        const val TARGET_ACTIVITY_CLASS = "$TARGET_PACKAGE.MainActivity"
    }
}
