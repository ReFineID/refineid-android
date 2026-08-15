package fi.refineid.android.keychain

import android.content.ComponentName
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import fi.refineid.android.ReFineIdApplication
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ExternalKeyProviderManifestInstrumentedTest {
    @Test
    fun providerIsExactlyExportedBehindTheKeyChainSignaturePermission() {
        val context = ApplicationProvider.getApplicationContext<ReFineIdApplication>()
        val packageManager = context.packageManager
        val component = ComponentName(context, ExternalKeyProviderService::class.java)
        val serviceInfo =
            packageManager.getServiceInfo(
                component,
                PackageManager.ComponentInfoFlags.of(NO_PACKAGE_MANAGER_FLAGS),
            )

        assertTrue(serviceInfo.exported)
        assertTrue(serviceInfo.enabled)
        assertEquals(KEYCHAIN_BIND_PERMISSION, serviceInfo.permission)

        val matchingServices =
            packageManager.queryIntentServices(
                Intent(PROVIDER_INTERFACE_ACTION).setPackage(context.packageName),
                PackageManager.ResolveInfoFlags.of(NO_PACKAGE_MANAGER_FLAGS),
            )
        assertEquals(
            listOf(component),
            matchingServices.map { result ->
                ComponentName(result.serviceInfo.packageName, result.serviceInfo.name)
            },
        )
    }

    @Test
    fun pinPromptIsPrivateAndExcludedFromRecents() {
        val context = ApplicationProvider.getApplicationContext<ReFineIdApplication>()
        val activityInfo =
            context.packageManager.getActivityInfo(
                ComponentName(context, ExternalKeyPinActivity::class.java),
                PackageManager.ComponentInfoFlags.of(NO_PACKAGE_MANAGER_FLAGS),
            )

        assertFalse(activityInfo.exported)
        assertTrue(activityInfo.flags and ActivityInfo.FLAG_EXCLUDE_FROM_RECENTS != NO_ACTIVITY_FLAGS)
        assertTrue(activityInfo.flags and ActivityInfo.FLAG_FINISH_ON_TASK_LAUNCH != NO_ACTIVITY_FLAGS)
    }

    private companion object {
        const val KEYCHAIN_BIND_PERMISSION =
            "com.android.keychain.permission.BIND_EXTERNAL_KEY_PROVIDER"
        const val PROVIDER_INTERFACE_ACTION =
            "com.android.keychain.external.IExternalKeyProviderService"
        const val NO_PACKAGE_MANAGER_FLAGS = 0L
        const val NO_ACTIVITY_FLAGS = 0
    }
}
