package fi.refineid.android.ui

import androidx.compose.runtime.Composable
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.usb.UsbReaderSnapshot

/** Release has no embedded browser; normal-browser integration is a platform boundary. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun BrowserHarness(
    snapshot: UsbReaderSnapshot,
    cardService: AuthenticationCardService?,
) = Unit
