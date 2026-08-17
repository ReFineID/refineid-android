package fi.refineid.android.ui

import androidx.compose.runtime.Composable
import fi.refineid.android.core.AuthenticationCardService

/** Release has no embedded browser; normal-browser integration is a platform boundary. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun BrowserHarness(
    cardService: AuthenticationCardService?,
    pinCache: fi.refineid.android.core.AuthenticationPinCache? = null,
    nfcStatus: fi.refineid.android.nfc.NfcReaderStatus? = null,
    nfcPrimed: Boolean = false,
    onNfcConnect: (
        fi.refineid.android.core.CanSubmission?,
        fi.refineid.android.core.Pin1Submission,
    ) -> Unit = { _, _ -> },
    launcher: (@Composable (onOpen: () -> Unit) -> Unit)? = null,
) = Unit
