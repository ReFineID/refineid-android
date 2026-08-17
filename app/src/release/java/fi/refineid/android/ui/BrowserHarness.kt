package fi.refineid.android.ui

import androidx.compose.runtime.Composable
import fi.refineid.android.core.AuthenticationCardService

/** Release has no embedded browser; normal-browser integration is a platform boundary. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun BrowserHarness(cardService: AuthenticationCardService?) = Unit
