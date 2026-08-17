// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import androidx.compose.runtime.Composable
import fi.refineid.android.settings.TimestampAuthorityRepository

/** Timestamp-authority settings remain hidden while release document signing is absent. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun TimestampAuthoritySettingsHarness(
    repository: TimestampAuthorityRepository?,
    launcher: (@Composable (onOpen: () -> Unit) -> Unit)? = null,
) = Unit
