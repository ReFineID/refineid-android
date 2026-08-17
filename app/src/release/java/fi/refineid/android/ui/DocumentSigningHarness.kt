package fi.refineid.android.ui

import androidx.compose.runtime.Composable
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.settings.TimestampAuthorityRepository

/** Archival document signing remains absent from release until every LTA stage is present. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DocumentSigningHarness(
    cardReady: Boolean,
    cardService: QualifiedCardService?,
    timestampAuthorityRepository: TimestampAuthorityRepository?,
) = Unit
