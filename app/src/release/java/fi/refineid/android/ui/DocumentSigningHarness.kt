package fi.refineid.android.ui

import androidx.compose.runtime.Composable
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.settings.TimestampAuthorityRepository

/**
 * How a signing request reaches the card. Present in every build so the
 * home screen can wire it, though release signing stays absent until
 * every long-term-archival stage ships.
 */
internal class DocumentSignTap(
    val begin: (canBytes: ByteArray?, onReady: () -> Unit, onNoCard: () -> Unit) -> Unit,
    val end: () -> Unit,
    val canRequired: Boolean,
)

/** Archival document signing remains absent from release until every LTA stage is present. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DocumentSigningHarness(
    signingAvailable: Boolean,
    cardService: QualifiedCardService?,
    tap: DocumentSignTap?,
    timestampAuthorityRepository: TimestampAuthorityRepository?,
) = Unit
