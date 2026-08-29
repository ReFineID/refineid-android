package fi.refineid.android.ui

import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.browser.BundledIssuerCertificates
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.document.DocumentSignatureVerdict
import fi.refineid.android.document.DocumentValidationResult
import fi.refineid.android.document.DocumentValidator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import java.io.IOException

private sealed interface DocumentValidationUiState {
    data object Idle : DocumentValidationUiState

    data object Working : DocumentValidationUiState

    data class Done(
        val result: DocumentValidationResult,
    ) : DocumentValidationUiState

    data object ReadFailed : DocumentValidationUiState
}

/** Debug-only card-free PAdES verification: pick a signed PDF, show the verdict. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DocumentValidationHarness(initialUri: Uri? = null) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf<DocumentValidationUiState>(DocumentValidationUiState.Idle) }
    var loadedBytes by remember { mutableStateOf<ByteArray?>(null) }
    var isCheckingRevocationOnline by remember { mutableStateOf(false) }

    val validator =
        remember(context) {
            DocumentValidator(
                trustAnchors = runCatching { BundledIssuerCertificates.load(context) }.getOrDefault(emptyList()),
            )
        }

    LaunchedEffect(initialUri) {
        if (initialUri != null) {
            state = DocumentValidationUiState.Working
            AppTrace.documentValidationStarted()
            scope.launch {
                state =
                    try {
                        val bytes =
                            withContext(Dispatchers.IO) {
                                runInterruptible { readDocument(context.contentResolver, initialUri) }
                            }
                        loadedBytes = bytes
                        val result =
                            withContext(Dispatchers.IO) {
                                validator.validate(bytes)
                            }
                        DocumentValidationUiState.Done(result)
                    } catch (_: IOException) {
                        DocumentValidationUiState.ReadFailed
                    }
                AppTrace.documentValidationCompleted(state is DocumentValidationUiState.Done)
            }
        }
    }

    val onCheckRevocationOnline: () -> Unit = {
        val bytes = loadedBytes
        if (bytes != null && !isCheckingRevocationOnline) {
            isCheckingRevocationOnline = true
            scope.launch {
                val newResult =
                    withContext(Dispatchers.IO) {
                        validator.validate(bytes)
                    }
                state = DocumentValidationUiState.Done(newResult)
                isCheckingRevocationOnline = false
            }
        }
    }

    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.DOCUMENT_VALIDATION_CARD),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = VALIDATION_CARD_ELEVATION),
    ) {
        Column(
            modifier = Modifier.padding(VALIDATION_CARD_PADDING),
            verticalArrangement = Arrangement.spacedBy(VALIDATION_CARD_SPACING),
        ) {
            DocumentValidationStatus(
                state = state,
                isCheckingRevocationOnline = isCheckingRevocationOnline,
                onCheckRevocationOnline = onCheckRevocationOnline,
            )
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DocumentValidationStatus(
    state: DocumentValidationUiState,
    isCheckingRevocationOnline: Boolean,
    onCheckRevocationOnline: () -> Unit,
) {
    when (state) {
        DocumentValidationUiState.Idle -> {
            // Nothing to show before a document is picked.
        }

        DocumentValidationUiState.Working -> {
            Text(stringResource(R.string.checking))
        }

        DocumentValidationUiState.ReadFailed -> {
            Text(stringResource(R.string.error), color = MaterialTheme.colorScheme.error)
        }

        is DocumentValidationUiState.Done -> {
            DocumentValidationVerdict(
                result = state.result,
                isCheckingRevocationOnline = isCheckingRevocationOnline,
                onCheckRevocationOnline = onCheckRevocationOnline,
            )
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DocumentValidationVerdict(
    result: DocumentValidationResult,
    isCheckingRevocationOnline: Boolean,
    onCheckRevocationOnline: () -> Unit,
) {
    when (result) {
        DocumentValidationResult.Unsigned -> {
            Text(stringResource(R.string.document_unsigned))
        }

        DocumentValidationResult.Malformed -> {
            Text(stringResource(R.string.document_malformed), color = MaterialTheme.colorScheme.error)
        }

        is DocumentValidationResult.Completed -> {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                val headline =
                    when {
                        result.isRevoked -> {
                            stringResource(R.string.signed_cert_revoked)
                        }

                        result.isValid && result.isRevocationChecked -> {
                            stringResource(
                                R.string.document_valid_revocation_checked,
                            )
                        }

                        result.isValid -> {
                            stringResource(R.string.document_valid)
                        }

                        else -> {
                            stringResource(R.string.document_invalid)
                        }
                    }
                Text(
                    text = headline,
                    color =
                        if (result.isValid) {
                            VALIDATION_VALID_COLOR
                        } else {
                            MaterialTheme.colorScheme.error
                        },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.testTag(UiAutomationIds.DOCUMENT_VALIDATION_STATUS),
                )

                result.signatures.forEachIndexed { index, verdict ->
                    SignatureDetailsCard(index = index, verdict = verdict)
                }

                if (!result.isRevocationChecked && !result.isRevoked) {
                    if (isCheckingRevocationOnline) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(top = 4.dp),
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                            )
                            Text(
                                text = stringResource(R.string.checking_revocation_online),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                    } else {
                        OutlinedButton(
                            onClick = onCheckRevocationOnline,
                            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                        ) {
                            Text(stringResource(R.string.check_revocation_online))
                        }
                    }
                }
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun SignatureDetailsCard(
    index: Int,
    verdict: DocumentSignatureVerdict,
) {
    val ordinalTitle =
        if (verdict.isDocumentTimestamp) {
            stringResource(R.string.document_timestamp_ordinal, index + 1)
        } else {
            stringResource(R.string.document_signature_ordinal, index + 1)
        }

    OutlinedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors =
            CardDefaults.outlinedCardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
            ),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = ordinalTitle,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                )
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    if (verdict.isValid) {
                        StatusChip(
                            text = stringResource(R.string.signature_status_valid),
                            color = VALIDATION_VALID_COLOR,
                        )
                    } else {
                        StatusChip(
                            text = stringResource(R.string.signature_status_invalid),
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    if (verdict.chainTrusted && !verdict.isDocumentTimestamp) {
                        StatusChip(
                            text = stringResource(R.string.signature_status_trusted),
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
            }

            if (!verdict.signerCommonName.isNullOrBlank()) {
                DetailRow(
                    label = stringResource(R.string.signature_details_signer),
                    value = verdict.signerCommonName,
                )
            }
            if (!verdict.signerIssuer.isNullOrBlank()) {
                DetailRow(
                    label = stringResource(R.string.signature_details_issuer),
                    value = verdict.signerIssuer,
                )
            }
            if (!verdict.signingTime.isNullOrBlank()) {
                DetailRow(
                    label = stringResource(R.string.signature_details_time),
                    value = formatDisplayTime(verdict.signingTime) ?: verdict.signingTime,
                )
            }

            if (!verdict.coversWholeDocument) {
                Text(
                    stringResource(R.string.document_partial_coverage),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium,
                )
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun StatusChip(
    text: String,
    color: Color,
) {
    Box(
        modifier =
            Modifier
                .background(
                    color = color.copy(alpha = 0.12f),
                    shape = RoundedCornerShape(8.dp),
                ).padding(horizontal = 8.dp, vertical = 2.dp),
    ) {
        Text(
            text = text,
            color = color,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DetailRow(
    label: String,
    value: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = "$label:",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.widthIn(min = 60.dp),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Normal,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

private fun formatDisplayTime(raw: String?): String? {
    if (raw == null) return null
    if (raw.length == UTC_TIME_LENGTH && raw.endsWith('Z') && raw.all { it.isDigit() || it == 'Z' }) {
        val datePart = "20" + raw.substring(0, 2) + "-" + raw.substring(2, 4) + "-" + raw.substring(4, 6)
        val timePart = raw.substring(6, 8) + ":" + raw.substring(8, 10) + ":" + raw.substring(10, 12)
        return "$datePart $timePart UTC"
    }
    if (raw.length == GENERALIZED_TIME_LENGTH && raw.endsWith('Z') && raw.all { it.isDigit() || it == 'Z' }) {
        val datePart = raw.substring(0, 4) + "-" + raw.substring(4, 6) + "-" + raw.substring(6, 8)
        val timePart = raw.substring(8, 10) + ":" + raw.substring(10, 12) + ":" + raw.substring(12, 14)
        return "$datePart $timePart UTC"
    }
    return raw
}

private fun readDocument(
    contentResolver: android.content.ContentResolver,
    uri: Uri,
): ByteArray =
    contentResolver.openInputStream(uri)?.use { it.readBytes() }
        ?: throw IOException("document could not be opened")

private const val UTC_TIME_LENGTH = 13
private const val GENERALIZED_TIME_LENGTH = 15
private const val PDF_MIME_TYPE = "application/pdf"
private val VALIDATION_CARD_PADDING = 20.dp
private val VALIDATION_CARD_SPACING = 12.dp
private val VALIDATION_CARD_ELEVATION = 2.dp
private val VALIDATION_VALID_COLOR = Color(0xFF168447)
