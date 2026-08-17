package fi.refineid.android.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.browser.BundledIssuerCertificates
import fi.refineid.android.diagnostics.AppTrace
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
internal fun DocumentValidationHarness() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf<DocumentValidationUiState>(DocumentValidationUiState.Idle) }
    val validator =
        remember(context) {
            DocumentValidator(
                trustAnchors = runCatching { BundledIssuerCertificates.load(context) }.getOrDefault(emptyList()),
            )
        }
    val picker =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri == null) {
                return@rememberLauncherForActivityResult
            }
            state = DocumentValidationUiState.Working
            AppTrace.documentValidationStarted()
            scope.launch {
                state =
                    try {
                        val bytes =
                            withContext(Dispatchers.IO) {
                                runInterruptible { readDocument(context.contentResolver, uri) }
                            }
                        DocumentValidationUiState.Done(validator.validate(bytes))
                    } catch (_: IOException) {
                        DocumentValidationUiState.ReadFailed
                    }
                AppTrace.documentValidationCompleted(state is DocumentValidationUiState.Done)
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
            Button(
                onClick = { picker.launch(arrayOf(PDF_MIME_TYPE)) },
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag(UiAutomationIds.DOCUMENT_VERIFY_ACTION),
            ) {
                Text(stringResource(R.string.verify_document))
            }
            DocumentValidationStatus(state)
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DocumentValidationStatus(state: DocumentValidationUiState) {
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
            DocumentValidationVerdict(state.result)
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DocumentValidationVerdict(result: DocumentValidationResult) {
    when (result) {
        DocumentValidationResult.Unsigned -> {
            Text(stringResource(R.string.document_unsigned))
        }

        DocumentValidationResult.Malformed -> {
            Text(stringResource(R.string.document_malformed), color = MaterialTheme.colorScheme.error)
        }

        is DocumentValidationResult.Completed -> {
            val headline =
                if (result.isValid) {
                    stringResource(R.string.document_valid)
                } else {
                    stringResource(R.string.document_invalid)
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
                modifier = Modifier.testTag(UiAutomationIds.DOCUMENT_VALIDATION_STATUS),
            )
            result.signatures.forEachIndexed { index, verdict ->
                Text(
                    text =
                        stringResource(R.string.document_signature_ordinal, index + 1) +
                            (verdict.signerCommonName?.let { " · $it" } ?: "") +
                            (verdict.signingTime?.let { " · $it" } ?: ""),
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (!verdict.coversWholeDocument) {
                    Text(
                        stringResource(R.string.document_partial_coverage),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
    }
}

private fun readDocument(
    contentResolver: android.content.ContentResolver,
    uri: Uri,
): ByteArray =
    contentResolver.openInputStream(uri)?.use { it.readBytes() }
        ?: throw IOException("document could not be opened")

private const val PDF_MIME_TYPE = "application/pdf"
private val VALIDATION_CARD_PADDING = 20.dp
private val VALIDATION_CARD_SPACING = 12.dp
private val VALIDATION_CARD_ELEVATION = 2.dp
private val VALIDATION_VALID_COLOR =
    androidx.compose.ui.graphics
        .Color(0xFF168447)
