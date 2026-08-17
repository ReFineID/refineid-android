package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.InputTransformation
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.Pin2Submission

internal enum class DocumentSigningStatus {
    IDLE,
    READING,
    HOLD_CARD,
    SIGNING,
    SAVING,
    SIGNED,
    CERT_REVOKED,
    NO_CARD,
    WRONG_PIN,
    PIN_LOCKED,
    UNAVAILABLE,
    ERROR,
}

/**
 * The signing card mirrors the reference flow: choose a document, enter
 * the signature PIN inline, then commit. The card is not assumed to be
 * present — committing shows a hold prompt and waits for the tap — and
 * the access number is entered here only when no card has been primed.
 * The destination is chosen after signing, so nothing is picked until
 * there is a signed file to save.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DocumentSigningCard(
    hasDocument: Boolean,
    canRequired: Boolean,
    status: DocumentSigningStatus,
    onChooseDocument: () -> Unit,
    onSign: (Pin2Submission, CanSubmission?) -> Unit,
) {
    val canState = remember { TextFieldState() }
    val pinState = remember { TextFieldState() }
    DisposableEffect(canState, pinState) {
        onDispose {
            canState.clearText()
            pinState.clearText()
        }
    }
    val isWorking =
        status == DocumentSigningStatus.READING ||
            status == DocumentSigningStatus.HOLD_CARD ||
            status == DocumentSigningStatus.SIGNING ||
            status == DocumentSigningStatus.SAVING
    val canReady = !canRequired || CanSubmission.isComplete(canState.text)
    val pinReady = Pin2Submission.isComplete(pinState.text)
    val submit = {
        if (canReady && pinReady) {
            val can = if (canRequired) CanSubmission.from(canState.text) else null
            val pin2 = Pin2Submission.from(pinState.text)
            canState.clearText()
            pinState.clearText()
            onSign(pin2, can)
        }
        Unit
    }

    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.DOCUMENT_SIGNING_CARD),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = DOCUMENT_CARD_ELEVATION),
        shape = RoundedCornerShape(DOCUMENT_CARD_CORNER_RADIUS),
    ) {
        Column(
            modifier = Modifier.padding(DOCUMENT_CARD_PADDING),
            verticalArrangement = Arrangement.spacedBy(DOCUMENT_ITEM_SPACING),
        ) {
            Text(
                text = stringResource(R.string.sign),
                fontWeight = FontWeight.SemiBold,
                style = MaterialTheme.typography.titleLarge,
            )
            Button(
                onClick = onChooseDocument,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag(UiAutomationIds.DOCUMENT_CHOOSE_ACTION),
                enabled = !isWorking,
            ) {
                Text(stringResource(R.string.choose_pdf))
            }
            if (hasDocument) {
                Text(
                    text = stringResource(R.string.pdf_selected),
                    modifier = Modifier.testTag(UiAutomationIds.DOCUMENT_SELECTED_STATUS),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (canRequired) {
                    SecureTextField(
                        state = canState,
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .testTag(UiAutomationIds.DOCUMENT_CAN_FIELD),
                        enabled = !isWorking,
                        label = { Text(stringResource(R.string.can)) },
                        inputTransformation = CanInputTransformation,
                        textObfuscationMode = TextObfuscationMode.Hidden,
                        keyboardOptions =
                            KeyboardOptions(
                                autoCorrectEnabled = false,
                                keyboardType = KeyboardType.NumberPassword,
                                imeAction = ImeAction.Next,
                            ),
                    )
                }
                SecureTextField(
                    state = pinState,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.PIN2_FIELD),
                    enabled = !isWorking,
                    label = { Text(stringResource(R.string.signature_pin2)) },
                    inputTransformation = Pin2InputTransformation,
                    textObfuscationMode = TextObfuscationMode.Hidden,
                    keyboardOptions =
                        KeyboardOptions(
                            autoCorrectEnabled = false,
                            keyboardType = KeyboardType.NumberPassword,
                            imeAction = ImeAction.Done,
                        ),
                )
                Button(
                    onClick = submit,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.DOCUMENT_SIGN_ACTION),
                    enabled = !isWorking && canReady && pinReady,
                ) {
                    Text(stringResource(R.string.sign_document))
                }
            }
            DocumentSigningStatusText(status)
        }
    }
}

internal val Pin2InputTransformation =
    InputTransformation {
        if (!Pin2Submission.acceptsEntry(asCharSequence())) {
            revertAllChanges()
        }
    }

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DocumentSigningStatusText(status: DocumentSigningStatus) {
    val text =
        when (status) {
            DocumentSigningStatus.IDLE -> null
            DocumentSigningStatus.READING -> stringResource(R.string.checking)
            DocumentSigningStatus.HOLD_CARD -> stringResource(R.string.hold_card)
            DocumentSigningStatus.SIGNING -> stringResource(R.string.signing)
            DocumentSigningStatus.SAVING -> stringResource(R.string.saving)
            DocumentSigningStatus.SIGNED -> stringResource(R.string.signed)
            DocumentSigningStatus.CERT_REVOKED -> stringResource(R.string.signed_cert_revoked)
            DocumentSigningStatus.NO_CARD -> stringResource(R.string.no_card)
            DocumentSigningStatus.WRONG_PIN -> stringResource(R.string.wrong_pin)
            DocumentSigningStatus.PIN_LOCKED -> stringResource(R.string.pin_locked)
            DocumentSigningStatus.UNAVAILABLE -> stringResource(R.string.unavailable)
            DocumentSigningStatus.ERROR -> stringResource(R.string.error)
        }
    if (text != null) {
        Text(
            text = text,
            modifier = Modifier.testTag(UiAutomationIds.DOCUMENT_SIGNING_STATUS),
            color =
                if (status == DocumentSigningStatus.SIGNED) {
                    DOCUMENT_SUCCESS_COLOR
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

private val DOCUMENT_CARD_PADDING = 20.dp
private val DOCUMENT_ITEM_SPACING = 14.dp
private val DOCUMENT_CARD_CORNER_RADIUS = 22.dp
private val DOCUMENT_CARD_ELEVATION = 2.dp
private val DOCUMENT_SUCCESS_COLOR = Color(0xFF168447)
