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
import fi.refineid.android.core.Pin2Submission

internal enum class DocumentSigningStatus {
    IDLE,
    READING,
    SIGNING,
    SAVING,
    SIGNED,
    WRONG_PIN,
    PIN_LOCKED,
    UNAVAILABLE,
    ERROR,
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DocumentSigningCard(
    hasDocument: Boolean,
    hasDestination: Boolean,
    status: DocumentSigningStatus,
    onChooseDocument: () -> Unit,
    onChooseDestination: () -> Unit,
    onSign: (Pin2Submission) -> Unit,
) {
    val pinState = remember { TextFieldState() }
    DisposableEffect(pinState) {
        onDispose(pinState::clearText)
    }
    val isWorking =
        status == DocumentSigningStatus.READING ||
            status == DocumentSigningStatus.SIGNING ||
            status == DocumentSigningStatus.SAVING
    val submit = {
        val submission =
            if (Pin2Submission.isComplete(pinState.text)) {
                Pin2Submission.from(pinState.text)
            } else {
                null
            }
        pinState.clearText()
        submission?.let(onSign)
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
                text = stringResource(R.string.pdf),
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
                Button(
                    onClick = onChooseDestination,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.DOCUMENT_DESTINATION_ACTION),
                    enabled = !isWorking,
                ) {
                    Text(stringResource(R.string.save_as))
                }
            }
            if (hasDocument && hasDestination) {
                SecureTextField(
                    state = pinState,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.PIN2_FIELD),
                    enabled = !isWorking,
                    label = { Text(stringResource(R.string.pin2)) },
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
                    enabled = !isWorking && Pin2Submission.isComplete(pinState.text),
                ) {
                    Text(stringResource(R.string.sign_pdf))
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
            DocumentSigningStatus.SIGNING -> stringResource(R.string.signing)
            DocumentSigningStatus.SAVING -> stringResource(R.string.saving)
            DocumentSigningStatus.SIGNED -> stringResource(R.string.signed)
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
