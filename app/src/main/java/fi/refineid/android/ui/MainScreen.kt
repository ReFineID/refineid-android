package fi.refineid.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.InputTransformation
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.browser.BrowserCardService
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.diagnostics.BuildDiagnostics
import fi.refineid.android.usb.AuthenticationStatus
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun MainScreen(
    snapshot: UsbReaderSnapshot,
    onRequestPermission: () -> Unit,
    onAuthenticate: (Pin1Submission) -> Unit,
    browserCardService: BrowserCardService? = null,
) {
    Scaffold(
        modifier =
            Modifier
                .semantics { testTagsAsResourceId = true }
                .testTag(UiAutomationIds.MAIN_SCREEN),
    ) { contentPadding ->
        Column(
            modifier =
                Modifier
                    .fillMaxSize()
                    .padding(contentPadding)
                    .padding(
                        horizontal = SCREEN_HORIZONTAL_PADDING,
                        vertical = SCREEN_VERTICAL_PADDING,
                    ),
            verticalArrangement = Arrangement.spacedBy(SCREEN_ITEM_SPACING),
        ) {
            Text(
                text = stringResource(R.string.app_name),
                style = MaterialTheme.typography.headlineLarge,
                fontWeight = FontWeight.SemiBold,
            )

            ReaderCard(
                snapshot = snapshot,
                onRequestPermission = onRequestPermission,
            )

            if (
                BuildDiagnostics.MANUAL_AUTHENTICATION_ENABLED &&
                snapshot.status == ReaderConnectionStatus.READY &&
                snapshot.cardPresence == CardPresence.PRESENT
            ) {
                AuthenticationCard(
                    status = snapshot.authenticationStatus,
                    onAuthenticate = onAuthenticate,
                )
            }

            BrowserHarness(
                snapshot = snapshot,
                cardService = browserCardService,
            )
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun AuthenticationCard(
    status: AuthenticationStatus,
    onAuthenticate: (Pin1Submission) -> Unit,
) {
    val pinState = remember { TextFieldState() }
    DisposableEffect(pinState) {
        onDispose(pinState::clearText)
    }
    val isSigning = status == AuthenticationStatus.SIGNING
    val submit = {
        val submission =
            if (Pin1Submission.isComplete(pinState.text)) {
                Pin1Submission.from(pinState.text)
            } else {
                null
            }
        pinState.clearText()
        submission?.let(onAuthenticate)
        Unit
    }

    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.AUTHENTICATION_CARD),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = CARD_ELEVATION),
        shape = RoundedCornerShape(CARD_CORNER_RADIUS),
    ) {
        Column(
            modifier = Modifier.padding(CARD_PADDING),
            verticalArrangement = Arrangement.spacedBy(CARD_ITEM_SPACING),
        ) {
            Text(
                text = stringResource(R.string.authentication),
                fontWeight = FontWeight.SemiBold,
                style = MaterialTheme.typography.titleLarge,
            )
            SecureTextField(
                state = pinState,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag(UiAutomationIds.PIN1_FIELD),
                enabled = !isSigning,
                label = { Text(stringResource(R.string.pin1)) },
                inputTransformation = Pin1InputTransformation,
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
                        .testTag(UiAutomationIds.AUTHENTICATION_ACTION),
                enabled = !isSigning && Pin1Submission.isComplete(pinState.text),
            ) {
                Text(stringResource(R.string.sign))
            }
            AuthenticationStatusText(status)
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun AuthenticationStatusText(status: AuthenticationStatus) {
    val text =
        when (status) {
            AuthenticationStatus.IDLE -> null
            AuthenticationStatus.SIGNING -> stringResource(R.string.signing)
            AuthenticationStatus.SUCCEEDED -> stringResource(R.string.signed)
            AuthenticationStatus.WRONG_PIN -> stringResource(R.string.wrong_pin)
            AuthenticationStatus.PIN_LOCKED -> stringResource(R.string.pin_locked)
            AuthenticationStatus.REFUSED -> stringResource(R.string.unavailable)
            AuthenticationStatus.ERROR -> stringResource(R.string.error)
        }
    if (text != null) {
        Text(
            text = text,
            modifier = Modifier.testTag(UiAutomationIds.AUTHENTICATION_STATUS),
            color =
                if (status == AuthenticationStatus.SUCCEEDED) {
                    SUCCESS_STATUS_COLOR
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

internal val Pin1InputTransformation =
    InputTransformation {
        if (!Pin1Submission.acceptsEntry(asCharSequence())) {
            revertAllChanges()
        }
    }

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun ReaderCard(
    snapshot: UsbReaderSnapshot,
    onRequestPermission: () -> Unit,
) {
    val statusColor =
        when (snapshot.status) {
            ReaderConnectionStatus.READY -> SUCCESS_STATUS_COLOR
            ReaderConnectionStatus.PERMISSION_REQUEST_FAILED -> MaterialTheme.colorScheme.error
            ReaderConnectionStatus.CARD_ERROR -> MaterialTheme.colorScheme.error
            ReaderConnectionStatus.TRANSPORT_ERROR -> MaterialTheme.colorScheme.error
            ReaderConnectionStatus.PERMISSION_REQUIRED -> PERMISSION_STATUS_COLOR
            ReaderConnectionStatus.CHECKING -> MaterialTheme.colorScheme.primary
            ReaderConnectionStatus.NOT_CONNECTED -> MaterialTheme.colorScheme.onSurfaceVariant
        }
    val statusTitle =
        when (snapshot.status) {
            ReaderConnectionStatus.READY -> {
                stringResource(R.string.ready)
            }

            ReaderConnectionStatus.PERMISSION_REQUIRED -> {
                stringResource(R.string.permission_required)
            }

            ReaderConnectionStatus.PERMISSION_REQUEST_FAILED -> {
                stringResource(R.string.access_failed)
            }

            ReaderConnectionStatus.CARD_ERROR -> {
                stringResource(R.string.error)
            }

            ReaderConnectionStatus.TRANSPORT_ERROR -> {
                stringResource(R.string.error)
            }

            ReaderConnectionStatus.CHECKING -> {
                stringResource(R.string.checking)
            }

            ReaderConnectionStatus.NOT_CONNECTED -> {
                stringResource(R.string.not_connected)
            }
        }

    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.READER_CARD),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = CARD_ELEVATION),
        shape = RoundedCornerShape(CARD_CORNER_RADIUS),
    ) {
        Column(
            modifier = Modifier.padding(CARD_PADDING),
            verticalArrangement = Arrangement.spacedBy(CARD_ITEM_SPACING),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(READER_STATUS_ITEM_SPACING),
            ) {
                Box(
                    modifier =
                        Modifier
                            .size(READER_STATUS_INDICATOR_SIZE)
                            .background(statusColor, CircleShape),
                )
                Column {
                    Text(
                        text = stringResource(R.string.usb_reader),
                        fontWeight = FontWeight.SemiBold,
                        style = MaterialTheme.typography.titleLarge,
                    )
                    Text(
                        text = statusTitle,
                        color = statusColor,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }

            if (
                snapshot.status == ReaderConnectionStatus.READY &&
                snapshot.cardPresence != null
            ) {
                HorizontalDivider()
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = stringResource(R.string.card),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Text(
                        text =
                            when (snapshot.cardPresence) {
                                CardPresence.PRESENT -> {
                                    stringResource(R.string.present)
                                }

                                CardPresence.NOT_PRESENT -> {
                                    stringResource(R.string.not_present)
                                }
                            },
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }

            if (
                snapshot.status == ReaderConnectionStatus.PERMISSION_REQUIRED ||
                snapshot.status == ReaderConnectionStatus.PERMISSION_REQUEST_FAILED ||
                snapshot.status == ReaderConnectionStatus.CARD_ERROR ||
                snapshot.status == ReaderConnectionStatus.TRANSPORT_ERROR
            ) {
                Button(
                    onClick = onRequestPermission,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.READER_ACTION),
                ) {
                    Text(
                        if (snapshot.status == ReaderConnectionStatus.TRANSPORT_ERROR) {
                            stringResource(R.string.retry)
                        } else {
                            stringResource(R.string.allow)
                        },
                    )
                }
            }
        }
    }
}

private val SCREEN_HORIZONTAL_PADDING = 24.dp
private val SCREEN_VERTICAL_PADDING = 28.dp
private val SCREEN_ITEM_SPACING = 28.dp
private val CARD_PADDING = 20.dp
private val CARD_ITEM_SPACING = 14.dp
private val CARD_CORNER_RADIUS = 22.dp
private val CARD_ELEVATION = 2.dp
private val READER_STATUS_ITEM_SPACING = 12.dp
private val READER_STATUS_INDICATOR_SIZE = 12.dp
private val SUCCESS_STATUS_COLOR = Color(0xFF168447)
private val PERMISSION_STATUS_COLOR = Color(0xFFE18400)
