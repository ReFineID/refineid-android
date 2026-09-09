@file:Suppress(
    "CyclomaticComplexMethod",
    "FunctionName",
    "LongMethod",
    "MagicNumber",
    "MaxLineLength",
    "TooManyFunctions",
    "UnusedParameter",
    "ktlint:standard:function-naming",
)

package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.core.ActivationReport
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.CardManagementFailure
import fi.refineid.android.core.CardManagementResult
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.CardManagementService
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.ManageOutcome
import fi.refineid.android.core.NativePin1State
import fi.refineid.android.core.NativePin2State

private enum class ManagementTask {
    CHANGE_PIN1,
    CHANGE_PIN2,
    RESET_PIN1,
    RESET_PIN2,
    ACTIVATE_CARD,
}

private data class OutcomeNotice(
    val resId: Int,
    val arg: String? = null,
)

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun CardManagementScreen(
    cardManagementService: CardManagementService?,
    onConnectNfc: ((CanSubmission) -> Unit)? = null,
    isCardReady: Boolean = false,
    pinCache: fi.refineid.android.core.AuthenticationPinCache? = null,
    onPin1Changed: (() -> Unit)? = null,
) {
    var health by remember { mutableStateOf<CredentialHealth?>(null) }
    var isProbing by remember { mutableStateOf(false) }
    var isOperating by remember { mutableStateOf(false) }
    var selectedTask by remember { mutableStateOf(ManagementTask.CHANGE_PIN1) }
    var outcomeNotice by remember { mutableStateOf<OutcomeNotice?>(null) }
    var outcomeIsError by remember { mutableStateOf(false) }
    var showConfirmDialog by remember { mutableStateOf(false) }

    val currentPinState = remember { TextFieldState() }
    val newPinState = remember { TextFieldState() }
    val newPinConfirmState = remember { TextFieldState() }
    val pukState = remember { TextFieldState() }
    val activationCodeState = remember { TextFieldState() }
    val canState =
        remember {
            TextFieldState(fi.refineid.android.core.CanSessionStore.currentCan ?: "")
        }

    fun clearEntries() {
        currentPinState.clearText()
        newPinState.clearText()
        newPinConfirmState.clearText()
        pukState.clearText()
        activationCodeState.clearText()
    }

    DisposableEffect(Unit) {
        onDispose {
            clearEntries()
        }
    }

    fun probe() {
        if (cardManagementService == null) return
        isProbing = true
        cardManagementService.probeCredentialHealth { result ->
            isProbing = false
            when (result) {
                is CardManagementResult.Success -> {
                    health = result.value
                    if (result.value.activationNeeds.any) {
                        selectedTask = ManagementTask.ACTIVATE_CARD
                    } else if (result.value.pin1State is NativePin1State.Locked) {
                        selectedTask = ManagementTask.RESET_PIN1
                    } else if (result.value.pin2State is NativePin2State.Locked) {
                        selectedTask = ManagementTask.RESET_PIN2
                    } else if (selectedTask == ManagementTask.ACTIVATE_CARD) {
                        selectedTask = ManagementTask.CHANGE_PIN1
                    }
                }

                is CardManagementResult.Failure -> {
                    outcomeNotice =
                        OutcomeNotice(
                            when (result.kind) {
                                CardManagementFailure.CARD_UNAVAILABLE -> R.string.unavailable
                                else -> R.string.error
                            },
                        )
                    outcomeIsError = true
                }
            }
        }
    }

    LaunchedEffect(isCardReady) {
        if (isCardReady) {
            probe()
        }
    }

    val currentPin = currentPinState.text.toString()
    val newPin = newPinState.text.toString()
    val newPinConfirm = newPinConfirmState.text.toString()
    val puk = pukState.text.toString()
    val activationCode = activationCodeState.text.toString()

    val pin1Bounds = 4..12
    val pin2Bounds = 6..12
    val pukBounds = 8..8

    val targetBounds =
        if (selectedTask == ManagementTask.CHANGE_PIN2 || selectedTask == ManagementTask.RESET_PIN2) {
            pin2Bounds
        } else {
            pin1Bounds
        }

    val currentPinValid = targetBounds.contains(currentPin.length)
    val newPinValid = targetBounds.contains(newPin.length)
    val confirmationValid = newPinValid && newPin == newPinConfirm
    val pinsDiffer = currentPin.isNotEmpty() && newPin.isNotEmpty() && currentPin != newPin
    val pukValid = pukBounds.contains(puk.length)
    val activationCodeValid = activationCode.length >= 4

    val pin1Attempts = health?.pin1State?.let { getAttempts(it) }
    val pin2Attempts = health?.pin2State?.let { getAttempts(it) }
    val pukAttempts = health?.pukState?.let { getAttempts(it) }

    val pukLocked = isLocked(health?.pukState)
    val pukLow = isLowAttempts(pukAttempts)
    val pukWarning = isWarningAttempts(pukAttempts)

    val pin1Locked = isLocked(health?.pin1State)
    val pin1Low = isLowAttempts(pin1Attempts)
    val pin1Warning = isWarningAttempts(pin1Attempts)

    val pin2Locked = isLocked(health?.pin2State)
    val pin2Low = isLowAttempts(pin2Attempts)
    val pin2Warning = isWarningAttempts(pin2Attempts)

    val isRefusedByPolicy =
        pukLocked ||
            when (selectedTask) {
                ManagementTask.CHANGE_PIN1 -> pin1Locked || pin1Low
                ManagementTask.CHANGE_PIN2 -> pin2Locked || pin2Low
                ManagementTask.RESET_PIN1, ManagementTask.RESET_PIN2 -> pukLow
                ManagementTask.ACTIVATE_CARD -> false
            }

    val (guidanceMessage, guidanceTone) =
        when {
            pukLocked -> {
                stringResource(R.string.unrecoverable_card) to BannerTone.CRITICAL
            }

            selectedTask == ManagementTask.CHANGE_PIN1 && pin1Locked -> {
                stringResource(R.string.recovery_guidance_pin1) to BannerTone.INFO
            }

            selectedTask == ManagementTask.CHANGE_PIN1 && pin1Low -> {
                stringResource(R.string.refuse_low_attempts_pin) to BannerTone.CRITICAL
            }

            selectedTask == ManagementTask.CHANGE_PIN1 && pin1Warning -> {
                stringResource(R.string.spent_attempts_notice, "PIN 1", pin1Attempts ?: 0, 5) to BannerTone.WARNING
            }

            selectedTask == ManagementTask.CHANGE_PIN2 && pin2Locked -> {
                stringResource(R.string.recovery_guidance_pin2) to BannerTone.INFO
            }

            selectedTask == ManagementTask.CHANGE_PIN2 && pin2Low -> {
                stringResource(R.string.refuse_low_attempts_pin) to BannerTone.CRITICAL
            }

            selectedTask == ManagementTask.CHANGE_PIN2 && pin2Warning -> {
                stringResource(R.string.spent_attempts_notice, "PIN 2", pin2Attempts ?: 0, 5) to BannerTone.WARNING
            }

            (selectedTask == ManagementTask.RESET_PIN1 || selectedTask == ManagementTask.RESET_PIN2) && pukLow -> {
                stringResource(R.string.refuse_low_attempts_puk) to BannerTone.CRITICAL
            }

            (selectedTask == ManagementTask.RESET_PIN1 || selectedTask == ManagementTask.RESET_PIN2) && pukWarning -> {
                stringResource(R.string.spent_attempts_notice, "PUK", pukAttempts ?: 0, 5) to BannerTone.WARNING
            }

            selectedTask == ManagementTask.RESET_PIN1 && pin1Locked -> {
                stringResource(R.string.recovery_guidance_pin1) to BannerTone.INFO
            }

            selectedTask == ManagementTask.RESET_PIN2 && pin2Locked -> {
                stringResource(R.string.recovery_guidance_pin2) to BannerTone.INFO
            }

            else -> {
                null to null
            }
        }

    val canExecute =
        !isRefusedByPolicy &&
            when (selectedTask) {
                ManagementTask.CHANGE_PIN1, ManagementTask.CHANGE_PIN2 -> {
                    currentPinValid && newPinValid && confirmationValid &&
                        pinsDiffer
                }

                ManagementTask.RESET_PIN1, ManagementTask.RESET_PIN2 -> {
                    pukValid && newPinValid && confirmationValid
                }

                ManagementTask.ACTIVATE_CARD -> {
                    activationCodeValid && newPinValid && confirmationValid
                }
            }

    fun executeOperation() {
        if (!canExecute || cardManagementService == null) return
        isOperating = true
        outcomeNotice = null

        when (selectedTask) {
            ManagementTask.CHANGE_PIN1, ManagementTask.CHANGE_PIN2 -> {
                val curBytes = currentPin.toByteArray(Charsets.US_ASCII)
                val newBytes = newPin.toByteArray(Charsets.US_ASCII)
                val isPin1 = selectedTask == ManagementTask.CHANGE_PIN1
                val pinName = if (isPin1) "PIN 1" else "PIN 2"
                if (isPin1) {
                    pinCache?.clear()
                    onPin1Changed?.invoke()
                }
                val callback: (CardManagementResult<ManageOutcome>) -> Unit = { result ->
                    isOperating = false
                    clearEntries()
                    when (result) {
                        is CardManagementResult.Success -> {
                            if (result.value is ManageOutcome.Succeeded) {
                                outcomeNotice = OutcomeNotice(R.string.pin_changed_success, pinName)
                                outcomeIsError = false
                                if (isPin1) {
                                    pinCache?.clear()
                                    onPin1Changed?.invoke()
                                }
                            } else {
                                outcomeNotice = OutcomeNotice(R.string.error)
                                outcomeIsError = true
                            }
                            probe()
                        }

                        is CardManagementResult.Failure -> {
                            outcomeNotice = OutcomeNotice(R.string.error)
                            outcomeIsError = true
                        }
                    }
                }
                if (isPin1) {
                    cardManagementService.changePin1(curBytes, newBytes, callback)
                } else {
                    cardManagementService.changePin2(curBytes, newBytes, callback)
                }
            }

            ManagementTask.RESET_PIN1, ManagementTask.RESET_PIN2 -> {
                val pukBytes = puk.toByteArray(Charsets.US_ASCII)
                val newBytes = newPin.toByteArray(Charsets.US_ASCII)
                val isPin1 = selectedTask == ManagementTask.RESET_PIN1
                val pinName = if (isPin1) "PIN 1" else "PIN 2"
                if (isPin1) {
                    pinCache?.clear()
                    onPin1Changed?.invoke()
                }
                val callback: (CardManagementResult<ManageOutcome>) -> Unit = { result ->
                    isOperating = false
                    clearEntries()
                    when (result) {
                        is CardManagementResult.Success -> {
                            if (result.value is ManageOutcome.Succeeded) {
                                outcomeNotice = OutcomeNotice(R.string.pin_reset_success, pinName)
                                outcomeIsError = false
                                if (isPin1) {
                                    pinCache?.clear()
                                    onPin1Changed?.invoke()
                                }
                            } else {
                                outcomeNotice = OutcomeNotice(R.string.error)
                                outcomeIsError = true
                            }
                            probe()
                        }

                        is CardManagementResult.Failure -> {
                            outcomeNotice = OutcomeNotice(R.string.error)
                            outcomeIsError = true
                        }
                    }
                }
                if (isPin1) {
                    cardManagementService.unblockPin1(pukBytes, newBytes, callback)
                } else {
                    cardManagementService.unblockPin2(pukBytes, newBytes, callback)
                }
            }

            ManagementTask.ACTIVATE_CARD -> {
                val codeBytes = activationCode.toByteArray(Charsets.US_ASCII)
                val new1Bytes =
                    if (health?.activationNeeds?.pin1 !=
                        false
                    ) {
                        newPin.toByteArray(Charsets.US_ASCII)
                    } else {
                        null
                    }
                val new2Bytes =
                    if (health?.activationNeeds?.pin2 !=
                        false
                    ) {
                        newPin.toByteArray(Charsets.US_ASCII)
                    } else {
                        null
                    }
                val scheme = health?.activationScheme ?: CardManagementScheme.PUK
                pinCache?.clear()
                onPin1Changed?.invoke()
                cardManagementService.activateCard(scheme, codeBytes, new1Bytes, new2Bytes) { result ->
                    isOperating = false
                    clearEntries()
                    when (result) {
                        is CardManagementResult.Success -> {
                            val actReport = result.value
                            if (actReport.pin1Outcome is ManageOutcome.Succeeded &&
                                actReport.pin2Outcome is ManageOutcome.Succeeded
                            ) {
                                outcomeNotice = OutcomeNotice(R.string.card_activated_success)
                                outcomeIsError = false
                                pinCache?.clear()
                                onPin1Changed?.invoke()
                                probe()
                            } else {
                                outcomeNotice = OutcomeNotice(R.string.error)
                                outcomeIsError = true
                                probe()
                            }
                        }

                        is CardManagementResult.Failure -> {
                            outcomeNotice = OutcomeNotice(R.string.error)
                            outcomeIsError = true
                        }
                    }
                }
            }
        }
    }

    Column(
        modifier =
            Modifier
                .fillMaxWidth()
                .imePadding()
                .testTag("CardManagementScreen"),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // NFC Connection section if card is not ready
        if (!isCardReady && onConnectNfc != null) {
            Section(stringResource(R.string.nfc)) {
                NavigationGroup {
                    Column(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        val canReady = CanSubmission.isComplete(canState.text)
                        SecureTextField(
                            state = canState,
                            modifier =
                                Modifier
                                    .fillMaxWidth()
                                    .testTag("managementCardAccessNumber"),
                            label = { Text(stringResource(R.string.can)) },
                            inputTransformation = CanInputTransformation,
                            textObfuscationMode = TextObfuscationMode.Visible,
                            keyboardOptions =
                                KeyboardOptions(
                                    autoCorrectEnabled = false,
                                    keyboardType = KeyboardType.NumberPassword,
                                    imeAction = ImeAction.Done,
                                ),
                        )
                        Button(
                            onClick = {
                                if (canReady) {
                                    fi.refineid.android.core.CanSessionStore
                                        .remember(canState.text)
                                    onConnectNfc(CanSubmission.from(canState.text))
                                }
                            },
                            enabled = canReady,
                            modifier =
                                Modifier
                                    .fillMaxWidth()
                                    .testTag("managementReadCard"),
                        ) {
                            Text(stringResource(R.string.read_identity_card))
                        }
                    }
                }
            }
        }

        // Outcome Banner
        if (outcomeNotice != null) {
            val notice = outcomeNotice!!
            val message =
                if (notice.arg != null) {
                    stringResource(notice.resId, notice.arg)
                } else {
                    stringResource(notice.resId)
                }
            OutcomeBanner(
                message = message,
                isError = outcomeIsError,
            )
        }

        // Guidance / Policy Banner
        if (guidanceMessage != null && guidanceTone != null && outcomeNotice == null) {
            GuidanceBanner(
                message = guidanceMessage,
                tone = guidanceTone,
            )
        }

        // If card awaits activation
        if (health?.activationNeeds?.any == true) {
            Section(stringResource(R.string.card_activation)) {
                CardActivationForm(
                    health = health!!,
                    activationCodeState = activationCodeState,
                    newPinState = newPinState,
                    newPinConfirmState = newPinConfirmState,
                    canExecute = canExecute,
                    isOperating = isOperating,
                    onSubmit = { showConfirmDialog = true },
                )
            }
        } else {
            // Task Form
            Section(
                when (selectedTask) {
                    ManagementTask.CHANGE_PIN1 -> stringResource(R.string.change_pin1)
                    ManagementTask.CHANGE_PIN2 -> stringResource(R.string.change_pin2)
                    ManagementTask.RESET_PIN1 -> stringResource(R.string.reset_pin1)
                    ManagementTask.RESET_PIN2 -> stringResource(R.string.reset_pin2)
                    ManagementTask.ACTIVATE_CARD -> stringResource(R.string.activate_card)
                },
            ) {
                when (selectedTask) {
                    ManagementTask.CHANGE_PIN1, ManagementTask.CHANGE_PIN2 -> {
                        ChangePinForm(
                            task = selectedTask,
                            currentState = currentPinState,
                            newState = newPinState,
                            confirmState = newPinConfirmState,
                            canExecute = canExecute,
                            isOperating = isOperating,
                            currentValid = currentPinValid,
                            newValid = newPinValid,
                            confirmValid = confirmationValid,
                            pinsDiffer = pinsDiffer,
                            onSubmit = { showConfirmDialog = true },
                        )
                    }

                    ManagementTask.RESET_PIN1, ManagementTask.RESET_PIN2 -> {
                        ResetPinForm(
                            task = selectedTask,
                            pukState = pukState,
                            newState = newPinState,
                            confirmState = newPinConfirmState,
                            canExecute = canExecute,
                            isOperating = isOperating,
                            pukValid = pukValid,
                            newValid = newPinValid,
                            confirmValid = confirmationValid,
                            onSubmit = { showConfirmDialog = true },
                        )
                    }

                    ManagementTask.ACTIVATE_CARD -> {
                        CardActivationForm(
                            health =
                                health ?: CredentialHealth(
                                    pin1State = NativePin1State.Remaining(3),
                                    pin2State = NativePin2State.Remaining(3),
                                    pukState = NativePin1State.Remaining(3),
                                    scheme = fi.refineid.android.core.NativePinReferenceScheme.CITIZEN,
                                    activationScheme = CardManagementScheme.PUK,
                                    activationNeeds =
                                        fi.refineid.android.core.CardActivationNeeds(
                                            pin1 = true,
                                            pin2 = true,
                                        ),
                                ),
                            activationCodeState = activationCodeState,
                            newPinState = newPinState,
                            newPinConfirmState = newPinConfirmState,
                            canExecute = canExecute,
                            isOperating = isOperating,
                            onSubmit = { showConfirmDialog = true },
                        )
                    }
                }
            }

            // Task Selector (at the bottom)
            Section(stringResource(R.string.card_pins)) {
                TaskSelector(
                    selectedTask = selectedTask,
                    onSelect = { task ->
                        selectedTask = task
                        outcomeNotice = null
                        clearEntries()
                    },
                )
            }
        }
    }

    if (showConfirmDialog) {
        val (dialogTitle, dialogMsg) =
            when (selectedTask) {
                ManagementTask.CHANGE_PIN1, ManagementTask.CHANGE_PIN2 -> {
                    val isPin1 = selectedTask == ManagementTask.CHANGE_PIN1
                    val pinName = if (isPin1) "PIN 1" else "PIN 2"
                    val attempts = if (isPin1) pin1Attempts else pin2Attempts
                    val title = stringResource(R.string.confirm_change_title, pinName)
                    val msg =
                        if (attempts != null && (attempts == 3 || attempts == 4)) {
                            stringResource(R.string.confirm_pin_change_warning, pinName, attempts)
                        } else {
                            null
                        }
                    title to msg
                }

                ManagementTask.RESET_PIN1, ManagementTask.RESET_PIN2 -> {
                    val isPin1 = selectedTask == ManagementTask.RESET_PIN1
                    val pinName = if (isPin1) "PIN 1" else "PIN 2"
                    val attempts = pukAttempts
                    val title = stringResource(R.string.confirm_reset_title, pinName)
                    val msg =
                        if (attempts != null && (attempts == 3 || attempts == 4)) {
                            stringResource(R.string.confirm_pin_reset_warning, "PUK", attempts)
                        } else {
                            null
                        }
                    title to msg
                }

                ManagementTask.ACTIVATE_CARD -> {
                    stringResource(R.string.confirm_activation_title) to null
                }
            }

        AlertDialog(
            onDismissRequest = { showConfirmDialog = false },
            title = { Text(dialogTitle) },
            text = dialogMsg?.let { msg -> { Text(msg) } },
            confirmButton = {
                Button(
                    onClick = {
                        showConfirmDialog = false
                        executeOperation()
                    },
                    modifier = Modifier.testTag("managementConfirmButton"),
                ) {
                    Text(stringResource(R.string.proceed))
                }
            },
            dismissButton = {
                OutlinedButton(onClick = { showConfirmDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            },
        )
    }
}

private enum class BannerTone {
    INFO,
    WARNING,
    CRITICAL,
}

private fun getAttempts(state: Any): Int? =
    when (state) {
        is NativePin1State.Remaining -> state.attempts
        is NativePin2State.Remaining -> state.attempts
        is NativePin1State.Locked, is NativePin2State.Locked -> 0
        is NativePin1State.Verified, is NativePin2State.Verified -> 5
        else -> null
    }

private fun isLowAttempts(attempts: Int?): Boolean = attempts != null && (attempts == 1 || attempts == 2)

private fun isWarningAttempts(attempts: Int?): Boolean = attempts != null && (attempts == 3 || attempts == 4)

private fun isLocked(state: Any?): Boolean =
    state is NativePin1State.Locked || state is NativePin2State.Locked || (state?.let { getAttempts(it) } == 0)

@Composable
private fun GuidanceBanner(
    message: String,
    tone: BannerTone,
    modifier: Modifier = Modifier,
) {
    val (containerColor, contentColor, icon) =
        when (tone) {
            BannerTone.CRITICAL -> {
                Triple(
                    MaterialTheme.colorScheme.errorContainer,
                    MaterialTheme.colorScheme.onErrorContainer,
                    Icons.Outlined.Warning,
                )
            }

            BannerTone.WARNING -> {
                Triple(
                    Color(0xFFFFF3E0),
                    Color(0xFFE65100),
                    Icons.Outlined.Warning,
                )
            }

            BannerTone.INFO -> {
                Triple(
                    Color(0xFFE3F2FD),
                    Color(0xFF0D47A1),
                    Icons.Outlined.CheckCircle,
                )
            }
        }

    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        shape = RoundedCornerShape(10.dp),
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = contentColor,
            )
            Text(text = message, color = contentColor, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun TaskSelector(
    selectedTask: ManagementTask,
    onSelect: (ManagementTask) -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            TaskButton(
                text = stringResource(R.string.change_pin1),
                isSelected = selectedTask == ManagementTask.CHANGE_PIN1,
                onClick = { onSelect(ManagementTask.CHANGE_PIN1) },
                modifier = Modifier.weight(1f).testTag("managementTask.changePin1"),
            )
            TaskButton(
                text = stringResource(R.string.change_pin2),
                isSelected = selectedTask == ManagementTask.CHANGE_PIN2,
                onClick = { onSelect(ManagementTask.CHANGE_PIN2) },
                modifier = Modifier.weight(1f).testTag("managementTask.changePin2"),
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            TaskButton(
                text = stringResource(R.string.reset_pin1),
                isSelected = selectedTask == ManagementTask.RESET_PIN1,
                onClick = { onSelect(ManagementTask.RESET_PIN1) },
                modifier = Modifier.weight(1f).testTag("managementTask.resetPin1"),
            )
            TaskButton(
                text = stringResource(R.string.reset_pin2),
                isSelected = selectedTask == ManagementTask.RESET_PIN2,
                onClick = { onSelect(ManagementTask.RESET_PIN2) },
                modifier = Modifier.weight(1f).testTag("managementTask.resetPin2"),
            )
        }
    }
}

@Composable
private fun TaskButton(
    text: String,
    isSelected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (isSelected) {
        Button(
            onClick = onClick,
            modifier = modifier,
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
            shape = RoundedCornerShape(10.dp),
        ) {
            Text(text = text, style = MaterialTheme.typography.labelLarge)
        }
    } else {
        OutlinedButton(
            onClick = onClick,
            modifier = modifier,
            shape = RoundedCornerShape(10.dp),
        ) {
            Text(text = text, style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
private fun OutcomeBanner(
    message: String,
    isError: Boolean,
) {
    val containerColor = if (isError) MaterialTheme.colorScheme.errorContainer else Color(0xFFE8F5E9)
    val contentColor = if (isError) MaterialTheme.colorScheme.onErrorContainer else Color(0xFF1B5E20)

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        shape = RoundedCornerShape(10.dp),
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(
                imageVector = if (isError) Icons.Outlined.Warning else Icons.Outlined.CheckCircle,
                contentDescription = null,
                tint = contentColor,
            )
            Text(text = message, color = contentColor, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun ChangePinForm(
    task: ManagementTask,
    currentState: TextFieldState,
    newState: TextFieldState,
    confirmState: TextFieldState,
    canExecute: Boolean,
    isOperating: Boolean,
    currentValid: Boolean,
    newValid: Boolean,
    confirmValid: Boolean,
    pinsDiffer: Boolean,
    onSubmit: () -> Unit,
) {
    NavigationGroup {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            val isPin2 = task == ManagementTask.CHANGE_PIN2
            val currentLabel =
                if (isPin2) {
                    stringResource(R.string.current_pin2)
                } else {
                    stringResource(R.string.current_pin1)
                }
            val newLabel =
                if (isPin2) {
                    stringResource(R.string.new_pin2)
                } else {
                    stringResource(R.string.new_pin1)
                }
            val repeatLabel =
                if (isPin2) {
                    stringResource(R.string.new_pin2_again)
                } else {
                    stringResource(R.string.new_pin1_again)
                }
            val buttonLabel =
                if (isPin2) {
                    stringResource(R.string.change_signature_pin2)
                } else {
                    stringResource(R.string.change_basic_pin1)
                }

            SecureTextField(
                state = currentState,
                modifier = Modifier.fillMaxWidth().testTag("managementCurrentPin"),
                label = { Text(currentLabel) },
                textObfuscationMode = TextObfuscationMode.Hidden,
                keyboardOptions =
                    KeyboardOptions(
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.NumberPassword,
                        imeAction = ImeAction.Next,
                    ),
            )

            SecureTextField(
                state = newState,
                modifier = Modifier.fillMaxWidth().testTag("managementNewPin"),
                label = { Text(newLabel) },
                textObfuscationMode = TextObfuscationMode.Hidden,
                keyboardOptions =
                    KeyboardOptions(
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.NumberPassword,
                        imeAction = ImeAction.Next,
                    ),
            )

            SecureTextField(
                state = confirmState,
                modifier = Modifier.fillMaxWidth().testTag("managementNewPinRepeat"),
                label = { Text(repeatLabel) },
                textObfuscationMode = TextObfuscationMode.Hidden,
                keyboardOptions =
                    KeyboardOptions(
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.NumberPassword,
                        imeAction = ImeAction.Done,
                    ),
                onKeyboardAction = { if (canExecute && !isOperating) onSubmit() },
            )

            Button(
                onClick = onSubmit,
                enabled = canExecute && !isOperating,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("managementSubmit"),
            ) {
                if (isOperating) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Text(buttonLabel)
                }
            }
        }
    }
}

@Composable
private fun ResetPinForm(
    task: ManagementTask,
    pukState: TextFieldState,
    newState: TextFieldState,
    confirmState: TextFieldState,
    canExecute: Boolean,
    isOperating: Boolean,
    pukValid: Boolean,
    newValid: Boolean,
    confirmValid: Boolean,
    onSubmit: () -> Unit,
) {
    NavigationGroup {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            val isPin2 = task == ManagementTask.RESET_PIN2
            val newLabel =
                if (isPin2) {
                    stringResource(R.string.new_pin2)
                } else {
                    stringResource(R.string.new_pin1)
                }
            val repeatLabel =
                if (isPin2) {
                    stringResource(R.string.new_pin2_again)
                } else {
                    stringResource(R.string.new_pin1_again)
                }
            val buttonLabel =
                if (isPin2) {
                    stringResource(R.string.reset_pin2)
                } else {
                    stringResource(R.string.reset_pin1)
                }

            SecureTextField(
                state = pukState,
                modifier = Modifier.fillMaxWidth().testTag("managementPuk"),
                label = { Text(stringResource(R.string.puk_code)) },
                textObfuscationMode = TextObfuscationMode.Hidden,
                keyboardOptions =
                    KeyboardOptions(
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.NumberPassword,
                        imeAction = ImeAction.Next,
                    ),
            )

            SecureTextField(
                state = newState,
                modifier = Modifier.fillMaxWidth().testTag("managementNewPin"),
                label = { Text(newLabel) },
                textObfuscationMode = TextObfuscationMode.Hidden,
                keyboardOptions =
                    KeyboardOptions(
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.NumberPassword,
                        imeAction = ImeAction.Next,
                    ),
            )

            SecureTextField(
                state = confirmState,
                modifier = Modifier.fillMaxWidth().testTag("managementNewPinRepeat"),
                label = { Text(repeatLabel) },
                textObfuscationMode = TextObfuscationMode.Hidden,
                keyboardOptions =
                    KeyboardOptions(
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.NumberPassword,
                        imeAction = ImeAction.Done,
                    ),
                onKeyboardAction = { if (canExecute && !isOperating) onSubmit() },
            )

            Button(
                onClick = onSubmit,
                enabled = canExecute && !isOperating,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("managementSubmit"),
            ) {
                if (isOperating) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Text(buttonLabel)
                }
            }
        }
    }
}

@Composable
private fun CardActivationForm(
    health: CredentialHealth,
    activationCodeState: TextFieldState,
    newPinState: TextFieldState,
    newPinConfirmState: TextFieldState,
    canExecute: Boolean,
    isOperating: Boolean,
    onSubmit: () -> Unit,
) {
    NavigationGroup {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SecureTextField(
                state = activationCodeState,
                modifier = Modifier.fillMaxWidth().testTag("managementActivationCode"),
                label = { Text(stringResource(R.string.activation_pin)) },
                textObfuscationMode = TextObfuscationMode.Hidden,
                keyboardOptions =
                    KeyboardOptions(
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.NumberPassword,
                        imeAction = ImeAction.Next,
                    ),
            )

            SecureTextField(
                state = newPinState,
                modifier = Modifier.fillMaxWidth().testTag("managementNewPin"),
                label = { Text(stringResource(R.string.new_pin1)) },
                textObfuscationMode = TextObfuscationMode.Hidden,
                keyboardOptions =
                    KeyboardOptions(
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.NumberPassword,
                        imeAction = ImeAction.Next,
                    ),
            )

            SecureTextField(
                state = newPinConfirmState,
                modifier = Modifier.fillMaxWidth().testTag("managementNewPinRepeat"),
                label = { Text(stringResource(R.string.new_pin1_again)) },
                textObfuscationMode = TextObfuscationMode.Hidden,
                keyboardOptions =
                    KeyboardOptions(
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.NumberPassword,
                        imeAction = ImeAction.Done,
                    ),
                onKeyboardAction = { if (canExecute && !isOperating) onSubmit() },
            )

            Button(
                onClick = onSubmit,
                enabled = canExecute && !isOperating,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("managementActivate"),
            ) {
                if (isOperating) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.activate_card))
                }
            }
        }
    }
}
