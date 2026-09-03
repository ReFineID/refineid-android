@file:Suppress("LongMethod", "MagicNumber", "MaxLineLength", "UnusedParameter")

package fi.refineid.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Clear
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import fi.refineid.android.R
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.rapp.PairingPhase
import fi.refineid.android.rapp.RappPairingCode
import fi.refineid.android.rapp.RappPairingModel

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun RappPairingScreen(
    model: RappPairingModel,
    pinCache: AuthenticationPinCache? = null,
    onConnectCard: (CanSubmission?, Pin1Submission?) -> Unit = { _, _ -> },
    onBack: () -> Unit,
) {
    val phase = model.phase

    Column(
        modifier =
            Modifier
                .fillMaxSize()
                .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        when (phase) {
            is PairingPhase.Idle, is PairingPhase.CodeEntry -> {
                val connectedPeer = model.activeConnectedPeer
                if (connectedPeer != null) {
                    Text(
                        text = stringResource(R.string.connected_to_computer),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                    ) {
                        Row(
                            modifier =
                                Modifier
                                    .fillMaxWidth()
                                    .padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column {
                                Text(
                                    text = connectedPeer.displayName,
                                    style = MaterialTheme.typography.bodyLarge,
                                    fontWeight = FontWeight.Medium,
                                )
                                Text(
                                    text = connectedPeer.platform,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            IconButton(onClick = { model.removePair(connectedPeer.pairIdHex) }) {
                                Icon(
                                    imageVector = Icons.Outlined.Delete,
                                    contentDescription = stringResource(R.string.forget),
                                    tint = MaterialTheme.colorScheme.error,
                                )
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = { model.disconnectActivePeer() },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary),
                    ) {
                        Text(stringResource(R.string.disconnect))
                    }
                } else {
                    var codeInput by remember { mutableStateOf("") }
                    val initialCan = remember { CanSessionStore.currentCan ?: "" }
                    var canInput by remember { mutableStateOf(initialCan) }
                    var pin1Input by remember { mutableStateOf(pinCache?.peekPin() ?: "") }
                    val canValid = CanSubmission.isComplete(canInput)
                    val codeValid = RappPairingCode.isValid(codeInput)

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                    ) {
                        Column(
                            modifier =
                                Modifier
                                    .fillMaxWidth()
                                    .padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(16.dp),
                        ) {
                            OutlinedTextField(
                                value = codeInput,
                                onValueChange = { codeInput = RappPairingCode.normalize(it) },
                                label = { Text(stringResource(R.string.pairing_code)) },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                singleLine = true,
                                textStyle =
                                    MaterialTheme.typography.bodyLarge.copy(
                                        textAlign = TextAlign.Center,
                                        fontFamily = FontFamily.Monospace,
                                    ),
                                modifier = Modifier.fillMaxWidth(),
                            )

                            OutlinedTextField(
                                value = canInput,
                                onValueChange = { canInput = it.filter { c -> c in '0'..'9' }.take(6) },
                                label = { Text(stringResource(R.string.can)) },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                singleLine = true,
                                textStyle =
                                    MaterialTheme.typography.bodyLarge.copy(
                                        textAlign = TextAlign.Center,
                                        fontFamily = FontFamily.Monospace,
                                    ),
                                modifier = Modifier.fillMaxWidth(),
                            )

                            OutlinedTextField(
                                value = pin1Input,
                                onValueChange = { pin1Input = it.filter { c -> c in '0'..'9' }.take(4) },
                                label = { Text(stringResource(R.string.pin1_optional)) },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                                visualTransformation = PasswordVisualTransformation(),
                                singleLine = true,
                                textStyle =
                                    MaterialTheme.typography.bodyLarge.copy(
                                        textAlign = TextAlign.Center,
                                        fontFamily = FontFamily.Monospace,
                                    ),
                                modifier = Modifier.fillMaxWidth(),
                            )

                            Button(
                                onClick = {
                                    CanSessionStore.remember(canInput)
                                    val canSubmission = CanSubmission.from(canInput)
                                    val pin1Submission =
                                        if (Pin1Submission.isComplete(pin1Input)) {
                                            val pinBytes = pin1Input.toByteArray(Charsets.US_ASCII)
                                            pinCache?.recordVerified(pinBytes)
                                            Pin1Submission.from(pin1Input)
                                        } else if (pinCache?.hasPin == true) {
                                            pinCache.take()
                                        } else {
                                            null
                                        }
                                    onConnectCard(canSubmission, pin1Submission)
                                    model.connectWithCode(codeInput)
                                },
                                enabled = codeValid && canValid,
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text(stringResource(R.string.pair_computer))
                            }
                        }
                    }
                }
            }

            is PairingPhase.Offering -> {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                ) {
                    Column(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        Text(
                            text = stringResource(R.string.pair_computer),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            text = RappPairingCode.formatted(phase.code),
                            style = MaterialTheme.typography.headlineLarge,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 36.sp,
                            letterSpacing = 4.sp,
                            color = MaterialTheme.colorScheme.primary,
                        )
                        Button(
                            onClick = { model.reset() },
                            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary),
                        ) {
                            Text(stringResource(R.string.cancel))
                        }
                    }
                }
            }

            is PairingPhase.Connecting -> {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                ) {
                    Column(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        CircularProgressIndicator()
                        Text(
                            text = phase.message,
                            style = MaterialTheme.typography.bodyLarge,
                            textAlign = TextAlign.Center,
                        )
                    }
                }
            }

            is PairingPhase.Paired -> {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
                ) {
                    Column(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Check,
                            contentDescription = "Success",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(48.dp),
                        )
                        Text(
                            text = stringResource(R.string.pairing_success),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(
                            text = "${phase.peer.displayName} (${phase.peer.platform})",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Button(onClick = { model.reset() }) {
                            Text(stringResource(R.string.ready))
                        }
                    }
                }
            }

            is PairingPhase.Failed -> {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                ) {
                    Column(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Clear,
                            contentDescription = "Failed",
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(48.dp),
                        )
                        Text(
                            text = stringResource(R.string.pairing_failed),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(
                            text = phase.reason,
                            style = MaterialTheme.typography.bodyMedium,
                            textAlign = TextAlign.Center,
                        )
                        Button(onClick = { model.reset() }) {
                            Text(stringResource(R.string.retry))
                        }
                    }
                }
            }
        }
    }
}
