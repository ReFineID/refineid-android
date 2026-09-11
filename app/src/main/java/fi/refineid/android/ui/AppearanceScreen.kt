package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import fi.refineid.android.R
import fi.refineid.android.settings.ThemePreference

/** Appearance override: follow the phone or pin light/dark unconditionally. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun AppearanceScreen(
    selected: ThemePreference,
    onSelected: (ThemePreference) -> Unit,
) {
    NavigationGroup {
        ThemePreference.entries.forEach { preference ->
            Row(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .selectable(
                            selected = preference == selected,
                            onClick = { onSelected(preference) },
                            role = Role.RadioButton,
                        ).padding(
                            horizontal = ROW_HORIZONTAL_PADDING,
                            vertical = ROW_VERTICAL_PADDING,
                        ).testTag(UiAutomationIds.APPEARANCE_OPTION + preference.name),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(ROW_ITEM_SPACING),
            ) {
                RadioButton(
                    selected = preference == selected,
                    onClick = null,
                )
                Text(
                    text = stringResource(id = themeLabel(preference)),
                    color = MaterialTheme.colorScheme.onSurface,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.weight(ROW_LABEL_WEIGHT),
                )
            }
        }
    }
}

private fun themeLabel(preference: ThemePreference): Int =
    when (preference) {
        ThemePreference.SYSTEM -> R.string.theme_system
        ThemePreference.LIGHT -> R.string.theme_light
        ThemePreference.DARK -> R.string.theme_dark
    }
