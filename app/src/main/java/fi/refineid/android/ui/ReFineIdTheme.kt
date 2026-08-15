package fi.refineid.android.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val REFINED_ID_PRIMARY = Color(0xFF0056A6)
private val REFINED_ID_PRIMARY_CONTAINER = Color(0xFFD7E9FF)
private val REFINED_ID_ON_PRIMARY_CONTAINER = Color(0xFF001C38)
private val REFINED_ID_SECONDARY = Color(0xFF35618E)
private val REFINED_ID_BACKGROUND = Color(0xFFF7F9FC)
private val REFINED_ID_ON_BACKGROUND = Color(0xFF171C22)
private val REFINED_ID_SURFACE_VARIANT = Color(0xFFE2E8F0)
private val REFINED_ID_ON_SURFACE_VARIANT = Color(0xFF424A54)
private val REFINED_ID_ERROR = Color(0xFFBA1A1A)

private val ReFineIdColors =
    lightColorScheme(
        primary = REFINED_ID_PRIMARY,
        onPrimary = Color.White,
        primaryContainer = REFINED_ID_PRIMARY_CONTAINER,
        onPrimaryContainer = REFINED_ID_ON_PRIMARY_CONTAINER,
        secondary = REFINED_ID_SECONDARY,
        onSecondary = Color.White,
        background = REFINED_ID_BACKGROUND,
        onBackground = REFINED_ID_ON_BACKGROUND,
        surface = Color.White,
        onSurface = REFINED_ID_ON_BACKGROUND,
        surfaceVariant = REFINED_ID_SURFACE_VARIANT,
        onSurfaceVariant = REFINED_ID_ON_SURFACE_VARIANT,
        error = REFINED_ID_ERROR,
    )

@Composable
internal fun ReFineIdTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = ReFineIdColors,
        typography = Typography(),
        content = content,
    )
}
