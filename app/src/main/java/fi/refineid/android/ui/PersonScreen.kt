@file:Suppress("LongMethod", "MagicNumber", "MaxLineLength")

package fi.refineid.android.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.core.graphics.createBitmap
import fi.refineid.android.R
import fi.refineid.android.core.PersonCardDetails
import java.io.File
import java.io.FileOutputStream

@Suppress("FunctionName", "ktlint:standard:function-naming", "LongMethod")
@Composable
internal fun PersonScreen(
    details: PersonCardDetails,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val photoBitmap = details.getPhotoBitmap()

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(SUBSCREEN_ITEM_SPACING),
    ) {
        // Photo Card
        NavigationGroup {
            Column(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .padding(PHOTO_CARD_PADDING),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(PHOTO_SECTION_SPACING),
            ) {
                if (photoBitmap != null) {
                    Image(
                        bitmap = photoBitmap.asImageBitmap(),
                        contentDescription = stringResource(R.string.section_identity),
                        modifier =
                            Modifier
                                .size(width = PHOTO_WIDTH, height = PHOTO_HEIGHT)
                                .clip(RoundedCornerShape(PHOTO_CORNER_RADIUS))
                                .border(
                                    width = 1.dp,
                                    color = MaterialTheme.colorScheme.outlineVariant,
                                    shape = RoundedCornerShape(PHOTO_CORNER_RADIUS),
                                ),
                    )
                } else {
                    Box(
                        modifier =
                            Modifier
                                .size(width = PHOTO_WIDTH, height = PHOTO_HEIGHT)
                                .clip(RoundedCornerShape(PHOTO_CORNER_RADIUS))
                                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                                .border(
                                    width = 1.dp,
                                    color = MaterialTheme.colorScheme.outlineVariant,
                                    shape = RoundedCornerShape(PHOTO_CORNER_RADIUS),
                                ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Box(
                                modifier =
                                    Modifier
                                        .size(AVATAR_CONTAINER_SIZE)
                                        .background(
                                            color = MaterialTheme.colorScheme.primaryContainer,
                                            shape = CircleShape,
                                        ),
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(
                                    imageVector = Icons.Outlined.Person,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(AVATAR_ICON_SIZE),
                                )
                            }
                            Text(
                                text = details.fullName,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                ) {
                    OutlinedButton(
                        onClick = {
                            val bitmapToCopy = photoBitmap ?: createPlaceholderBadge(details.fullName)
                            copyPhotoToClipboard(context, bitmapToCopy)
                        },
                        colors = ButtonDefaults.outlinedButtonColors(),
                    ) {
                        Icon(
                            imageVector = CopyIcon,
                            contentDescription = null,
                            modifier = Modifier.size(BUTTON_ICON_SIZE),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(stringResource(R.string.copy_photo))
                    }

                    Spacer(modifier = Modifier.width(12.dp))

                    OutlinedButton(
                        onClick = {
                            val bitmapToShare = photoBitmap ?: createPlaceholderBadge(details.fullName)
                            sharePhoto(context, bitmapToShare)
                        },
                        colors = ButtonDefaults.outlinedButtonColors(),
                    ) {
                        Icon(
                            imageVector = ShareIcon,
                            contentDescription = null,
                            modifier = Modifier.size(BUTTON_ICON_SIZE),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(stringResource(R.string.share_photo))
                    }
                }
            }
        }

        // Personal Details Section
        Section(stringResource(R.string.person_details)) {
            NavigationGroup {
                DetailInfoRow(
                    label = stringResource(R.string.full_name),
                    value = details.fullName,
                )
                if (details.dateOfBirth != null) {
                    HorizontalDivider(modifier = Modifier.padding(start = GROUP_DIVIDER_INSET))
                    DetailInfoRow(
                        label = stringResource(R.string.date_of_birth),
                        value = details.dateOfBirth,
                    )
                }
                HorizontalDivider(modifier = Modifier.padding(start = GROUP_DIVIDER_INSET))
                DetailInfoRow(
                    label = stringResource(R.string.nationality),
                    value = details.nationality,
                )
                if (details.identifier != null) {
                    HorizontalDivider(modifier = Modifier.padding(start = GROUP_DIVIDER_INSET))
                    DetailInfoRow(
                        label = stringResource(R.string.identifier),
                        value = details.identifier,
                    )
                }
            }
        }

        // Card Details Section
        Section(stringResource(R.string.card_details)) {
            NavigationGroup {
                if (details.issuedDate != null) {
                    DetailInfoRow(
                        label = stringResource(R.string.issued),
                        value = details.issuedDate,
                    )
                    HorizontalDivider(modifier = Modifier.padding(start = GROUP_DIVIDER_INSET))
                }
                if (details.expiryDate != null) {
                    DetailInfoRow(
                        label = stringResource(R.string.expires),
                        value = details.expiryDate,
                    )
                    HorizontalDivider(modifier = Modifier.padding(start = GROUP_DIVIDER_INSET))
                }
                DetailInfoRow(
                    label = stringResource(R.string.signature_details_issuer),
                    value = details.issuer ?: "Digi- ja väestötietovirasto (DVV)",
                )
            }
        }

        // Authenticity & Integrity Section
        Section(stringResource(R.string.card_integrity)) {
            NavigationGroup {
                Row(
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .padding(horizontal = ROW_HORIZONTAL_PADDING, vertical = ROW_VERTICAL_PADDING),
                    verticalAlignment = Alignment.Top,
                    horizontalArrangement = Arrangement.spacedBy(ROW_ITEM_SPACING),
                ) {
                    Icon(
                        imageVector = Icons.Outlined.CheckCircle,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(ROW_ICON_SIZE),
                    )
                    Column(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(
                            text = stringResource(R.string.card_untampered),
                            style = MaterialTheme.typography.bodyLarge,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = stringResource(R.string.card_integrity_description),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DetailInfoRow(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier =
            modifier
                .fillMaxWidth()
                .padding(horizontal = ROW_HORIZONTAL_PADDING, vertical = ROW_VERTICAL_PADDING),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private fun copyPhotoToClipboard(
    context: Context,
    bitmap: Bitmap,
) {
    try {
        val uri = saveBitmapToCache(context, bitmap)
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newUri(context.contentResolver, "Card Photo", uri)
        clipboard.setPrimaryClip(clip)
        Toast.makeText(context, context.getString(R.string.photo_copied), Toast.LENGTH_SHORT).show()
    } catch (_: Exception) {
        Toast.makeText(context, "Error copying photo", Toast.LENGTH_SHORT).show()
    }
}

private fun sharePhoto(
    context: Context,
    bitmap: Bitmap,
) {
    try {
        val uri = saveBitmapToCache(context, bitmap)
        val shareIntent =
            Intent(Intent.ACTION_SEND).apply {
                type = "image/png"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
        context.startActivity(Intent.createChooser(shareIntent, context.getString(R.string.share_photo)))
    } catch (_: Exception) {
        Toast.makeText(context, "Error sharing photo", Toast.LENGTH_SHORT).show()
    }
}

private fun saveBitmapToCache(
    context: Context,
    bitmap: Bitmap,
): Uri {
    val imagesFolder = File(context.cacheDir, "images").apply { mkdirs() }
    val file = File(imagesFolder, "card_photo.png")
    FileOutputStream(file).use { out ->
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
    }
    return FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
}

private fun createPlaceholderBadge(name: String): Bitmap {
    val bitmap = createBitmap(BADGE_CANVAS_WIDTH, BADGE_CANVAS_HEIGHT)
    val canvas = Canvas(bitmap)
    canvas.drawColor(Color.rgb(BADGE_BG_R, BADGE_BG_G, BADGE_BG_B))

    val paint =
        Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(BADGE_TEXT_R, BADGE_TEXT_G, BADGE_TEXT_B)
            textSize = BADGE_TEXT_SIZE
            textAlign = Paint.Align.CENTER
        }
    canvas.drawText(name.take(BADGE_MAX_NAME_CHARS), BADGE_TEXT_X, BADGE_TEXT_Y, paint)
    return bitmap
}

private val PHOTO_WIDTH = 130.dp
private val PHOTO_HEIGHT = 160.dp
private val PHOTO_CORNER_RADIUS = 12.dp
private val PHOTO_CARD_PADDING = 16.dp
private val PHOTO_SECTION_SPACING = 16.dp
private val AVATAR_CONTAINER_SIZE = 64.dp
private val AVATAR_ICON_SIZE = 36.dp
private val BUTTON_ICON_SIZE = 18.dp

private const val BADGE_CANVAS_WIDTH = 300
private const val BADGE_CANVAS_HEIGHT = 380
private const val BADGE_BG_R = 240
private const val BADGE_BG_G = 243
private const val BADGE_BG_B = 246
private const val BADGE_TEXT_R = 0
private const val BADGE_TEXT_G = 102
private const val BADGE_TEXT_B = 204
private const val BADGE_TEXT_SIZE = 32f
private const val BADGE_TEXT_X = 150f
private const val BADGE_TEXT_Y = 200f
private const val BADGE_MAX_NAME_CHARS = 16

private val CopyIcon: ImageVector by lazy {
    ImageVector
        .Builder(
            name = "Copy",
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
        ).addPath(
            pathData =
                PathParser()
                    .parsePathString(
                        "M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z",
                    ).toNodes(),
            fill = SolidColor(androidx.compose.ui.graphics.Color.Black),
        ).build()
}

private val ShareIcon: ImageVector by lazy {
    ImageVector
        .Builder(
            name = "Share",
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
        ).addPath(
            pathData =
                PathParser()
                    .parsePathString(
                        "M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92 1.61 0 2.92-1.31 2.92-2.92s-1.31-2.92-2.92-2.92z",
                    ).toNodes(),
            fill = SolidColor(androidx.compose.ui.graphics.Color.Black),
        ).build()
}
