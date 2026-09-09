// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress("MagicNumber")

package fi.refineid.android.ui

import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.graphics.Typeface
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.util.Locale
import kotlin.math.min
import androidx.compose.ui.text.intl.Locale as ComposeLocale

/**
 * Visual red electronic signature stamp.
 * Primary language is prominently centered in the seal.
 * Secondary languages are dynamically scaled and formatted along the top and bottom circular border arcs,
 * separated by side stars.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming", "MagicNumber")
@Composable
internal fun ElectronicSignatureStamp(
    modifier: Modifier = Modifier,
    size: Dp = 170.dp,
    color: Color = STAMP_RED,
) {
    val locale = ComposeLocale.current.platformLocale
    val stampTexts = remember(locale) { resolveStampTexts(locale) }
    val density = LocalDensity.current
    val baseBorderTextSizePx = with(density) { 6.2.sp.toPx() }
    val middleTextSizePx = with(density) { 8.8.sp.toPx() }

    val baseBorderPaint =
        remember(color, baseBorderTextSizePx) {
            createBorderPaint(color, baseBorderTextSizePx)
        }
    val middleTextPaint =
        remember(color, middleTextSizePx) {
            createMiddlePaint(color, middleTextSizePx)
        }
    val starPaint =
        remember(color, baseBorderTextSizePx) {
            createStarPaint(color, baseBorderTextSizePx)
        }

    Box(
        modifier = modifier.size(size),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(modifier = Modifier.size(size)) {
            val canvasSize = min(this.size.width, this.size.height)
            val center = Offset(this.size.width / 2f, this.size.height / 2f)
            val outerRadius = (canvasSize / 2f) - with(density) { 4.dp.toPx() }
            val borderInnerRadius = outerRadius - with(density) { 18.dp.toPx() }
            val textRadius = (outerRadius + borderInnerRadius) / 2f
            val centerCircleRadius = borderInnerRadius - with(density) { 2.5.dp.toPx() }

            drawStampRings(color, density, center, outerRadius, borderInnerRadius, centerCircleRadius)
            drawStampBorderArcs(center, textRadius, stampTexts, baseBorderPaint, starPaint, baseBorderTextSizePx)
            drawStampCenterText(center, stampTexts.middleLines, middleTextPaint, middleTextSizePx)
        }
    }
}

private fun createBorderPaint(
    color: Color,
    textSize: Float,
) = Paint().apply {
    isAntiAlias = true
    this.color = color.toArgb()
    this.textSize = textSize
    textAlign = Paint.Align.CENTER
    letterSpacing = 0.03f
    typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
}

private fun createMiddlePaint(
    color: Color,
    textSize: Float,
) = Paint().apply {
    isAntiAlias = true
    this.color = color.toArgb()
    this.textSize = textSize
    textAlign = Paint.Align.CENTER
    letterSpacing = 0.03f
    typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
}

private fun createStarPaint(
    color: Color,
    textSize: Float,
) = Paint().apply {
    isAntiAlias = true
    this.color = color.toArgb()
    this.textSize = textSize * 1.2f
    textAlign = Paint.Align.CENTER
    typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
}

private fun DrawScope.drawStampRings(
    color: Color,
    density: Density,
    center: Offset,
    outerRadius: Float,
    borderInnerRadius: Float,
    centerCircleRadius: Float,
) {
    drawCircle(
        color = color,
        radius = outerRadius,
        center = center,
        style = Stroke(width = with(density) { 2.dp.toPx() }),
    )
    drawCircle(
        color = color,
        radius = borderInnerRadius,
        center = center,
        style = Stroke(width = with(density) { 1.dp.toPx() }),
    )
    drawCircle(
        color = color,
        radius = centerCircleRadius,
        center = center,
        style = Stroke(width = with(density) { 0.6.dp.toPx() }),
    )
}

@Suppress("MagicNumber")
private fun DrawScope.drawStampBorderArcs(
    center: Offset,
    textRadius: Float,
    stampTexts: StampTexts,
    baseBorderPaint: Paint,
    starPaint: Paint,
    baseBorderTextSizePx: Float,
) {
    val sweepAngle = 156f
    val arcLength = (sweepAngle / 360f) * 2f * Math.PI.toFloat() * textRadius
    val topRect = RectF(center.x - textRadius, center.y - textRadius, center.x + textRadius, center.y + textRadius)

    val topPath = Path().apply { addArc(topRect, 192f, sweepAngle) }
    val topPaint = Paint(baseBorderPaint)
    fitTextSizeToArc(topPaint, stampTexts.topBorderText, arcLength, baseBorderTextSizePx)
    drawContext.canvas.nativeCanvas.drawTextOnPath(
        stampTexts.topBorderText,
        topPath,
        arcLength / 2f,
        topPaint.textSize * 0.32f,
        topPaint,
    )

    val bottomPath = Path().apply { addArc(topRect, 168f, -sweepAngle) }
    val bottomPaint = Paint(baseBorderPaint)
    fitTextSizeToArc(bottomPaint, stampTexts.bottomBorderText, arcLength, baseBorderTextSizePx)
    drawContext.canvas.nativeCanvas.drawTextOnPath(
        stampTexts.bottomBorderText,
        bottomPath,
        arcLength / 2f,
        -bottomPaint.textSize * 0.25f,
        bottomPaint,
    )

    val starYOffset = (starPaint.descent() + starPaint.ascent()) / 2f
    drawContext.canvas.nativeCanvas.drawText("★", center.x - textRadius, center.y - starYOffset, starPaint)
    drawContext.canvas.nativeCanvas.drawText("★", center.x + textRadius, center.y - starYOffset, starPaint)
}

private fun DrawScope.drawStampCenterText(
    center: Offset,
    lines: List<String>,
    middleTextPaint: Paint,
    middleTextSizePx: Float,
) {
    val lineHeight = middleTextSizePx * 1.35f
    val totalHeight = (lines.size - 1) * lineHeight
    val startY = center.y - (totalHeight / 2f) - ((middleTextPaint.descent() + middleTextPaint.ascent()) / 2f)

    lines.forEachIndexed { index, line ->
        val y = startY + index * lineHeight
        drawContext.canvas.nativeCanvas.drawText(line, center.x, y, middleTextPaint)
    }
}

private fun fitTextSizeToArc(
    paint: Paint,
    text: String,
    availableArcLength: Float,
    baseSizePx: Float,
) {
    paint.textSize = baseSizePx
    val measuredWidth = paint.measureText(text)
    val targetLength = availableArcLength * 0.94f
    if (measuredWidth > targetLength && measuredWidth > 0f) {
        paint.textSize = baseSizePx * (targetLength / measuredWidth)
    }
}

internal data class StampTexts(
    val middleLines: List<String>,
    val topBorderText: String,
    val bottomBorderText: String,
)

internal fun resolveStampTexts(locale: Locale): StampTexts {
    val lang = locale.language.lowercase()
    val fiTitle = listOf("TARKASTA ASIAKIRJAN", "SÄHKÖINEN", "ALLEKIRJOITUS")
    val svTitle = listOf("KONTROLLERA DOKUMENTETS", "ELEKTRONISKA", "SIGNATUR")
    val enTitle = listOf("CHECK DOCUMENT", "ELECTRONIC", "SIGNATURE")

    val fiBorder = "TARKASTA ASIAKIRJAN SÄHKÖINEN ALLEKIRJOITUS"
    val svBorder = "KONTROLLERA DOKUMENTETS ELEKTRONISKA SIGNATUR"
    val enBorder = "CHECK DOCUMENT ELECTRONIC SIGNATURE"

    return when (lang) {
        "sv" -> {
            StampTexts(
                middleLines = svTitle,
                topBorderText = fiBorder,
                bottomBorderText = enBorder,
            )
        }

        "fi" -> {
            StampTexts(
                middleLines = fiTitle,
                topBorderText = svBorder,
                bottomBorderText = enBorder,
            )
        }

        else -> {
            StampTexts(
                middleLines = enTitle,
                topBorderText = fiBorder,
                bottomBorderText = svBorder,
            )
        }
    }
}

private val STAMP_RED = Color(0xFFC62828)
