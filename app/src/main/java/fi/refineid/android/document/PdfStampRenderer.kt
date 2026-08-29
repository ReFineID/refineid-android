// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.util.Locale
import kotlin.math.cos
import kotlin.math.sin

@Suppress("MagicNumber")
internal object PdfStampRenderer {
    const val STAMP_RADIUS = 64.0
    const val STAMP_BLEED = 2.0
    const val STAMP_REACH = 66.0
    private const val BORDER_INNER_RADIUS = 48.0
    private const val INK_COLOR = "0.7765 0.1569 0.1569" // Authentic Red #C62828

    fun generateStampOperators(locale: Locale = Locale.getDefault()): String {
        val sb = StringBuilder()
        sb.append("q\n")
        sb.append("$INK_COLOR RG $INK_COLOR rg\n")

        // Outer ring (radius 64, width 1.8)
        sb.append("1.8 w\n")
        appendCircle(sb, STAMP_RADIUS)
        sb.append("S\n")

        // Border separator ring (radius 48, width 0.9)
        sb.append("0.9 w\n")
        appendCircle(sb, BORDER_INNER_RADIUS)
        sb.append("S\n")

        // Inner subtle ring (radius 45, width 0.5)
        sb.append("0.5 w\n")
        appendCircle(sb, BORDER_INNER_RADIUS - 3.0)
        sb.append("S\n")

        val stampTexts = resolveStampTexts(locale)
        val textRadius = 55.5

        // Top arc text (Clockwise across top from 168° to 12°, apex at 90°)
        val topChars = stampTexts.topBorderText.toCharArray()
        val topCount = topChars.size
        val topStartAngle = 168.0 * (Math.PI / 180.0)
        val topSweepAngle = -156.0 * (Math.PI / 180.0)
        val topFontSize = calculatePdfFontSize(topCount)

        sb.append("BT\n")
        sb.append(String.format(Locale.US, "/F1 %.1f Tf\n", topFontSize))
        for (i in topChars.indices) {
            val fraction = if (topCount > 1) i.toDouble() / (topCount - 1) else 0.5
            val angle = topStartAngle + fraction * topSweepAngle
            val x = textRadius * cos(angle)
            val y = textRadius * sin(angle)

            val textAngle = angle - Math.PI / 2.0
            val cosA = cos(textAngle)
            val sinA = sin(textAngle)

            sb.append(String.format(Locale.US, "%.4f %.4f %.4f %.4f %.2f %.2f Tm\n", cosA, sinA, -sinA, cosA, x, y))
            val charStr = escapePdfString(topChars[i])
            sb.append("($charStr) Tj\n")
        }

        // Bottom arc text (Counter-clockwise across bottom from -168° to -12°, apex at -90°, upright letters)
        val bottomChars = stampTexts.bottomBorderText.toCharArray()
        val bottomCount = bottomChars.size
        val bottomStartAngle = -168.0 * (Math.PI / 180.0)
        val bottomSweepAngle = 156.0 * (Math.PI / 180.0)
        val bottomFontSize = calculatePdfFontSize(bottomCount)

        sb.append(String.format(Locale.US, "/F1 %.1f Tf\n", bottomFontSize))
        for (i in bottomChars.indices) {
            val fraction = if (bottomCount > 1) i.toDouble() / (bottomCount - 1) else 0.5
            val angle = bottomStartAngle + fraction * bottomSweepAngle
            val x = textRadius * cos(angle)
            val y = textRadius * sin(angle)

            val textAngle = angle + Math.PI / 2.0
            val cosA = cos(textAngle)
            val sinA = sin(textAngle)

            sb.append(String.format(Locale.US, "%.4f %.4f %.4f %.4f %.2f %.2f Tm\n", cosA, sinA, -sinA, cosA, x, y))
            val charStr = escapePdfString(bottomChars[i])
            sb.append("($charStr) Tj\n")
        }

        // Side separator stars at 180° (left) and 0° (right)
        sb.append("/F1 4.5 Tf\n")
        sb.append(String.format(Locale.US, "1.0000 0.0000 0.0000 1.0000 %.2f -1.50 Tm\n", -textRadius - 1.0))
        sb.append("(\\225) Tj\n")
        sb.append(String.format(Locale.US, "1.0000 0.0000 0.0000 1.0000 %.2f -1.50 Tm\n", textRadius - 2.0))
        sb.append("(\\225) Tj\n")
        sb.append("ET\n")

        // Primary language prominently in the center
        val lines = stampTexts.middleLines
        val fontSize = 5.2
        val lineHeight = fontSize * 1.45
        val totalHeight = (lines.size - 1) * lineHeight
        val startY = (totalHeight / 2.0) - (fontSize * 0.3)

        sb.append("BT\n")
        sb.append(String.format(Locale.US, "/F1 %.1f Tf\n", fontSize))
        lines.forEachIndexed { index, line ->
            val y = startY - index * lineHeight
            val approxWidth = line.length * (fontSize * 0.56)
            val x = -(approxWidth / 2.0)
            sb.append(String.format(Locale.US, "1.0000 0.0000 0.0000 1.0000 %.2f %.2f Tm\n", x, y))
            val escapedLine = line.map { escapePdfString(it) }.joinToString("")
            sb.append("($escapedLine) Tj\n")
        }
        sb.append("ET\n")

        sb.append("Q\n")
        return sb.toString()
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

    private fun calculatePdfFontSize(charCount: Int): Double =
        if (charCount > 40) {
            2.9
        } else if (charCount > 30) {
            3.3
        } else {
            3.6
        }

    private fun appendCircle(
        sb: StringBuilder,
        r: Double,
    ) {
        val c = r * 0.5522847498307935
        sb.append(String.format(Locale.US, "%.2f 0.00 m\n", r))
        sb.append(String.format(Locale.US, "%.2f %.2f %.2f %.2f 0.00 %.2f c\n", r, c, c, r, r))
        sb.append(String.format(Locale.US, "-%.2f %.2f -%.2f %.2f -%.2f 0.00 c\n", c, r, r, c, r))
        sb.append(String.format(Locale.US, "-%.2f -%.2f -%.2f -%.2f 0.00 -%.2f c\n", r, c, c, r, r))
        sb.append(String.format(Locale.US, "%.2f -%.2f %.2f -%.2f %.2f 0.00 c\n", c, r, r, c, r))
    }

    private fun escapePdfString(c: Char): String {
        return when (c) {
            '(' -> {
                "\\("
            }

            ')' -> {
                "\\)"
            }

            '\\' -> {
                "\\\\"
            }

            'ä' -> {
                "\\344"
            }

            'ö' -> {
                "\\366"
            }

            'å' -> {
                "\\345"
            }

            'Ä' -> {
                "\\304"
            }

            'Ö' -> {
                "\\326"
            }

            'Å' -> {
                "\\305"
            }

            '•' -> {
                "\\225"
            }

            else -> {
                if (c.code in 32..126) {
                    c.toString()
                } else {
                    "\\%03o".format(Locale.US, c.code and 0xFF)
                }
            }
        }
    }
}
