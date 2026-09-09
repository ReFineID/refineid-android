package fi.refineid.android.document

import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

/**
 * Names a signed document after the original, stamped with the instant
 * it was signed, so signing twice never overwrites and a set of signed
 * files sorts in signing order. Mirrors the reference app: the word for
 * signing is localized, but the instant stays in the engineering ISO
 * form in every language, so a name mailed abroad reads and sorts the
 * same. Colons are replaced so the name is safe on every filesystem.
 */
internal object SignedDocumentName {
    private const val SEPARATOR = " - "
    private const val DEFAULT_EXTENSION = "pdf"

    /**
     * The name a signed output should be offered under, given the
     * original's display name and the already-localized, instant-bearing
     * "signed at …" phrase. A PAdES signature keeps the original
     * extension; a container caller passes its own.
     */
    fun suggested(
        originalName: String,
        signedAtPhrase: String,
        extensionOverride: String? = null,
    ): String {
        val base = originalName.substringBeforeLast('.', originalName).ifBlank { originalName }
        val originalExtension = originalName.substringAfterLast('.', "")
        val extension =
            extensionOverride
                ?: originalExtension.ifBlank { DEFAULT_EXTENSION }
        return base + SEPARATOR + signedAtPhrase + "." + extension
    }

    /**
     * The UTC instant in engineering ISO-8601 form with colons replaced,
     * e.g. `2026-08-17T15-04-05Z`, to embed in the localized phrase.
     */
    fun instantStamp(instant: Instant): String =
        DateTimeFormatter.ISO_INSTANT
            .format(instant.truncatedTo(ChronoUnit.SECONDS))
            .replace(":", "-")
}
