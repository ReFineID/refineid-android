// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

internal enum class PdfSigningFailure {
    ENCRYPTED,
    NOT_A_PDF,
    PLACEHOLDER_MALFORMED,
    SIGNATURE_CLAIM_MALFORMED,
    SIGNATURE_TOO_LARGE,
    STREAM_ENCODING_UNSUPPORTED,
    STRUCTURE_UNREADABLE,
    VALIDATION_MATERIAL_MALFORMED,
    VALIDATION_MATERIAL_UNAVAILABLE,
}

internal class PdfSigningException(
    val kind: PdfSigningFailure,
    val needed: Int? = null,
    val reserved: Int? = null,
) : IllegalArgumentException(kind.name)
