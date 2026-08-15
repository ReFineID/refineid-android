// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

internal enum class PdfSigningFailure {
    CROSS_REFERENCE_STREAM_UNSUPPORTED,
    ENCRYPTED,
    NOT_A_PDF,
    PLACEHOLDER_MALFORMED,
    SIGNATURE_CLAIM_MALFORMED,
    SIGNATURE_TOO_LARGE,
    STRUCTURE_UNREADABLE,
    VALIDATION_MATERIAL_MALFORMED,
    VALIDATION_MATERIAL_UNAVAILABLE,
}

internal class PdfSigningException(
    val kind: PdfSigningFailure,
    val needed: Int? = null,
    val reserved: Int? = null,
) : IllegalArgumentException(kind.name)
