// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.util.Base64

/** Bounded DER ownership and strict standard-PEM decoding for CRL input. */
internal object CertificateRevocationListInput {
    fun derEncoded(input: ByteArray): ByteArray {
        if (input.isEmpty() || input.size > MAXIMUM_INPUT_BYTES) {
            throw malformed()
        }
        if (input[FIRST_BYTE_OFFSET].toUnsignedInt() == DerValues.TAG_SEQUENCE) {
            if (input.size > PdfValidationMaterialLimits.MAXIMUM_REVOCATION_LIST_BYTES) {
                throw malformed()
            }
            return input.copyOf()
        }
        if (input.any { byte -> byte.toUnsignedInt() > MAXIMUM_ASCII }) {
            throw malformed()
        }
        val lines =
            input
                .toString(Charsets.US_ASCII)
                .lineSequence()
                .map(String::trim)
                .filter(String::isNotEmpty)
                .toList()
        if (
            lines.size <= PEM_BOUNDARY_LINE_COUNT ||
            lines.first() != PEM_BEGIN ||
            lines.last() != PEM_END
        ) {
            throw malformed()
        }
        val body = lines.subList(PEM_BODY_START_INDEX, lines.lastIndex)
        if (body.any { line -> line.startsWith(PEM_BOUNDARY_PREFIX) }) {
            throw malformed()
        }
        val decoded =
            try {
                Base64.getDecoder().decode(body.joinToString(separator = EMPTY_SEPARATOR))
            } catch (_: IllegalArgumentException) {
                throw malformed()
            }
        if (
            decoded.isEmpty() ||
            decoded.size > PdfValidationMaterialLimits.MAXIMUM_REVOCATION_LIST_BYTES ||
            decoded[FIRST_BYTE_OFFSET].toUnsignedInt() != DerValues.TAG_SEQUENCE
        ) {
            decoded.fill(ZERO_BYTE)
            throw malformed()
        }
        return decoded
    }

    private fun malformed(): RevocationListValidationException =
        RevocationListValidationException(RevocationListValidationFailure.MALFORMED)

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private const val FIRST_BYTE_OFFSET = 0
    private const val MAXIMUM_ASCII = 0x7F
    private const val PEM_BOUNDARY_LINE_COUNT = 2
    private const val PEM_BODY_START_INDEX = 1
    private const val PEM_BOUNDARY_PREFIX = "-----"
    private const val PEM_BEGIN = "-----BEGIN X509 CRL-----"
    private const val PEM_END = "-----END X509 CRL-----"
    private const val EMPTY_SEPARATOR = ""
    private const val ZERO_BYTE: Byte = 0
    private const val PEM_EXPANSION_NUMERATOR = 4
    private const val PEM_EXPANSION_DENOMINATOR = 3
    private const val PEM_FORMAT_ALLOWANCE_BYTES = 4_096
    private const val MAXIMUM_INPUT_BYTES =
        PdfValidationMaterialLimits.MAXIMUM_REVOCATION_LIST_BYTES * PEM_EXPANSION_NUMERATOR /
            PEM_EXPANSION_DENOMINATOR + PEM_FORMAT_ALLOWANCE_BYTES
}
