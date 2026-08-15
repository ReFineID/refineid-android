// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** Owned certificate and revocation evidence ready for one PDF DSS revision. */
internal class PdfValidationMaterial private constructor(
    private val ownedCertificates: List<ByteArray>,
    private val ownedOcspResponses: List<ByteArray>,
    private val ownedRevocationLists: List<ByteArray>,
) : AutoCloseable {
    private var isClosed = false

    val isEmpty: Boolean
        get() {
            requireOpen()
            return ownedCertificates.isEmpty() &&
                ownedOcspResponses.isEmpty() &&
                ownedRevocationLists.isEmpty()
        }

    fun <T> useCopies(operation: (List<ByteArray>, List<ByteArray>, List<ByteArray>) -> T): T {
        requireOpen()
        val certificates = ownedCertificates.map(ByteArray::copyOf)
        val ocspResponses = ownedOcspResponses.map(ByteArray::copyOf)
        val revocationLists = ownedRevocationLists.map(ByteArray::copyOf)
        return try {
            operation(certificates, ocspResponses, revocationLists)
        } finally {
            certificates.clearBytes()
            ocspResponses.clearBytes()
            revocationLists.clearBytes()
        }
    }

    override fun close() {
        if (!isClosed) {
            ownedCertificates.clearBytes()
            ownedOcspResponses.clearBytes()
            ownedRevocationLists.clearBytes()
            isClosed = true
        }
    }

    override fun toString(): String =
        "PdfValidationMaterial(certificates=" + ownedCertificates.size +
            ", ocspResponses=" + ownedOcspResponses.size +
            ", revocationLists=" + ownedRevocationLists.size +
            ", closed=" + isClosed + ")"

    private fun requireOpen() {
        if (isClosed) {
            throw PdfSigningException(PdfSigningFailure.VALIDATION_MATERIAL_UNAVAILABLE)
        }
    }

    companion object {
        fun copyOf(
            certificates: List<ByteArray>,
            ocspResponses: List<ByteArray>,
            revocationLists: List<ByteArray>,
        ): PdfValidationMaterial {
            validateCategory(
                values = certificates,
                maximumCount = PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_COUNT,
                maximumValueBytes = PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES,
            )
            validateCategory(
                values = ocspResponses,
                maximumCount = PdfValidationMaterialLimits.MAXIMUM_OCSP_RESPONSE_COUNT,
                maximumValueBytes = PdfValidationMaterialLimits.MAXIMUM_OCSP_RESPONSE_BYTES,
            )
            validateCategory(
                values = revocationLists,
                maximumCount = PdfValidationMaterialLimits.MAXIMUM_REVOCATION_LIST_COUNT,
                maximumValueBytes = PdfValidationMaterialLimits.MAXIMUM_REVOCATION_LIST_BYTES,
            )
            validateTotalSize(certificates, ocspResponses, revocationLists)
            return PdfValidationMaterial(
                ownedCertificates = certificates.map(ByteArray::copyOf),
                ownedOcspResponses = ocspResponses.map(ByteArray::copyOf),
                ownedRevocationLists = revocationLists.map(ByteArray::copyOf),
            )
        }

        private fun validateCategory(
            values: List<ByteArray>,
            maximumCount: Int,
            maximumValueBytes: Int,
        ) {
            if (
                values.size > maximumCount ||
                values.any { value -> value.isEmpty() || value.size > maximumValueBytes }
            ) {
                throw malformed()
            }
        }

        private fun validateTotalSize(vararg categories: List<ByteArray>) {
            var totalBytes = EMPTY_MATERIAL_BYTES
            for (category in categories) {
                for (value in category) {
                    totalBytes += value.size.toLong()
                    if (totalBytes > PdfValidationMaterialLimits.MAXIMUM_TOTAL_BYTES) {
                        throw malformed()
                    }
                }
            }
        }

        private fun malformed(): PdfSigningException =
            PdfSigningException(PdfSigningFailure.VALIDATION_MATERIAL_MALFORMED)

        private fun List<ByteArray>.clearBytes() {
            forEach { value -> value.fill(ZERO_BYTE) }
        }

        private const val EMPTY_MATERIAL_BYTES = 0L
        private const val ZERO_BYTE: Byte = 0
    }
}

/** Resource ceilings for untrusted validation material before PDF allocation. */
internal object PdfValidationMaterialLimits {
    const val MAXIMUM_VALIDATION_PATH_COUNT = 2
    const val MAXIMUM_CERTIFICATES_PER_PATH = 12
    const val MAXIMUM_CERTIFICATE_COUNT =
        MAXIMUM_VALIDATION_PATH_COUNT * MAXIMUM_CERTIFICATES_PER_PATH
    const val MAXIMUM_OCSP_RESPONSE_COUNT = MAXIMUM_CERTIFICATE_COUNT
    const val MAXIMUM_REVOCATION_LIST_COUNT = MAXIMUM_CERTIFICATE_COUNT

    const val MAXIMUM_CERTIFICATE_BYTES = 65_536
    const val MAXIMUM_OCSP_RESPONSE_BYTES = 65_536

    // Current public FINEID lists can exceed 13 MiB; this remains a hard ceiling.
    const val MAXIMUM_REVOCATION_LIST_BYTES = 16_777_216
    const val MAXIMUM_TOTAL_BYTES = 67_108_864L
}
