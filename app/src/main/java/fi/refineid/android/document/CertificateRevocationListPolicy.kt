// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.cert.X509CRL

/** Full-list and critical-extension policy intentionally excluding delta/indirect CRLs. */
internal object CertificateRevocationListPolicy {
    fun validate(list: X509CRL) {
        if (list.getExtensionValue(RevocationListOids.DELTA_CRL_INDICATOR) != null) {
            throw failure(RevocationListValidationFailure.DELTA_UNSUPPORTED)
        }
        list.getExtensionValue(RevocationListOids.ISSUING_DISTRIBUTION_POINT)?.let { wrapped ->
            validateIssuingDistributionPoint(wrapped)
        }
        validateCriticalListExtensions(list)
        validateEntries(list)
    }

    private fun validateIssuingDistributionPoint(wrapped: ByteArray) {
        val outer = DerReader(wrapped)
        val octetString =
            outer.next()
                ?: throw failure(RevocationListValidationFailure.MALFORMED)
        if (octetString.tag != DerValues.TAG_OCTET_STRING || !outer.isAtEnd) {
            throw failure(RevocationListValidationFailure.MALFORMED)
        }
        val encoded = outer.content(octetString)
        try {
            val value = DerReader(encoded)
            val sequence =
                value.next()
                    ?: throw failure(RevocationListValidationFailure.MALFORMED)
            if (sequence.tag != DerValues.TAG_SEQUENCE || !value.isAtEnd) {
                throw failure(RevocationListValidationFailure.MALFORMED)
            }
            if (!value.children(sequence).isAtEnd) {
                throw failure(RevocationListValidationFailure.SCOPE_UNSUPPORTED)
            }
        } finally {
            encoded.fill(ZERO_BYTE)
            wrapped.fill(ZERO_BYTE)
        }
    }

    private fun validateCriticalListExtensions(list: X509CRL) {
        val critical = list.criticalExtensionOIDs.orEmpty()
        if (critical.any { identifier -> identifier != RevocationListOids.ISSUING_DISTRIBUTION_POINT }) {
            throw failure(RevocationListValidationFailure.UNSUPPORTED_CRITICAL_EXTENSION)
        }
        if (list.hasUnsupportedCriticalExtension()) {
            throw failure(RevocationListValidationFailure.UNSUPPORTED_CRITICAL_EXTENSION)
        }
    }

    private fun validateEntries(list: X509CRL) {
        for (entry in list.revokedCertificates.orEmpty()) {
            if (entry.getExtensionValue(RevocationListOids.CERTIFICATE_ISSUER) != null) {
                throw failure(RevocationListValidationFailure.INDIRECT_UNSUPPORTED)
            }
            if (!entry.criticalExtensionOIDs.isNullOrEmpty() || entry.hasUnsupportedCriticalExtension()) {
                throw failure(RevocationListValidationFailure.UNSUPPORTED_CRITICAL_EXTENSION)
            }
        }
    }

    private fun failure(kind: RevocationListValidationFailure): RevocationListValidationException =
        RevocationListValidationException(kind)

    private const val ZERO_BYTE: Byte = 0
}

internal object RevocationListOids {
    const val CERTIFICATE_ISSUER = "2.5.29.29"
    const val DELTA_CRL_INDICATOR = "2.5.29.27"
    const val ISSUING_DISTRIBUTION_POINT = "2.5.29.28"
    const val SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
    const val SHA384_WITH_RSA = "1.2.840.113549.1.1.12"
    const val SHA512_WITH_RSA = "1.2.840.113549.1.1.13"
    const val ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
    const val ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3"
    const val ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4"
}
