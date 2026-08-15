// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.MessageDigest

/** A nonce-bound OCSP request for one exact RFC 6960 certificate identity. */
internal object OcspRequest {
    const val NONCE_BYTE_COUNT = 32

    fun encoded(
        issuerName: ByteArray,
        issuerKeyBits: ByteArray,
        serialNumber: ByteArray,
        nonce: ByteArray,
    ): ByteArray {
        require(issuerName.isNotEmpty() && issuerName.size <= MAXIMUM_IDENTITY_BYTES) {
            "OCSP issuer name is outside the supported bound"
        }
        require(issuerKeyBits.isNotEmpty() && issuerKeyBits.size <= MAXIMUM_IDENTITY_BYTES) {
            "OCSP issuer key is outside the supported bound"
        }
        require(isCanonicalSerialNumber(serialNumber)) {
            "OCSP serial number is not a canonical positive INTEGER"
        }
        require(nonce.size == NONCE_BYTE_COUNT) {
            "OCSP nonce has the wrong length"
        }
        val issuerNameHash = MessageDigest.getInstance(SHA1_JAVA_NAME).digest(issuerName)
        val issuerKeyHash = MessageDigest.getInstance(SHA1_JAVA_NAME).digest(issuerKeyBits)
        return try {
            val certificateId =
                DerEncoder.sequence(
                    listOf(
                        sha1AlgorithmIdentifier(),
                        DerEncoder.octetString(issuerNameHash),
                        DerEncoder.octetString(issuerKeyHash),
                        DerEncoder.tlv(DerValues.TAG_INTEGER, serialNumber),
                    ),
                )
            val requestList = DerEncoder.sequence(listOf(DerEncoder.sequence(listOf(certificateId))))
            val nonceExtension =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.objectIdentifier(CertificateOids.OCSP_NONCE),
                        DerEncoder.octetString(DerEncoder.octetString(nonce)),
                    ),
                )
            val extensions =
                DerEncoder.tlv(
                    tag = DerValues.TAG_CONTEXT_2_CONSTRUCTED,
                    content = DerEncoder.sequence(listOf(nonceExtension)),
                )
            DerEncoder.sequence(listOf(DerEncoder.sequence(listOf(requestList, extensions))))
        } finally {
            issuerNameHash.fill(ZERO_BYTE)
            issuerKeyHash.fill(ZERO_BYTE)
        }
    }

    private fun sha1AlgorithmIdentifier(): ByteArray =
        DerEncoder.sequence(
            listOf(
                DerEncoder.objectIdentifier(CertificateOids.SHA1),
                DerEncoder.nullValue(),
            ),
        )

    private fun isCanonicalSerialNumber(serialNumber: ByteArray): Boolean {
        if (serialNumber.isEmpty() || serialNumber.size > MAXIMUM_SERIAL_NUMBER_BYTES) {
            return false
        }
        val encoded = DerEncoder.tlv(DerValues.TAG_INTEGER, serialNumber)
        return try {
            val reader = DerReader(encoded)
            val integer = reader.next() ?: return false
            Rfc3161DerValidation.isCanonicalNonNegativeInteger(reader, integer) &&
                serialNumber.any { byte -> byte != ZERO_BYTE }
        } finally {
            encoded.fill(ZERO_BYTE)
        }
    }

    private const val SHA1_JAVA_NAME = "SHA-1"
    private const val MAXIMUM_IDENTITY_BYTES = PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES
    private const val MAXIMUM_SERIAL_NUMBER_BYTES = 20
    private const val ZERO_BYTE: Byte = 0
}
