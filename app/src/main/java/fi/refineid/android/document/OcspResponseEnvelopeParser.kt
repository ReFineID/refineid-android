// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** Strict OCSPResponse and BasicOCSPResponse envelope parsing. */
internal object OcspResponseEnvelopeParser {
    fun parse(
        response: ByteArray,
        expected: ExpectedOcspCertificateId,
        nonce: ByteArray,
    ): ParsedBasicOcspResponse {
        val outer = DerReader(response)
        val sequence = required(outer, DerValues.TAG_SEQUENCE)
        if (!outer.isAtEnd) {
            throw malformed()
        }
        val fields = outer.children(sequence)
        val status = required(fields, DerValues.TAG_ENUMERATED)
        val statusValue = Rfc3161DerValidation.implicitNonNegativeLong(fields, status)
        if (statusValue == null || statusValue > Int.MAX_VALUE) {
            throw malformed()
        }
        if (statusValue != SUCCESS_RESPONSE_STATUS) {
            throw OcspResponseValidationException(
                kind = OcspResponseValidationFailure.REJECTED,
                responderStatus = statusValue.toInt(),
            )
        }
        val wrapped = required(fields, DerValues.TAG_CONTEXT_0_CONSTRUCTED)
        if (!fields.isAtEnd) {
            throw malformed()
        }
        val basicEncoding = responseBytes(fields, wrapped)
        return try {
            parseBasic(basicEncoding, expected, nonce)
        } finally {
            basicEncoding.fill(ZERO_BYTE)
        }
    }

    private fun responseBytes(
        parent: DerReader,
        wrapper: DerReader.Element,
    ): ByteArray {
        val wrapped = parent.children(wrapper)
        val sequence = required(wrapped, DerValues.TAG_SEQUENCE)
        if (!wrapped.isAtEnd) {
            throw malformed()
        }
        val fields = wrapped.children(sequence)
        val type = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
        val encodedType = fields.raw(type)
        try {
            if (!encodedType.contentEquals(BASIC_RESPONSE_IDENTIFIER)) {
                throw failure(OcspResponseValidationFailure.UNSUPPORTED_RESPONSE_TYPE)
            }
        } finally {
            encodedType.fill(ZERO_BYTE)
        }
        val body = required(fields, DerValues.TAG_OCTET_STRING)
        if (!fields.isAtEnd) {
            throw malformed()
        }
        return fields.content(body)
    }

    private fun parseBasic(
        encoded: ByteArray,
        expected: ExpectedOcspCertificateId,
        nonce: ByteArray,
    ): ParsedBasicOcspResponse {
        val outer = DerReader(encoded)
        val sequence = required(outer, DerValues.TAG_SEQUENCE)
        if (!outer.isAtEnd) {
            throw malformed()
        }
        val fields = outer.children(sequence)
        val responseDataElement = required(fields, DerValues.TAG_SEQUENCE)
        val responseData = OcspResponseDataParser.parse(encoded, responseDataElement, expected, nonce)
        var signatureAlgorithm: ByteArray? = null
        var signature: ByteArray? = null
        var certificates: List<ByteArray> = emptyList()
        var transferred = false
        try {
            val signatureAlgorithmElement = required(fields, DerValues.TAG_SEQUENCE)
            signatureAlgorithm = fields.raw(signatureAlgorithmElement)
            val signatureElement = required(fields, DerValues.TAG_BIT_STRING)
            signature = signature(fields, signatureElement)
            if (!fields.isAtEnd) {
                val certificateWrapper = required(fields, DerValues.TAG_CONTEXT_0_CONSTRUCTED)
                certificates = certificates(fields, certificateWrapper)
            }
            if (!fields.isAtEnd) {
                throw malformed()
            }
            return ParsedBasicOcspResponse(
                responseData = responseData,
                ownedSignatureAlgorithm = signatureAlgorithm,
                ownedSignature = signature,
                ownedCertificates = certificates,
            ).also {
                transferred = true
            }
        } finally {
            if (!transferred) {
                responseData.close()
                signatureAlgorithm?.fill(ZERO_BYTE)
                signature?.fill(ZERO_BYTE)
                certificates.forEach { certificate -> certificate.fill(ZERO_BYTE) }
            }
        }
    }

    private fun signature(
        reader: DerReader,
        element: DerReader.Element,
    ): ByteArray {
        val content = reader.content(element)
        return try {
            if (
                content.size <= BIT_STRING_PREFIX_BYTE_COUNT ||
                content[UNUSED_BITS_OFFSET] != NO_UNUSED_BITS
            ) {
                throw failure(OcspResponseValidationFailure.SIGNATURE_INVALID)
            }
            content.copyOfRange(BIT_STRING_PREFIX_BYTE_COUNT, content.size)
        } finally {
            content.fill(ZERO_BYTE)
        }
    }

    private fun certificates(
        parent: DerReader,
        wrapper: DerReader.Element,
    ): List<ByteArray> {
        val wrapped = parent.children(wrapper)
        val sequence = required(wrapped, DerValues.TAG_SEQUENCE)
        if (!wrapped.isAtEnd) {
            throw malformed()
        }
        val reader = wrapped.children(sequence)
        val certificates = mutableListOf<ByteArray>()
        var transferred = false
        try {
            while (!reader.isAtEnd) {
                val certificate = required(reader, DerValues.TAG_SEQUENCE)
                val encoded = reader.raw(certificate)
                if (
                    encoded.size > PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES ||
                    certificates.size >= PdfValidationMaterialLimits.MAXIMUM_CERTIFICATES_PER_PATH
                ) {
                    encoded.fill(ZERO_BYTE)
                    throw malformed()
                }
                certificates += encoded
            }
            if (certificates.isEmpty()) {
                throw malformed()
            }
            return certificates.also {
                transferred = true
            }
        } finally {
            if (!transferred) {
                certificates.forEach { value -> value.fill(ZERO_BYTE) }
            }
        }
    }

    private fun required(
        reader: DerReader,
        tag: Int,
    ): DerReader.Element {
        val element = reader.next() ?: throw malformed()
        if (element.tag != tag) {
            throw malformed()
        }
        return element
    }

    private fun malformed(): OcspResponseValidationException = failure(OcspResponseValidationFailure.MALFORMED)

    private fun failure(kind: OcspResponseValidationFailure): OcspResponseValidationException =
        OcspResponseValidationException(kind)

    private const val SUCCESS_RESPONSE_STATUS = 0L
    private const val BIT_STRING_PREFIX_BYTE_COUNT = 1
    private const val UNUSED_BITS_OFFSET = 0
    private const val NO_UNUSED_BITS: Byte = 0
    private const val ZERO_BYTE: Byte = 0
    private val BASIC_RESPONSE_IDENTIFIER = DerEncoder.objectIdentifier(OcspOids.BASIC_RESPONSE)
}
