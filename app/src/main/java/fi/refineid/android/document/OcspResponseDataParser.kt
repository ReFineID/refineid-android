// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

internal data class ParsedOcspSingleResponse(
    val matches: Boolean,
    val nextUpdate: java.time.Instant?,
    val status: OcspCertificateStatus,
    val thisUpdate: java.time.Instant,
)

/** Strict parsing of the signed RFC 6960 ResponseData and SingleResponse values. */
internal object OcspResponseDataParser {
    fun parse(
        encoded: ByteArray,
        element: DerReader.Element,
        expected: ExpectedOcspCertificateId,
        nonce: ByteArray,
    ): ParsedOcspResponseData {
        val fields = DerReader(encoded).children(element)
        var first = fields.next() ?: throw malformed()
        if (first.tag == DerValues.TAG_CONTEXT_0_CONSTRUCTED) {
            requireVersionOne(fields, first)
            first = fields.next() ?: throw malformed()
        }
        val responderId = responderId(fields, first)
        var transferred = false
        try {
            val producedAt = OcspResponseTime.parse(fields, required(fields, DerValues.TAG_GENERALIZED_TIME))
            val responses = required(fields, DerValues.TAG_SEQUENCE)
            val matched = matchingResponse(fields, responses, expected)
            requireTrailingExtensions(fields, nonce)
            return ParsedOcspResponseData(
                nextUpdate = matched.nextUpdate,
                producedAt = producedAt,
                ownedRaw = fields.raw(element),
                responderId = responderId,
                status = matched.status,
                thisUpdate = matched.thisUpdate,
            ).also {
                transferred = true
            }
        } finally {
            if (!transferred) {
                responderId.close()
            }
        }
    }

    private fun matchingResponse(
        parent: DerReader,
        responses: DerReader.Element,
        expected: ExpectedOcspCertificateId,
    ): ParsedOcspSingleResponse {
        val entries = parent.children(responses)
        var matched: ParsedOcspSingleResponse? = null
        var responseCount = EMPTY_RESPONSE_COUNT
        while (!entries.isAtEnd) {
            val response = required(entries, DerValues.TAG_SEQUENCE)
            val candidate = singleResponse(entries, response, expected)
            responseCount += SINGLE_RESPONSE_COUNT
            if (candidate.matches) {
                if (matched != null) {
                    throw malformed()
                }
                matched = candidate
            }
        }
        if (responseCount == EMPTY_RESPONSE_COUNT) {
            throw malformed()
        }
        return matched ?: throw failure(OcspResponseValidationFailure.CERTIFICATE_MISMATCH)
    }

    private fun singleResponse(
        parent: DerReader,
        element: DerReader.Element,
        expected: ExpectedOcspCertificateId,
    ): ParsedOcspSingleResponse {
        val fields = parent.children(element)
        val certificateId = required(fields, DerValues.TAG_SEQUENCE)
        val matches = certificateIdMatches(fields, certificateId, expected)
        val status = certificateStatus(fields, fields.next() ?: throw malformed())
        val thisUpdate = OcspResponseTime.parse(fields, required(fields, DerValues.TAG_GENERALIZED_TIME))
        val nextUpdate = optionalFields(fields)
        if (!fields.isAtEnd) {
            throw malformed()
        }
        return ParsedOcspSingleResponse(matches, nextUpdate, status, thisUpdate)
    }

    private fun optionalFields(fields: DerReader): java.time.Instant? {
        var optional = fields.next() ?: return null
        var nextUpdate: java.time.Instant? = null
        if (optional.tag == DerValues.TAG_CONTEXT_0_CONSTRUCTED) {
            nextUpdate = explicitTime(fields, optional)
            optional = fields.next() ?: return nextUpdate
        }
        if (optional.tag != DerValues.TAG_CONTEXT_1_CONSTRUCTED) {
            throw malformed()
        }
        OcspResponseExtensions.rejectCritical(fields, optional)
        return nextUpdate
    }

    private fun explicitTime(
        parent: DerReader,
        wrapper: DerReader.Element,
    ): java.time.Instant {
        val wrapped = parent.children(wrapper)
        val time = required(wrapped, DerValues.TAG_GENERALIZED_TIME)
        if (!wrapped.isAtEnd) {
            throw malformed()
        }
        return OcspResponseTime.parse(wrapped, time)
    }

    private fun certificateStatus(
        parent: DerReader,
        element: DerReader.Element,
    ): OcspCertificateStatus =
        when (element.tag) {
            DerValues.TAG_CONTEXT_0_PRIMITIVE -> {
                if (element.contentStart != element.contentEnd) {
                    throw malformed()
                }
                OcspCertificateStatus.GOOD
            }

            DerValues.TAG_CONTEXT_1_CONSTRUCTED -> {
                requireRevocationFields(parent, element)
                OcspCertificateStatus.REVOKED
            }

            DerValues.TAG_CONTEXT_2_PRIMITIVE -> {
                if (element.contentStart != element.contentEnd) {
                    throw malformed()
                }
                OcspCertificateStatus.UNKNOWN
            }

            else -> {
                throw malformed()
            }
        }

    private fun requireRevocationFields(
        parent: DerReader,
        element: DerReader.Element,
    ) {
        val fields = parent.children(element)
        OcspResponseTime.parse(fields, required(fields, DerValues.TAG_GENERALIZED_TIME))
        if (!fields.isAtEnd) {
            val wrapper = required(fields, DerValues.TAG_CONTEXT_0_CONSTRUCTED)
            val reason = fields.children(wrapper)
            val value = required(reason, DerValues.TAG_ENUMERATED)
            if (!reason.isAtEnd || Rfc3161DerValidation.implicitNonNegativeLong(reason, value) == null) {
                throw malformed()
            }
        }
        if (!fields.isAtEnd) {
            throw malformed()
        }
    }

    private fun certificateIdMatches(
        parent: DerReader,
        element: DerReader.Element,
        expected: ExpectedOcspCertificateId,
    ): Boolean {
        val fields = parent.children(element)
        val algorithm = required(fields, DerValues.TAG_SEQUENCE)
        val algorithmMatches = isSha1Algorithm(fields, algorithm)
        val nameHash = fields.content(required(fields, DerValues.TAG_OCTET_STRING))
        val keyHash = fields.content(required(fields, DerValues.TAG_OCTET_STRING))
        val serialElement = required(fields, DerValues.TAG_INTEGER)
        val serialNumber = fields.content(serialElement)
        return try {
            if (
                !fields.isAtEnd ||
                nameHash.isEmpty() ||
                keyHash.isEmpty() ||
                !Rfc3161DerValidation.isCanonicalNonNegativeInteger(fields, serialElement)
            ) {
                throw malformed()
            }
            algorithmMatches &&
                nameHash.size == SHA1_DIGEST_BYTE_COUNT &&
                keyHash.size == SHA1_DIGEST_BYTE_COUNT &&
                expected.matches(nameHash, keyHash, serialNumber)
        } finally {
            nameHash.fill(ZERO_BYTE)
            keyHash.fill(ZERO_BYTE)
            serialNumber.fill(ZERO_BYTE)
        }
    }

    private fun isSha1Algorithm(
        parent: DerReader,
        element: DerReader.Element,
    ): Boolean {
        val fields = parent.children(element)
        val identifier = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
        val encodedIdentifier = fields.raw(identifier)
        try {
            if (!encodedIdentifier.contentEquals(SHA1_IDENTIFIER)) {
                return false
            }
        } finally {
            encodedIdentifier.fill(ZERO_BYTE)
        }
        val parameters = fields.next()
        if (parameters == null) {
            return fields.isAtEnd
        }
        return parameters.tag == DerValues.TAG_NULL &&
            parameters.contentStart == parameters.contentEnd &&
            fields.isAtEnd
    }

    private fun responderId(
        parent: DerReader,
        element: DerReader.Element,
    ): OcspResponderId =
        when (element.tag) {
            DerValues.TAG_CONTEXT_1_CONSTRUCTED -> {
                val wrapped = parent.children(element)
                val name = required(wrapped, DerValues.TAG_SEQUENCE)
                if (!wrapped.isAtEnd) {
                    throw malformed()
                }
                OcspResponderId.ByName(wrapped.raw(name))
            }

            DerValues.TAG_CONTEXT_2_PRIMITIVE -> {
                val hash = parent.content(element)
                if (hash.size != SHA1_DIGEST_BYTE_COUNT) {
                    hash.fill(ZERO_BYTE)
                    throw malformed()
                }
                OcspResponderId.ByKey(hash)
            }

            else -> {
                throw malformed()
            }
        }

    private fun requireVersionOne(
        parent: DerReader,
        wrapper: DerReader.Element,
    ) {
        val wrapped = parent.children(wrapper)
        val version = required(wrapped, DerValues.TAG_INTEGER)
        val value = Rfc3161DerValidation.nonNegativeLong(wrapped, version)
        if (!wrapped.isAtEnd || value != VERSION_ONE_VALUE) {
            throw malformed()
        }
    }

    private fun requireTrailingExtensions(
        fields: DerReader,
        nonce: ByteArray,
    ) {
        if (!fields.isAtEnd) {
            val extensions = required(fields, DerValues.TAG_CONTEXT_1_CONSTRUCTED)
            OcspResponseExtensions.requireResponseNonce(fields, extensions, nonce)
        }
        if (!fields.isAtEnd) {
            throw malformed()
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

    private const val VERSION_ONE_VALUE = 0L
    private const val EMPTY_RESPONSE_COUNT = 0
    private const val SINGLE_RESPONSE_COUNT = 1
    private const val SHA1_DIGEST_BYTE_COUNT = 20
    private const val ZERO_BYTE: Byte = 0
    private val SHA1_IDENTIFIER = DerEncoder.objectIdentifier(CertificateOids.SHA1)
}
