// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.time.Instant

/** Ordered parsing of the message imprint and optional fields in one TSTInfo. */
internal object Rfc3161TstInfoParser {
    data class Binding(
        val algorithm: ByteArray,
        val digest: ByteArray,
        val generatedAt: Instant,
        val nonce: ByteArray?,
    )

    private data class RequiredFields(
        val imprint: DerReader.Element,
        val generatedAt: Instant,
    )

    fun binding(tstInfo: ByteArray): Binding {
        val outer = DerReader(tstInfo)
        val sequence = required(outer, DerValues.TAG_SEQUENCE)
        if (!outer.isAtEnd) {
            throw malformed()
        }
        val fields = outer.children(sequence)
        val required = requiredFields(fields)
        val (algorithm, digest) = messageImprint(fields, required.imprint)
        val optional = mutableListOf<DerReader.Element>()
        while (!fields.isAtEnd) {
            optional += fields.next() ?: throw malformed()
        }
        return Binding(
            algorithm = algorithm,
            digest = digest,
            generatedAt = required.generatedAt,
            nonce = optionalFields(fields, optional),
        )
    }

    private fun requiredFields(fields: DerReader): RequiredFields {
        val version = required(fields, DerValues.TAG_INTEGER)
        if (Rfc3161DerValidation.nonNegativeLong(fields, version) != TST_INFO_VERSION) {
            throw malformed()
        }
        val policy = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
        if (!Rfc3161DerValidation.isCanonicalObjectIdentifier(fields, policy)) {
            throw malformed()
        }
        val imprint = required(fields, DerValues.TAG_SEQUENCE)
        val serial = required(fields, DerValues.TAG_INTEGER)
        if (!Rfc3161DerValidation.isCanonicalNonNegativeInteger(fields, serial)) {
            throw malformed()
        }
        val time = required(fields, DerValues.TAG_GENERALIZED_TIME)
        val generatedAt = Rfc3161TimeParser.parse(fields.content(time)) ?: throw malformed()
        return RequiredFields(imprint = imprint, generatedAt = generatedAt)
    }

    private fun messageImprint(
        source: DerReader,
        imprint: DerReader.Element,
    ): Pair<ByteArray, ByteArray> {
        val fields = source.children(imprint)
        val algorithm = required(fields, DerValues.TAG_SEQUENCE)
        val digest = required(fields, DerValues.TAG_OCTET_STRING)
        if (!fields.isAtEnd) {
            throw malformed()
        }
        return fields.raw(algorithm) to fields.content(digest)
    }

    private fun optionalFields(
        source: DerReader,
        fields: List<DerReader.Element>,
    ): ByteArray? {
        var index = FIRST_COLLECTION_INDEX
        if (fields.getOrNull(index)?.tag == DerValues.TAG_SEQUENCE) {
            validateAccuracy(source.children(fields[index]))
            index += COLLECTION_INDEX_STEP
        }
        if (fields.getOrNull(index)?.tag == DerValues.TAG_BOOLEAN) {
            val ordering = source.content(fields[index])
            try {
                if (!ordering.contentEquals(byteArrayOf(DerValues.DER_TRUE_BYTE))) {
                    throw malformed()
                }
            } finally {
                ordering.fill(ZERO_BYTE)
            }
            index += COLLECTION_INDEX_STEP
        }
        var nonce: ByteArray? = null
        if (fields.getOrNull(index)?.tag == DerValues.TAG_INTEGER) {
            if (!Rfc3161DerValidation.isCanonicalNonNegativeInteger(source, fields[index])) {
                throw malformed()
            }
            nonce = source.raw(fields[index])
            index += COLLECTION_INDEX_STEP
        }
        if (fields.getOrNull(index)?.tag == DerValues.TAG_CONTEXT_0_CONSTRUCTED) {
            validateTsaName(source.children(fields[index]))
            index += COLLECTION_INDEX_STEP
        }
        if (fields.getOrNull(index)?.tag == DerValues.TAG_CONTEXT_1_CONSTRUCTED) {
            validateTimestampExtensions(source.children(fields[index]))
            index += COLLECTION_INDEX_STEP
        }
        if (index != fields.size) {
            nonce?.fill(ZERO_BYTE)
            throw malformed()
        }
        return nonce
    }

    private fun validateAccuracy(reader: DerReader) {
        var count = EMPTY_COLLECTION_SIZE
        var candidate = reader.next()
        if (candidate?.tag == DerValues.TAG_INTEGER) {
            val seconds = Rfc3161DerValidation.nonNegativeLong(reader, candidate) ?: throw malformed()
            if (seconds < MINIMUM_ACCURACY_SECONDS) {
                throw malformed()
            }
            count += COLLECTION_COUNT_STEP
            candidate = reader.next()
        }
        for (tag in ACCURACY_SUBSECOND_TAGS) {
            if (candidate?.tag == tag) {
                val value = Rfc3161DerValidation.implicitNonNegativeLong(reader, candidate) ?: throw malformed()
                if (value !in MINIMUM_ACCURACY_SUBSECOND..MAXIMUM_ACCURACY_SUBSECOND) {
                    throw malformed()
                }
                count += COLLECTION_COUNT_STEP
                candidate = reader.next()
            }
        }
        if (candidate != null || !reader.isAtEnd || count == EMPTY_COLLECTION_SIZE) {
            throw malformed()
        }
    }

    private fun validateTsaName(reader: DerReader) {
        val name = reader.next() ?: throw malformed()
        if (!reader.isAtEnd) {
            throw malformed()
        }
        val accepted =
            when (name.tag) {
                DerValues.TAG_CONTEXT_4_CONSTRUCTED -> {
                    reader.content(name).isNotEmpty()
                }

                DerValues.TAG_CONTEXT_1_PRIMITIVE -> {
                    Rfc3161TextValidation.isMailbox(reader.content(name))
                }

                else -> {
                    false
                }
            }
        if (!accepted) {
            throw malformed()
        }
    }

    private fun validateTimestampExtensions(reader: DerReader) {
        val identifiers = mutableListOf<ByteArray>()
        while (!reader.isAtEnd) {
            val extension = required(reader, DerValues.TAG_SEQUENCE)
            val identifier = validateTimestampExtension(reader, extension)
            if (identifiers.any(identifier::contentEquals)) {
                throw malformed()
            }
            identifiers += identifier
        }
        if (identifiers.isEmpty()) {
            throw malformed()
        }
    }

    private fun validateTimestampExtension(
        source: DerReader,
        extension: DerReader.Element,
    ): ByteArray {
        val fields = source.children(extension)
        val identifier = required(fields, DerValues.TAG_OBJECT_IDENTIFIER)
        if (!Rfc3161DerValidation.isCanonicalObjectIdentifier(fields, identifier)) {
            throw malformed()
        }
        var value = fields.next() ?: throw malformed()
        if (value.tag == DerValues.TAG_BOOLEAN) {
            val critical = fields.content(value)
            try {
                if (
                    !critical.contentEquals(byteArrayOf(DerValues.DER_TRUE_BYTE)) &&
                    !critical.contentEquals(byteArrayOf(DerValues.DER_FALSE_BYTE))
                ) {
                    throw malformed()
                }
            } finally {
                critical.fill(ZERO_BYTE)
            }
            value = fields.next() ?: throw malformed()
        }
        if (value.tag != DerValues.TAG_OCTET_STRING || !fields.isAtEnd) {
            throw malformed()
        }
        return fields.raw(identifier)
    }

    private fun required(
        reader: DerReader,
        tag: Int,
    ): DerReader.Element = reader.next()?.takeIf { element -> element.tag == tag } ?: throw malformed()

    private fun malformed(): Rfc3161TimestampException =
        Rfc3161TimestampException(Rfc3161TimestampFailure.RESPONSE_MALFORMED)

    private const val TST_INFO_VERSION = 1L
    private const val EMPTY_COLLECTION_SIZE = 0
    private const val COLLECTION_COUNT_STEP = 1
    private const val COLLECTION_INDEX_STEP = 1
    private const val FIRST_COLLECTION_INDEX = 0
    private const val MINIMUM_ACCURACY_SECONDS = 1L
    private const val MINIMUM_ACCURACY_SUBSECOND = 1L
    private const val MAXIMUM_ACCURACY_SUBSECOND = 999L
    private const val ZERO_BYTE: Byte = 0
    private val ACCURACY_SUBSECOND_TAGS =
        listOf(
            DerValues.TAG_CONTEXT_0_PRIMITIVE,
            DerValues.TAG_CONTEXT_1_PRIMITIVE,
        )
}
