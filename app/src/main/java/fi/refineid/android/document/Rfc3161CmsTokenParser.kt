// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** Locates TSTInfo and its algorithm identifier without authenticating CMS. */
internal object Rfc3161CmsTokenParser {
    fun tstInfoContent(token: ByteArray): ByteArray {
        val encapsulated = encapsulatedContentInfo(token, signedData(token))
        val content = DerReader(token).children(encapsulated)
        val contentType = required(content, DerValues.TAG_OBJECT_IDENTIFIER)
        val wrapper = required(content, DerValues.TAG_CONTEXT_0_CONSTRUCTED)
        if (
            !content.raw(contentType).contentEquals(
                DerEncoder.objectIdentifier(Rfc3161Oids.TST_INFO),
            ) ||
            !content.isAtEnd
        ) {
            throw malformed()
        }
        val explicit = content.children(wrapper)
        val octets = required(explicit, DerValues.TAG_OCTET_STRING)
        if (!explicit.isAtEnd) {
            throw malformed()
        }
        return explicit.content(octets)
    }

    fun isSha384(encoded: ByteArray): Boolean {
        val outer = DerReader(encoded)
        val sequence = outer.next() ?: return false
        if (sequence.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
            return false
        }
        val fields = outer.children(sequence)
        val identifier = fields.next() ?: return false
        if (
            identifier.tag != DerValues.TAG_OBJECT_IDENTIFIER ||
            !fields.raw(identifier).contentEquals(
                DerEncoder.objectIdentifier(QualifiedCmsOids.SHA384),
            )
        ) {
            return false
        }
        val parameters = fields.next() ?: return fields.isAtEnd
        return parameters.tag == DerValues.TAG_NULL &&
            fields.content(parameters).isEmpty() &&
            fields.isAtEnd
    }

    private fun signedData(token: ByteArray): DerReader.Element {
        val outer = DerReader(token)
        val contentInfo = required(outer, DerValues.TAG_SEQUENCE)
        if (!outer.isAtEnd) {
            throw malformed()
        }
        val info = outer.children(contentInfo)
        val type = required(info, DerValues.TAG_OBJECT_IDENTIFIER)
        val wrapper = required(info, DerValues.TAG_CONTEXT_0_CONSTRUCTED)
        if (
            !info.raw(type).contentEquals(
                DerEncoder.objectIdentifier(QualifiedCmsOids.SIGNED_DATA),
            ) ||
            !info.isAtEnd
        ) {
            throw malformed()
        }
        val wrapped = info.children(wrapper)
        val signedData = required(wrapped, DerValues.TAG_SEQUENCE)
        if (!wrapped.isAtEnd) {
            throw malformed()
        }
        return signedData
    }

    private fun encapsulatedContentInfo(
        token: ByteArray,
        signedData: DerReader.Element,
    ): DerReader.Element {
        val signed = DerReader(token).children(signedData)
        required(signed, DerValues.TAG_INTEGER)
        required(signed, DerValues.TAG_SET)
        return required(signed, DerValues.TAG_SEQUENCE)
    }

    private fun required(
        reader: DerReader,
        tag: Int,
    ): DerReader.Element = reader.next()?.takeIf { element -> element.tag == tag } ?: throw malformed()

    private fun malformed(): Rfc3161TimestampException =
        Rfc3161TimestampException(Rfc3161TimestampFailure.RESPONSE_MALFORMED)
}
