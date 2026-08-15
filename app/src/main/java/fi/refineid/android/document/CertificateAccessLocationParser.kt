// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.net.URI
import java.net.URISyntaxException

internal data class CertificateAuthorityAccessLocations(
    val issuerCertificates: List<String>,
    val ocspResponders: List<String>,
)

/** Strict HTTP(S) URI extraction from X.509 AIA and CRL extensions. */
internal object CertificateAccessLocationParser {
    fun authorityInformation(encoded: ByteArray): CertificateAuthorityAccessLocations? {
        val outer = DerReader(encoded)
        val sequence = outer.next() ?: return null
        if (sequence.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
            return null
        }
        val entries = outer.children(sequence)
        val issuers = mutableListOf<String>()
        val responders = mutableListOf<String>()
        while (!entries.isAtEnd) {
            val entry = entries.next() ?: return null
            if (entry.tag != DerValues.TAG_SEQUENCE) {
                return null
            }
            val fields = entries.children(entry)
            val method = fields.next() ?: return null
            val location = fields.next() ?: return null
            if (!validAccessDescription(fields, method)) {
                return null
            }
            val address = httpAddress(fields, location)
            if (address != null) {
                addAccessAddress(fields.raw(method), address, issuers, responders)
            }
        }
        return CertificateAuthorityAccessLocations(
            issuerCertificates = issuers,
            ocspResponders = responders,
        )
    }

    fun revocationLists(encoded: ByteArray): List<String>? {
        val outer = DerReader(encoded)
        val sequence = outer.next() ?: return null
        if (sequence.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
            return null
        }
        val points = outer.children(sequence)
        val addresses = mutableListOf<String>()
        while (!points.isAtEnd) {
            val point = points.next() ?: return null
            if (point.tag != DerValues.TAG_SEQUENCE) {
                return null
            }
            val fields = points.children(point)
            while (!fields.isAtEnd) {
                val field = fields.next() ?: return null
                if (field.tag == DerValues.TAG_CONTEXT_0_CONSTRUCTED) {
                    appendDistinct(addresses, fullNameAddresses(fields, field))
                }
            }
        }
        return addresses
    }

    private fun validAccessDescription(
        fields: DerReader,
        method: DerReader.Element,
    ): Boolean =
        method.tag == DerValues.TAG_OBJECT_IDENTIFIER &&
            Rfc3161DerValidation.isCanonicalObjectIdentifier(fields, method) &&
            fields.isAtEnd

    private fun addAccessAddress(
        encodedMethod: ByteArray,
        address: String,
        issuers: MutableList<String>,
        responders: MutableList<String>,
    ) {
        try {
            when {
                encodedMethod.contentEquals(CA_ISSUERS_ACCESS_METHOD) -> {
                    appendDistinct(issuers, listOf(address))
                }

                encodedMethod.contentEquals(OCSP_ACCESS_METHOD) -> {
                    appendDistinct(responders, listOf(address))
                }
            }
        } finally {
            encodedMethod.fill(ZERO_BYTE)
        }
    }

    private fun fullNameAddresses(
        fields: DerReader,
        distributionPoint: DerReader.Element,
    ): List<String> {
        val named = fields.children(distributionPoint)
        val fullName = named.next() ?: return emptyList()
        if (fullName.tag != DerValues.TAG_CONTEXT_0_CONSTRUCTED || !named.isAtEnd) {
            return emptyList()
        }
        val names = named.children(fullName)
        val addresses = mutableListOf<String>()
        while (!names.isAtEnd) {
            val name = names.next() ?: return emptyList()
            httpAddress(names, name)?.let(addresses::add)
        }
        return addresses
    }

    private fun httpAddress(
        reader: DerReader,
        element: DerReader.Element,
    ): String? {
        if (element.tag != DerValues.TAG_CONTEXT_6_PRIMITIVE) {
            return null
        }
        val content = reader.content(element)
        return try {
            if (!isVisibleAsciiAddress(content)) {
                return null
            }
            val address = content.toString(Charsets.US_ASCII)
            val uri = try {
                URI(address)
            } catch (_: URISyntaxException) {
                return null
            }
            if (isPermittedHttpUri(uri)) address else null
        } finally {
            content.fill(ZERO_BYTE)
        }
    }

    private fun isVisibleAsciiAddress(content: ByteArray): Boolean =
        content.isNotEmpty() &&
            content.size <= MAXIMUM_URI_BYTES &&
            content.all { byte -> byte.toUnsignedInt() in MINIMUM_VISIBLE_ASCII..MAXIMUM_VISIBLE_ASCII }

    private fun isPermittedHttpUri(uri: URI): Boolean =
        uri.scheme?.lowercase() in HTTP_SCHEMES &&
            !uri.host.isNullOrEmpty() &&
            uri.rawUserInfo == null &&
            uri.rawFragment == null

    private fun appendDistinct(
        destination: MutableList<String>,
        values: List<String>,
    ) {
        for (value in values) {
            if (value !in destination) {
                destination += value
            }
        }
    }

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private const val MAXIMUM_URI_BYTES = 2_048
    private const val MINIMUM_VISIBLE_ASCII = 0x21
    private const val MAXIMUM_VISIBLE_ASCII = 0x7E
    private const val ZERO_BYTE: Byte = 0

    private val HTTP_SCHEMES = setOf("http", "https")
    private val CA_ISSUERS_ACCESS_METHOD =
        DerEncoder.objectIdentifier(CertificateOids.CA_ISSUERS_ACCESS_METHOD)
    private val OCSP_ACCESS_METHOD =
        DerEncoder.objectIdentifier(CertificateOids.OCSP_ACCESS_METHOD)
}
