// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

/** Globally routable IPv6 policy, including recognized embedded IPv4 forms. */
internal object SigningNetworkIpv6Policy {
    fun isPublic(bytes: ByteArray): Boolean {
        if (bytes.size != IPV6_BYTE_COUNT || bytes.all { byte -> byte == ZERO_BYTE }) {
            return false
        }
        embeddedIpv4(bytes)?.let { address -> return SigningNetworkIpv4Policy.isPublic(address) }
        return isCurrentGlobalUnicast(bytes) &&
            !hasIetfProtocolAssignmentsPrefix(bytes) &&
            !bytes.startsWith(DOCUMENTATION_PREFIX) &&
            !hasDocumentationTwentyBitPrefix(bytes)
    }

    private fun embeddedIpv4(bytes: ByteArray): ByteArray? {
        if (bytes.copyOfRange(FIRST_OCTET_INDEX, IPV4_COMPATIBLE_PREFIX_LENGTH).all(::isZero)) {
            return bytes.copyOfRange(IPV4_SUFFIX_START, IPV6_BYTE_COUNT)
        }
        if (
            bytes.copyOfRange(FIRST_OCTET_INDEX, IPV4_MAPPED_PREFIX_LENGTH).all(::isZero) &&
            bytes
                .copyOfRange(IPV4_MAPPED_PREFIX_LENGTH, IPV4_SUFFIX_START)
                .contentEquals(IPV4_MAPPED_MARKER)
        ) {
            return bytes.copyOfRange(IPV4_SUFFIX_START, IPV6_BYTE_COUNT)
        }
        if (bytes.startsWith(WELL_KNOWN_NAT64_PREFIX)) {
            return bytes.copyOfRange(IPV4_SUFFIX_START, IPV6_BYTE_COUNT)
        }
        if (bytes.startsWith(SIX_TO_FOUR_PREFIX)) {
            return bytes.copyOfRange(SIX_TO_FOUR_IPV4_START, SIX_TO_FOUR_IPV4_END)
        }
        return null
    }

    private fun isCurrentGlobalUnicast(bytes: ByteArray): Boolean =
        bytes[FIRST_OCTET_INDEX].toUByte().toInt() in
            GLOBAL_UNICAST_FIRST_OCTET_FLOOR..GLOBAL_UNICAST_FIRST_OCTET_CEILING

    private fun hasIetfProtocolAssignmentsPrefix(bytes: ByteArray): Boolean =
        bytes[FIRST_OCTET_INDEX] == IETF_ASSIGNMENTS_FIRST_OCTET &&
            bytes[SECOND_OCTET_INDEX] == IETF_ASSIGNMENTS_SECOND_OCTET &&
            (bytes[THIRD_OCTET_INDEX].toUByte().toInt() and IETF_ASSIGNMENTS_THIRD_OCTET_MASK) ==
            IETF_ASSIGNMENTS_THIRD_OCTET_PREFIX

    private fun hasDocumentationTwentyBitPrefix(bytes: ByteArray): Boolean =
        bytes[FIRST_OCTET_INDEX] == DOCUMENTATION_TWENTY_BIT_FIRST_OCTET &&
            bytes[SECOND_OCTET_INDEX] == DOCUMENTATION_TWENTY_BIT_SECOND_OCTET &&
            (bytes[THIRD_OCTET_INDEX].toUByte().toInt() and HIGH_NIBBLE_MASK) == DOCUMENTATION_HIGH_NIBBLE

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean =
        size >= prefix.size && prefix.indices.all { index -> this[index] == prefix[index] }

    private fun isZero(byte: Byte): Boolean = byte == ZERO_BYTE

    private const val IPV6_BYTE_COUNT = 16
    private const val IPV4_BYTE_COUNT = 4
    private const val FIRST_OCTET_INDEX = 0
    private const val SECOND_OCTET_INDEX = 1
    private const val THIRD_OCTET_INDEX = 2
    private const val IPV4_COMPATIBLE_PREFIX_LENGTH = 12
    private const val IPV4_MAPPED_PREFIX_LENGTH = 10
    private const val IPV4_SUFFIX_START = IPV6_BYTE_COUNT - IPV4_BYTE_COUNT
    private const val SIX_TO_FOUR_IPV4_START = 2
    private const val SIX_TO_FOUR_IPV4_END = SIX_TO_FOUR_IPV4_START + IPV4_BYTE_COUNT
    private const val GLOBAL_UNICAST_FIRST_OCTET_FLOOR = 0x20
    private const val GLOBAL_UNICAST_FIRST_OCTET_CEILING = 0x3F
    private const val IETF_ASSIGNMENTS_FIRST_OCTET: Byte = 0x20
    private const val IETF_ASSIGNMENTS_SECOND_OCTET: Byte = 0x01
    private const val IETF_ASSIGNMENTS_THIRD_OCTET_MASK = 0xFE
    private const val IETF_ASSIGNMENTS_THIRD_OCTET_PREFIX = 0
    private const val HIGH_NIBBLE_MASK = 0xF0
    private const val DOCUMENTATION_HIGH_NIBBLE = 0
    private const val DOCUMENTATION_TWENTY_BIT_FIRST_OCTET: Byte = 0x3F
    private const val ZERO_BYTE: Byte = 0
    private val DOCUMENTATION_TWENTY_BIT_SECOND_OCTET = 0xFF.toByte()
    private val IPV4_MAPPED_MARKER = byteArrayOf(0xFF.toByte(), 0xFF.toByte())
    private val WELL_KNOWN_NAT64_PREFIX =
        byteArrayOf(
            0x00,
            0x64,
            0xFF.toByte(),
            0x9B.toByte(),
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        )
    private val SIX_TO_FOUR_PREFIX = byteArrayOf(0x20, 0x02)
    private val DOCUMENTATION_PREFIX = byteArrayOf(0x20, 0x01, 0x0D, 0xB8.toByte())
}
