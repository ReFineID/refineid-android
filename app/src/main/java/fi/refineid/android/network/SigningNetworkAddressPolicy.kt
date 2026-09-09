// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

internal fun interface SigningNetworkResolver {
    /** Every distinct numeric answer for one hostname, with no partial result. */
    fun resolve(host: String): List<InetAddress>
}

internal object SystemSigningNetworkResolver : SigningNetworkResolver {
    override fun resolve(host: String): List<InetAddress> = InetAddress.getAllByName(host).toList()
}

/** Static and resolver-backed target checks for certificate-controlled addresses. */
internal object SigningNetworkAddressPolicy {
    fun normalizedHost(host: String): String {
        val withoutBrackets = host.removePrefix(IPV6_LITERAL_OPEN).removeSuffix(IPV6_LITERAL_CLOSE)
        val lowercased = withoutBrackets.lowercase()
        return lowercased.removeSuffix(ABSOLUTE_DNS_NAME_SUFFIX)
    }

    fun hostCouldBePublic(host: String): Boolean {
        val normalized = normalizedHost(host)
        if (
            normalized.isEmpty() ||
            normalized.contains(IPV6_ZONE_SEPARATOR) ||
            isLocalName(normalized)
        ) {
            return false
        }
        numericAddress(normalized)?.let { address -> return isPublic(address) }
        return !looksLikeNumericAddress(normalized)
    }

    fun numericAddress(host: String): InetAddress? {
        val normalized = normalizedHost(host)
        strictIpv4(normalized)?.let { address -> return address }
        if (!normalized.contains(IPV6_COMPONENT_SEPARATOR)) {
            return null
        }
        return try {
            InetAddress.getByName(normalized)
        } catch (_: UnknownHostException) {
            null
        }
    }

    fun publicResolvedAddresses(
        host: String,
        resolver: SigningNetworkResolver,
    ): List<InetAddress> {
        val resolved =
            try {
                resolver.resolve(normalizedHost(host))
            } catch (_: Exception) {
                throw unsafeAddress()
            }
        val distinct = mutableListOf<InetAddress>()
        for (address in resolved) {
            if (distinct.none { existing -> existing.address.contentEquals(address.address) }) {
                distinct += address
                if (distinct.size > MAXIMUM_RESOLVED_ADDRESS_COUNT) {
                    throw unsafeAddress()
                }
            }
        }
        if (distinct.isEmpty() || distinct.any { address -> !isPublic(address) }) {
            throw unsafeAddress()
        }
        return distinct
    }

    fun isPublic(address: InetAddress): Boolean =
        when (address) {
            is Inet4Address -> SigningNetworkIpv4Policy.isPublic(address.address)
            is Inet6Address -> SigningNetworkIpv6Policy.isPublic(address.address)
            else -> false
        }

    private fun strictIpv4(host: String): Inet4Address? {
        val components = host.split(IPV4_COMPONENT_SEPARATOR)
        if (components.size != IPV4_COMPONENT_COUNT) {
            return null
        }
        val bytes = ByteArray(IPV4_COMPONENT_COUNT)
        for ((index, component) in components.withIndex()) {
            if (
                component.isEmpty() ||
                component.any { character -> character !in ASCII_ZERO..ASCII_NINE } ||
                (
                    component.length > SINGLE_DIGIT_LENGTH &&
                        component.startsWith(ASCII_ZERO)
                )
            ) {
                return null
            }
            val value =
                component.toIntOrNull()?.takeIf { candidate -> candidate <= UNSIGNED_BYTE_MAXIMUM }
                    ?: return null
            bytes[index] = value.toByte()
        }
        return try {
            InetAddress.getByAddress(bytes) as? Inet4Address
        } catch (_: UnknownHostException) {
            null
        }
    }

    private fun looksLikeNumericAddress(host: String): Boolean =
        host.all { character ->
            character in ASCII_ZERO..ASCII_NINE || character == IPV4_COMPONENT_SEPARATOR
        } || host.startsWith(HEXADECIMAL_LITERAL_PREFIX)

    private fun isLocalName(host: String): Boolean =
        host == LOCALHOST_NAME ||
            host.endsWith(LOCALHOST_SUFFIX) ||
            host == MULTICAST_DNS_NAME ||
            host.endsWith(MULTICAST_DNS_SUFFIX)

    private fun unsafeAddress(): SigningNetworkException = SigningNetworkException(SigningNetworkFailure.UNSAFE_ADDRESS)

    private const val IPV4_COMPONENT_COUNT = 4
    private const val MAXIMUM_RESOLVED_ADDRESS_COUNT = 8
    private const val UNSIGNED_BYTE_MAXIMUM = 255
    private const val SINGLE_DIGIT_LENGTH = 1
    private const val IPV4_COMPONENT_SEPARATOR = '.'
    private const val IPV6_COMPONENT_SEPARATOR = ':'
    private const val IPV6_ZONE_SEPARATOR = '%'
    private const val IPV6_LITERAL_OPEN = "["
    private const val IPV6_LITERAL_CLOSE = "]"
    private const val ABSOLUTE_DNS_NAME_SUFFIX = "."
    private const val LOCALHOST_NAME = "localhost"
    private const val LOCALHOST_SUFFIX = ".localhost"
    private const val MULTICAST_DNS_NAME = "local"
    private const val MULTICAST_DNS_SUFFIX = ".local"
    private const val HEXADECIMAL_LITERAL_PREFIX = "0x"
    private const val ASCII_ZERO = '0'
    private const val ASCII_NINE = '9'
}

/** Globally routable IPv4 policy for certificate-published endpoints. */
internal object SigningNetworkIpv4Policy {
    fun isPublic(bytes: ByteArray): Boolean {
        if (bytes.size != IPV4_BYTE_COUNT) {
            return false
        }
        val first = bytes[FIRST_OCTET_INDEX].toUByte().toInt()
        val second = bytes[SECOND_OCTET_INDEX].toUByte().toInt()
        val third = bytes[THIRD_OCTET_INDEX].toUByte().toInt()
        return !isPrivateOrSpecial(first, second) &&
            !isDocumentation(first, second, third) &&
            !isDeprecatedRelay(first, second, third)
    }

    private fun isPrivateOrSpecial(
        first: Int,
        second: Int,
    ): Boolean {
        if (
            first == UNSPECIFIED_FIRST_OCTET ||
            first == PRIVATE_TEN_FIRST_OCTET ||
            first == LOOPBACK_FIRST_OCTET ||
            first >= MULTICAST_FIRST_OCTET
        ) {
            return true
        }
        return when (first) {
            SHARED_FIRST_OCTET -> {
                second in SHARED_SECOND_OCTET_FLOOR..SHARED_SECOND_OCTET_CEILING
            }

            LINK_LOCAL_FIRST_OCTET -> {
                second == LINK_LOCAL_SECOND_OCTET
            }

            PRIVATE_172_FIRST_OCTET -> {
                second in PRIVATE_172_SECOND_OCTET_FLOOR..PRIVATE_172_SECOND_OCTET_CEILING
            }

            PRIVATE_192_FIRST_OCTET -> {
                second == PRIVATE_192_SECOND_OCTET || second == SPECIAL_PURPOSE_SECOND_OCTET
            }

            BENCHMARK_FIRST_OCTET -> {
                second == BENCHMARK_FIRST_SECOND_OCTET || second == BENCHMARK_SECOND_SECOND_OCTET
            }

            else -> {
                false
            }
        }
    }

    private fun isDocumentation(
        first: Int,
        second: Int,
        third: Int,
    ): Boolean =
        (
            first == DOCUMENTATION_ONE_FIRST_OCTET &&
                second == DOCUMENTATION_ONE_SECOND_OCTET &&
                third == DOCUMENTATION_ONE_THIRD_OCTET
        ) ||
            (
                first == DOCUMENTATION_TWO_FIRST_OCTET &&
                    second == DOCUMENTATION_TWO_SECOND_OCTET &&
                    third == DOCUMENTATION_TWO_THIRD_OCTET
            ) ||
            (
                first == DOCUMENTATION_THREE_FIRST_OCTET &&
                    second == DOCUMENTATION_THREE_SECOND_OCTET &&
                    third == DOCUMENTATION_THREE_THIRD_OCTET
            )

    private fun isDeprecatedRelay(
        first: Int,
        second: Int,
        third: Int,
    ): Boolean =
        (
            first == DEPRECATED_RELAY_FIRST_OCTET &&
                second == DEPRECATED_RELAY_SECOND_OCTET &&
                third == DEPRECATED_RELAY_THIRD_OCTET
        )

    private const val IPV4_BYTE_COUNT = 4
    private const val FIRST_OCTET_INDEX = 0
    private const val SECOND_OCTET_INDEX = 1
    private const val THIRD_OCTET_INDEX = 2
    private const val UNSPECIFIED_FIRST_OCTET = 0
    private const val PRIVATE_TEN_FIRST_OCTET = 10
    private const val LOOPBACK_FIRST_OCTET = 127
    private const val MULTICAST_FIRST_OCTET = 224
    private const val SHARED_FIRST_OCTET = 100
    private const val SHARED_SECOND_OCTET_FLOOR = 64
    private const val SHARED_SECOND_OCTET_CEILING = 127
    private const val LINK_LOCAL_FIRST_OCTET = 169
    private const val LINK_LOCAL_SECOND_OCTET = 254
    private const val PRIVATE_172_FIRST_OCTET = 172
    private const val PRIVATE_172_SECOND_OCTET_FLOOR = 16
    private const val PRIVATE_172_SECOND_OCTET_CEILING = 31
    private const val PRIVATE_192_FIRST_OCTET = 192
    private const val PRIVATE_192_SECOND_OCTET = 168
    private const val SPECIAL_PURPOSE_SECOND_OCTET = 0
    private const val BENCHMARK_FIRST_OCTET = 198
    private const val BENCHMARK_FIRST_SECOND_OCTET = 18
    private const val BENCHMARK_SECOND_SECOND_OCTET = 19
    private const val DOCUMENTATION_ONE_FIRST_OCTET = 192
    private const val DOCUMENTATION_ONE_SECOND_OCTET = 0
    private const val DOCUMENTATION_ONE_THIRD_OCTET = 2
    private const val DOCUMENTATION_TWO_FIRST_OCTET = 198
    private const val DOCUMENTATION_TWO_SECOND_OCTET = 51
    private const val DOCUMENTATION_TWO_THIRD_OCTET = 100
    private const val DOCUMENTATION_THREE_FIRST_OCTET = 203
    private const val DOCUMENTATION_THREE_SECOND_OCTET = 0
    private const val DOCUMENTATION_THREE_THIRD_OCTET = 113
    private const val DEPRECATED_RELAY_FIRST_OCTET = 192
    private const val DEPRECATED_RELAY_SECOND_OCTET = 88
    private const val DEPRECATED_RELAY_THIRD_OCTET = 99
}
