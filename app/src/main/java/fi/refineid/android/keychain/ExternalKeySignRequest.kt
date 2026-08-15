package fi.refineid.android.keychain

import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.acceptsInputLength
import java.security.MessageDigest

/** Closed alias vocabulary exported by the privileged KeyChain provider. */
internal enum class ExternalKeyAlias(
    val wireValue: String,
) {
    AUTHENTICATION("refineid-authentication"),
    ;

    companion object {
        fun fromWireValue(value: String): ExternalKeyAlias? = entries.firstOrNull { alias -> alias.wireValue == value }
    }
}

@JvmInline
internal value class ExternalKeyCallerUid(
    val value: Int,
) {
    init {
        require(value >= MINIMUM_CALLER_UID) {
            "external-key caller UID must not be negative"
        }
    }

    private companion object {
        const val MINIMUM_CALLER_UID = 0
    }
}

@JvmInline
internal value class ExternalKeyProviderGeneration(
    val value: Long,
) {
    init {
        require(value >= INITIAL_PROVIDER_GENERATION) {
            "external-key provider generation must be positive"
        }
    }

    private companion object {
        const val INITIAL_PROVIDER_GENERATION = 1L
    }
}

/** One validated exact-digest request received from the trusted KeyChain service. */
internal class ExternalKeySignRequest private constructor(
    val callerUid: ExternalKeyCallerUid,
    val alias: ExternalKeyAlias,
    val providerGeneration: ExternalKeyProviderGeneration,
    val algorithm: AuthenticationSigningAlgorithm,
    private var ownedDigest: ByteArray?,
) : AutoCloseable {
    val digestLength: Int
        get() = algorithm.digestLength

    internal fun copyDigest(): ByteArray =
        synchronized(this) {
            requireDigest().copyOf()
        }

    internal fun matches(
        callerUid: ExternalKeyCallerUid,
        alias: ExternalKeyAlias,
        providerGeneration: ExternalKeyProviderGeneration,
        algorithm: AuthenticationSigningAlgorithm,
        digest: ByteArray,
    ): Boolean {
        if (
            this.callerUid != callerUid ||
            this.alias != alias ||
            this.providerGeneration != providerGeneration ||
            this.algorithm != algorithm
        ) {
            return false
        }
        return synchronized(this) {
            MessageDigest.isEqual(requireDigest(), digest)
        }
    }

    override fun close() {
        synchronized(this) {
            ownedDigest?.fill(CLEARED_BYTE)
            ownedDigest = null
        }
    }

    override fun toString(): String =
        synchronized(this) {
            "ExternalKeySignRequest(" +
                "alias=" + alias +
                ", generation=" + providerGeneration.value +
                ", algorithm=" + algorithm +
                ", digestLength=" + digestLength +
                ", closed=" + (ownedDigest == null) +
                ")"
        }

    private fun requireDigest(): ByteArray =
        checkNotNull(ownedDigest) {
            "external-key sign request is closed"
        }

    companion object {
        fun create(
            callerUid: ExternalKeyCallerUid,
            alias: ExternalKeyAlias,
            providerGeneration: ExternalKeyProviderGeneration,
            algorithm: AuthenticationSigningAlgorithm,
            digest: ByteArray,
        ): ExternalKeySignRequest {
            require(
                algorithm.acceptsInputLength(
                    AuthenticationSigningInputMode.PREHASHED,
                    digest.size,
                ),
            ) {
                "external-key digest length does not match the algorithm"
            }
            return ExternalKeySignRequest(
                callerUid = callerUid,
                alias = alias,
                providerGeneration = providerGeneration,
                algorithm = algorithm,
                ownedDigest = digest.copyOf(),
            )
        }

        private const val CLEARED_BYTE: Byte = 0
    }
}
