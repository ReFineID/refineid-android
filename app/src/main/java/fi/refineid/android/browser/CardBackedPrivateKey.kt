package fi.refineid.android.browser

import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.NativeAuthenticationSignature
import java.security.PrivateKey
import java.security.SignatureException

/** Synchronous non-exportable key operation used by browser TLS engines. */
internal fun interface CardSignatureOperation {
    @Throws(SignatureException::class)
    fun sign(
        algorithm: AuthenticationSigningAlgorithm,
        message: ByteArray,
    ): NativeAuthenticationSignature
}

/** A JCA key handle whose private material remains on the identity card. */
internal class CardBackedPrivateKey(
    private val keyAlgorithm: String,
    internal val operation: CardSignatureOperation,
) : PrivateKey {
    override fun getAlgorithm(): String = keyAlgorithm

    override fun getFormat(): String? = null

    override fun getEncoded(): ByteArray? = null

    override fun toString(): String = "CardBackedPrivateKey(algorithm=$keyAlgorithm)"

    private companion object {
        @Suppress("unused")
        const val serialVersionUID: Long = 1
    }
}
