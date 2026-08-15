package fi.refineid.android.core

/** Consumer-neutral boundary over one retained, locally verified card session. */
internal interface AuthenticationCardService {
    fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit)

    fun signAuthenticationMessage(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        message: ByteArray,
    ): AuthenticationSignResult

    fun signAuthenticationDigest(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        digest: ByteArray,
    ): AuthenticationSignResult
}
