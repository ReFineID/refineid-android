package fi.refineid.android.browser

import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.Pin1Submission

/** Browser-neutral boundary over one retained card session. */
internal interface BrowserCardService {
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
