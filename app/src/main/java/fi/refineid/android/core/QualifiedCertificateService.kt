package fi.refineid.android.core

/** Credential-free access to the qualified-signature certificate. */
internal interface QualifiedCertificateService {
    fun requestQualifiedCertificate(onResult: (NativeCertificateReadResult<NativeQualifiedCertificate>) -> Unit)
}
