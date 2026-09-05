package fi.refineid.android.core

/** Holder-facing boundary for PIN2 preflight and one qualified signature. */
internal interface QualifiedSigningService {
    fun requestPin2Preflight(onResult: (NativePin2PreflightResult) -> Unit)

    fun requestQualifiedSignature(
        algorithm: QualifiedSigningAlgorithm,
        pin2: Pin2Submission,
        content: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
        onResult: (QualifiedSignResult) -> Unit,
    )

    fun requestQualifiedDigestSignature(
        algorithm: QualifiedSigningAlgorithm,
        pin2: Pin2Submission,
        digest: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
        onResult: (QualifiedSignResult) -> Unit,
    )
}

internal interface QualifiedCardService :
    QualifiedCertificateService,
    QualifiedSigningService
