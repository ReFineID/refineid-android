// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedSignature
import fi.refineid.android.core.P384EcdsaSignature
import fi.refineid.android.core.QualifiedSignatureVerifier
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import java.security.MessageDigest

internal enum class QualifiedDocumentCmsFailure {
    DOCUMENT_DIGEST_MALFORMED,
    CERTIFICATE_UNPARSEABLE,
    CERTIFICATE_PROFILE_MISMATCH,
    SIGNATURE_MALFORMED,
    SIGNED_ATTRIBUTES_MALFORMED,
    TIMESTAMP_MISSING,
    TIMESTAMP_IMPRINT_MISMATCH,
    TIMESTAMP_TOKEN_UNAVAILABLE,
}

internal class QualifiedDocumentCmsException(
    val kind: QualifiedDocumentCmsFailure,
) : IllegalArgumentException(kind.name)

/** Canonical detached CMS SignedData for one PAdES qualified signature. */
internal object QualifiedDocumentCms {
    fun signedAttributes(
        byteRangeDigest: ByteArray,
        signerCertificate: NativeQualifiedCertificate,
    ): ByteArray {
        if (byteRangeDigest.size != SHA384_DIGEST_LENGTH_BYTES) {
            throw QualifiedDocumentCmsException(
                QualifiedDocumentCmsFailure.DOCUMENT_DIGEST_MALFORMED,
            )
        }
        val certificateDer = signerCertificate.copyDer()
        return try {
            signedAttributes(
                byteRangeDigest = byteRangeDigest,
                signerCertificateDer = certificateDer,
            )
        } finally {
            certificateDer.fill(ZERO_BYTE)
        }
    }

    fun signatureTimestampDigest(signature: NativeQualifiedSignature): ByteArray {
        requireSignatureShape(signature)
        val signatureValue = cmsSignatureValue(signature)
        return try {
            sha384(signatureValue)
        } finally {
            signatureValue.fill(ZERO_BYTE)
        }
    }

    fun assemble(
        signedAttributesSet: ByteArray,
        signature: NativeQualifiedSignature,
        signerCertificate: NativeQualifiedCertificate,
    ): ByteArray =
        assemble(
            signedAttributesSet = signedAttributesSet,
            signature = signature,
            signerCertificate = signerCertificate,
            timestampTokens = emptyList(),
        )

    fun assembleTimestamped(
        signedAttributesSet: ByteArray,
        signature: NativeQualifiedSignature,
        signerCertificate: NativeQualifiedCertificate,
        timestampTokens: List<VerifiedTimestampToken>,
    ): ByteArray {
        if (timestampTokens.isEmpty()) {
            throw QualifiedDocumentCmsException(QualifiedDocumentCmsFailure.TIMESTAMP_MISSING)
        }
        return assemble(
            signedAttributesSet = signedAttributesSet,
            signature = signature,
            signerCertificate = signerCertificate,
            timestampTokens = timestampTokens,
        )
    }

    private fun assemble(
        signedAttributesSet: ByteArray,
        signature: NativeQualifiedSignature,
        signerCertificate: NativeQualifiedCertificate,
        timestampTokens: List<VerifiedTimestampToken>,
    ): ByteArray {
        if (signature.algorithm.keyProfile != signerCertificate.keyProfile) {
            throw QualifiedDocumentCmsException(
                QualifiedDocumentCmsFailure.CERTIFICATE_PROFILE_MISMATCH,
            )
        }
        requireSignatureShape(signature)
        val certificateDer = signerCertificate.copyDer()
        val signatureValue = cmsSignatureValue(signature)
        val encodedTimestampTokens = mutableListOf<ByteArray>()
        return try {
            QualifiedDocumentCmsValidation.validateSignedAttributes(
                signedAttributesSet = signedAttributesSet,
                signerCertificateDer = certificateDer,
            )
            QualifiedDocumentCmsValidation.validateCertificateProfile(
                certificateDer = certificateDer,
                expectedProfile = signerCertificate.keyProfile,
            )
            if (
                !QualifiedSignatureVerifier.verify(
                    certificate = signerCertificate,
                    content = signedAttributesSet,
                    signature = signature,
                )
            ) {
                throw QualifiedDocumentCmsException(
                    QualifiedDocumentCmsFailure.SIGNATURE_MALFORMED,
                )
            }
            requireTimestampBindings(
                timestampTokens = timestampTokens,
                signatureValue = signatureValue,
                encodedTimestampTokens = encodedTimestampTokens,
            )
            assembleValidated(
                signedAttributesSet = signedAttributesSet,
                signatureValue = signatureValue,
                algorithm = signature.algorithm,
                signerCertificateDer = certificateDer,
                timestampTokens = encodedTimestampTokens,
            )
        } finally {
            certificateDer.fill(ZERO_BYTE)
            signatureValue.fill(ZERO_BYTE)
            encodedTimestampTokens.forEach { token -> token.fill(ZERO_BYTE) }
        }
    }

    internal fun signedAttributes(
        byteRangeDigest: ByteArray,
        signerCertificateDer: ByteArray,
    ): ByteArray {
        if (byteRangeDigest.size != SHA384_DIGEST_LENGTH_BYTES) {
            throw QualifiedDocumentCmsException(
                QualifiedDocumentCmsFailure.DOCUMENT_DIGEST_MALFORMED,
            )
        }
        val contentType =
            attribute(
                oid = QualifiedCmsOids.CONTENT_TYPE,
                value = DerEncoder.objectIdentifier(QualifiedCmsOids.DATA),
            )
        val messageDigest =
            attribute(
                oid = QualifiedCmsOids.MESSAGE_DIGEST,
                value = DerEncoder.octetString(byteRangeDigest),
            )
        val certificateHash = sha384(signerCertificateDer)
        val signingCertificate =
            try {
                val essCertId =
                    DerEncoder.sequence(
                        listOf(
                            sha384AlgorithmIdentifier(),
                            DerEncoder.octetString(certificateHash),
                        ),
                    )
                attribute(
                    oid = QualifiedCmsOids.SIGNING_CERTIFICATE_V2,
                    value =
                        DerEncoder.sequence(
                            listOf(
                                DerEncoder.sequence(listOf(essCertId)),
                            ),
                        ),
                )
            } finally {
                certificateHash.fill(ZERO_BYTE)
            }
        return DerEncoder.setOf(
            listOf(
                contentType,
                messageDigest,
                signingCertificate,
            ),
        )
    }

    private fun assembleValidated(
        signedAttributesSet: ByteArray,
        signatureValue: ByteArray,
        algorithm: QualifiedSigningAlgorithm,
        signerCertificateDer: ByteArray,
        timestampTokens: List<ByteArray>,
    ): ByteArray {
        val signerInfo =
            mutableListOf(
                DerEncoder.integer(SIGNER_INFO_VERSION),
                QualifiedDocumentCmsValidation.issuerAndSerial(signerCertificateDer),
                sha384AlgorithmIdentifier(),
                DerEncoder.retagged(
                    encoded = signedAttributesSet,
                    tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                ),
                signatureAlgorithmIdentifier(algorithm),
                DerEncoder.octetString(signatureValue),
            )
        timestampAttributes(timestampTokens)?.let(signerInfo::add)

        val signedData =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.integer(SIGNED_DATA_VERSION),
                    DerEncoder.setOf(listOf(sha384AlgorithmIdentifier())),
                    DerEncoder.sequence(
                        listOf(DerEncoder.objectIdentifier(QualifiedCmsOids.DATA)),
                    ),
                    DerEncoder.tlv(
                        tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                        content = signerCertificateDer,
                    ),
                    DerEncoder.setOf(listOf(DerEncoder.sequence(signerInfo))),
                ),
            )
        return DerEncoder.sequence(
            listOf(
                DerEncoder.objectIdentifier(QualifiedCmsOids.SIGNED_DATA),
                DerEncoder.tlv(
                    tag = DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                    content = signedData,
                ),
            ),
        )
    }

    private fun requireTimestampBindings(
        timestampTokens: List<VerifiedTimestampToken>,
        signatureValue: ByteArray,
        encodedTimestampTokens: MutableList<ByteArray>,
    ) {
        if (timestampTokens.isEmpty()) {
            return
        }
        val imprint = sha384(signatureValue)
        try {
            for (token in timestampTokens) {
                val matches =
                    try {
                        token.matchesMessageImprint(imprint)
                    } catch (_: IllegalStateException) {
                        throw QualifiedDocumentCmsException(
                            QualifiedDocumentCmsFailure.TIMESTAMP_TOKEN_UNAVAILABLE,
                        )
                    }
                if (!matches) {
                    throw QualifiedDocumentCmsException(
                        QualifiedDocumentCmsFailure.TIMESTAMP_IMPRINT_MISMATCH,
                    )
                }
                encodedTimestampTokens +=
                    try {
                        token.copyEncoding()
                    } catch (_: IllegalStateException) {
                        throw QualifiedDocumentCmsException(
                            QualifiedDocumentCmsFailure.TIMESTAMP_TOKEN_UNAVAILABLE,
                        )
                    }
            }
        } finally {
            imprint.fill(ZERO_BYTE)
        }
    }

    private fun timestampAttributes(tokens: List<ByteArray>): ByteArray? {
        if (tokens.isEmpty()) {
            return null
        }
        val unique = mutableListOf<ByteArray>()
        try {
            for (token in tokens) {
                val attribute =
                    attribute(
                        oid = QualifiedCmsOids.SIGNATURE_TIMESTAMP_TOKEN,
                        value = token,
                    )
                if (unique.any { existing -> existing.contentEquals(attribute) }) {
                    attribute.fill(ZERO_BYTE)
                } else {
                    unique += attribute
                }
            }
            val set = DerEncoder.setOf(unique)
            return try {
                DerEncoder.retagged(
                    encoded = set,
                    tag = DerValues.TAG_CONTEXT_1_CONSTRUCTED,
                )
            } finally {
                set.fill(ZERO_BYTE)
            }
        } finally {
            unique.forEach { attribute -> attribute.fill(ZERO_BYTE) }
        }
    }

    private fun cmsSignatureValue(signature: NativeQualifiedSignature): ByteArray =
        signature.useBytes { rawSignature ->
            when (signature.algorithm) {
                QualifiedSigningAlgorithm.RSA_PKCS1_SHA384 -> {
                    rawSignature.copyOf()
                }

                QualifiedSigningAlgorithm.ECDSA_P384_SHA384 -> {
                    P384EcdsaSignature.toDer(rawSignature)
                }
            }
        }

    private fun requireSignatureShape(signature: NativeQualifiedSignature) {
        if (signature.length != signature.algorithm.signatureLength) {
            throw QualifiedDocumentCmsException(
                QualifiedDocumentCmsFailure.SIGNATURE_MALFORMED,
            )
        }
    }

    private fun signatureAlgorithmIdentifier(algorithm: QualifiedSigningAlgorithm): ByteArray =
        when (algorithm) {
            QualifiedSigningAlgorithm.RSA_PKCS1_SHA384 -> {
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.objectIdentifier(QualifiedCmsOids.SHA384_WITH_RSA),
                        DerEncoder.nullValue(),
                    ),
                )
            }

            QualifiedSigningAlgorithm.ECDSA_P384_SHA384 -> {
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.objectIdentifier(QualifiedCmsOids.ECDSA_WITH_SHA384),
                    ),
                )
            }
        }

    private fun sha384AlgorithmIdentifier(): ByteArray =
        DerEncoder.sequence(
            listOf(DerEncoder.objectIdentifier(QualifiedCmsOids.SHA384)),
        )

    private fun attribute(
        oid: String,
        value: ByteArray,
    ): ByteArray =
        DerEncoder.sequence(
            listOf(
                DerEncoder.objectIdentifier(oid),
                DerEncoder.setOf(listOf(value)),
            ),
        )

    private fun sha384(bytes: ByteArray): ByteArray = MessageDigest.getInstance(SHA384_DIGEST_ALGORITHM).digest(bytes)

    private const val SIGNED_DATA_VERSION = 1
    private const val SIGNER_INFO_VERSION = 1
    private const val SHA384_DIGEST_ALGORITHM = "SHA-384"
    private const val ZERO_BYTE: Byte = 0
}

internal object QualifiedCmsOids {
    const val DATA = "1.2.840.113549.1.7.1"
    const val SIGNED_DATA = "1.2.840.113549.1.7.2"
    const val CONTENT_TYPE = "1.2.840.113549.1.9.3"
    const val MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
    const val SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"
    const val SIGNATURE_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14"
    const val SHA384 = "2.16.840.1.101.3.4.2.2"
    const val ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3"
    const val SHA384_WITH_RSA = "1.2.840.113549.1.1.12"
}
