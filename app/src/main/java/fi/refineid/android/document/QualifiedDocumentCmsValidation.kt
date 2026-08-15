// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.core.P384_COORDINATE_LENGTH_BITS
import fi.refineid.android.core.RSA_3072_KEY_LENGTH_BITS
import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/** Strict validation and certificate-field extraction for qualified CMS. */
internal object QualifiedDocumentCmsValidation {
    fun validateSignedAttributes(
        signedAttributesSet: ByteArray,
        signerCertificateDer: ByteArray,
    ) {
        val byteRangeDigest =
            byteRangeDigest(signedAttributesSet)
                ?: throw failure(QualifiedDocumentCmsFailure.SIGNED_ATTRIBUTES_MALFORMED)
        val canonical =
            QualifiedDocumentCms.signedAttributes(
                byteRangeDigest = byteRangeDigest,
                signerCertificateDer = signerCertificateDer,
            )
        try {
            if (!signedAttributesSet.contentEquals(canonical)) {
                throw failure(QualifiedDocumentCmsFailure.SIGNED_ATTRIBUTES_MALFORMED)
            }
        } finally {
            byteRangeDigest.fill(ZERO_BYTE)
            canonical.fill(ZERO_BYTE)
        }
    }

    fun validateCertificateProfile(
        certificateDer: ByteArray,
        expectedProfile: NativeCardKeyProfile,
    ) {
        val certificate =
            try {
                CertificateFactory
                    .getInstance(X509_CERTIFICATE_TYPE)
                    .generateCertificate(certificateDer.inputStream()) as? X509Certificate
            } catch (_: CertificateException) {
                null
            } catch (_: RuntimeException) {
                null
            } ?: throw failure(QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE)
        val profileMatches =
            when (expectedProfile) {
                NativeCardKeyProfile.RSA_3072 -> {
                    val publicKey = certificate.publicKey as? RSAPublicKey
                    publicKey?.modulus?.bitLength() == RSA_3072_KEY_LENGTH_BITS
                }

                NativeCardKeyProfile.ECDSA_P384 -> {
                    val publicKey = certificate.publicKey as? ECPublicKey
                    publicKey != null &&
                        publicKey.params.curve.field.fieldSize == P384_COORDINATE_LENGTH_BITS &&
                        publicKey.params.order.bitLength() == P384_COORDINATE_LENGTH_BITS
                }

                NativeCardKeyProfile.RSA_2048,
                NativeCardKeyProfile.ECDSA_P256,
                -> {
                    false
                }
            }
        if (!profileMatches) {
            throw failure(QualifiedDocumentCmsFailure.CERTIFICATE_PROFILE_MISMATCH)
        }
    }

    fun issuerAndSerial(certificateDer: ByteArray): ByteArray {
        val outer = DerReader(certificateDer)
        val certificate =
            outer.next()
                ?: throw failure(QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE)
        if (certificate.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
            throw failure(QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE)
        }
        val certificateFields = outer.children(certificate)
        val tbs =
            certificateFields.next()
                ?: throw failure(QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE)
        if (tbs.tag != DerValues.TAG_SEQUENCE) {
            throw failure(QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE)
        }
        val tbsFields = certificateFields.children(tbs)
        var serial =
            tbsFields.next()
                ?: throw failure(QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE)
        if (serial.tag == DerValues.TAG_CONTEXT_0_CONSTRUCTED) {
            serial =
                tbsFields.next()
                    ?: throw failure(QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE)
        }
        if (serial.tag != DerValues.TAG_INTEGER) {
            throw failure(QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE)
        }
        val signatureAlgorithm =
            tbsFields.next()
                ?: throw failure(QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE)
        val issuer =
            tbsFields.next()
                ?: throw failure(QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE)
        if (
            signatureAlgorithm.tag != DerValues.TAG_SEQUENCE ||
            issuer.tag != DerValues.TAG_SEQUENCE
        ) {
            throw failure(QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE)
        }
        return DerEncoder.sequence(
            listOf(
                tbsFields.raw(issuer),
                tbsFields.raw(serial),
            ),
        )
    }

    private fun byteRangeDigest(signedAttributesSet: ByteArray): ByteArray? {
        val outer = DerReader(signedAttributesSet)
        val set =
            outer.next()
                ?: return null
        if (set.tag != DerValues.TAG_SET || !outer.isAtEnd) {
            return null
        }
        val attributes = outer.children(set)
        var digest: ByteArray? = null
        while (!attributes.isAtEnd) {
            val attribute =
                attributes.next()
                    ?: run {
                        digest?.fill(ZERO_BYTE)
                        return null
                    }
            if (attribute.tag != DerValues.TAG_SEQUENCE) {
                digest?.fill(ZERO_BYTE)
                return null
            }
            val candidate = messageDigest(attributes, attribute)
            if (candidate != null) {
                if (digest != null) {
                    digest.fill(ZERO_BYTE)
                    candidate.fill(ZERO_BYTE)
                    return null
                }
                digest = candidate
            }
        }
        return digest
    }

    private fun messageDigest(
        attributes: DerReader,
        attribute: DerReader.Element,
    ): ByteArray? {
        val fields = attributes.children(attribute)
        val identifier =
            fields.next()
                ?: return null
        val values =
            fields.next()
                ?: return null
        val messageDigestIdentifier =
            DerEncoder.objectIdentifier(QualifiedCmsOids.MESSAGE_DIGEST)
        if (
            !fields.isAtEnd ||
            identifier.tag != DerValues.TAG_OBJECT_IDENTIFIER ||
            !attributes.raw(identifier).contentEquals(messageDigestIdentifier)
        ) {
            return null
        }
        if (values.tag != DerValues.TAG_SET) {
            return null
        }
        val valueReader = attributes.children(values)
        val value =
            valueReader.next()
                ?: return null
        if (value.tag != DerValues.TAG_OCTET_STRING || !valueReader.isAtEnd) {
            return null
        }
        val digest = attributes.content(value)
        return digest.takeIf { it.size == SHA384_DIGEST_LENGTH_BYTES }
            ?: run {
                digest.fill(ZERO_BYTE)
                null
            }
    }

    private fun failure(kind: QualifiedDocumentCmsFailure): QualifiedDocumentCmsException =
        QualifiedDocumentCmsException(kind)

    private const val X509_CERTIFICATE_TYPE = "X.509"
    private const val ZERO_BYTE: Byte = 0
}
