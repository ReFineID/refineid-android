// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.GeneralSecurityException
import java.security.cert.CertPathValidator
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date

/** Authenticates one direct X.509 certificate-issuer relationship. */
internal object CertificateIssuer {
    fun isDirectlyIssued(
        certificateDer: ByteArray,
        issuerDer: ByteArray,
        referenceTime: Instant,
    ): Boolean {
        val certificateFacts = CertificateFacts.parse(certificateDer) ?: return false
        val issuerFacts = CertificateFacts.parse(issuerDer) ?: run {
            certificateFacts.close()
            return false
        }
        return try {
            val certificate = parseCertificate(certificateDer) ?: return false
            val issuer = parseCertificate(issuerDer) ?: return false
            namesMatch(certificate, issuer) &&
                validityCovers(certificate, referenceTime) &&
                validityCovers(issuer, referenceTime) &&
                canIssueCertificates(issuer) &&
                signatureIsValid(certificate, issuer) &&
                directPathIsValid(certificate, issuer, referenceTime)
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        } finally {
            certificateFacts.close()
            issuerFacts.close()
        }
    }

    private fun parseCertificate(encoded: ByteArray): X509Certificate? =
        try {
            val parsed =
                CertificateFactory
                    .getInstance(X509_CERTIFICATE_TYPE)
                    .generateCertificate(encoded.inputStream()) as? X509Certificate
            parsed?.takeIf { certificate -> certificate.encoded.contentEquals(encoded) }
        } catch (_: CertificateException) {
            null
        } catch (_: RuntimeException) {
            null
        }

    private fun namesMatch(
        certificate: X509Certificate,
        issuer: X509Certificate,
    ): Boolean = certificate.issuerX500Principal == issuer.subjectX500Principal

    private fun validityCovers(
        certificate: X509Certificate,
        referenceTime: Instant,
    ): Boolean =
        try {
            certificate.checkValidity(Date.from(referenceTime))
            true
        } catch (_: CertificateException) {
            false
        }

    private fun canIssueCertificates(issuer: X509Certificate): Boolean {
        if (issuer.basicConstraints < MINIMUM_CERTIFICATE_AUTHORITY_PATH_LENGTH) {
            return false
        }
        val usage = issuer.keyUsage ?: return !issuer.hasUnsupportedCriticalExtension()
        return usage.getOrNull(CERTIFICATE_SIGNING_KEY_USAGE_INDEX) == true &&
            !issuer.hasUnsupportedCriticalExtension()
    }

    private fun signatureIsValid(
        certificate: X509Certificate,
        issuer: X509Certificate,
    ): Boolean =
        try {
            certificate.verify(issuer.publicKey)
            true
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }

    private fun directPathIsValid(
        certificate: X509Certificate,
        issuer: X509Certificate,
        referenceTime: Instant,
    ): Boolean {
        if (certificate.hasUnsupportedCriticalExtension()) {
            return false
        }
        val factory = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE)
        val path = factory.generateCertPath(listOf(certificate))
        val parameters =
            PKIXParameters(setOf(TrustAnchor(issuer, null))).apply {
                isRevocationEnabled = false
                date = Date.from(referenceTime)
            }
        CertPathValidator.getInstance(PKIX_ALGORITHM).validate(path, parameters)
        return true
    }

    private const val X509_CERTIFICATE_TYPE = "X.509"
    private const val PKIX_ALGORITHM = "PKIX"
    private const val MINIMUM_CERTIFICATE_AUTHORITY_PATH_LENGTH = 0
    private const val CERTIFICATE_SIGNING_KEY_USAGE_INDEX = 5
}
