// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.core

import java.security.GeneralSecurityException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Supplies an owned issuing certificate only after proving the direct X.509 relationship. */
internal fun interface AuthenticationIssuerCertificateSource {
    fun copyIssuerCertificate(leafCertificate: ByteArray): ByteArray?
}

/** Immutable public-issuer set shared by app-owned and system-browser identities. */
internal class AuthenticationIssuerCertificateStore(
    issuerCertificates: List<X509Certificate>,
) : AuthenticationIssuerCertificateSource {
    private val issuers = issuerCertificates.toList()

    override fun copyIssuerCertificate(leafCertificate: ByteArray): ByteArray? {
        val leaf = parseExactCertificate(leafCertificate) ?: return null
        val issuer = issuers.firstOrNull { candidate -> candidate.isDirectIssuerOf(leaf) } ?: return null
        val encoded =
            try {
                issuer.encoded
            } catch (_: GeneralSecurityException) {
                return null
            } catch (_: RuntimeException) {
                return null
            }
        return try {
            encoded.copyOf()
        } finally {
            encoded.fill(CLEARED_BYTE)
        }
    }

    private fun X509Certificate.allowsCertificateSigning(): Boolean {
        val usage = keyUsage ?: return true
        return usage.size > KEY_CERTIFICATE_SIGNING_USAGE_INDEX &&
            usage[KEY_CERTIFICATE_SIGNING_USAGE_INDEX]
    }

    private fun parseExactCertificate(encoded: ByteArray): X509Certificate? {
        val certificate =
            try {
                CertificateFactory
                    .getInstance(X509_CERTIFICATE_TYPE)
                    .generateCertificate(encoded.inputStream()) as? X509Certificate
            } catch (_: GeneralSecurityException) {
                null
            } catch (_: RuntimeException) {
                null
            } ?: return null
        val canonical =
            try {
                certificate.encoded
            } catch (_: GeneralSecurityException) {
                return null
            } catch (_: RuntimeException) {
                return null
            }
        return try {
            certificate.takeIf { canonical.contentEquals(encoded) }
        } finally {
            canonical.fill(CLEARED_BYTE)
        }
    }

    private fun X509Certificate.isDirectIssuerOf(leaf: X509Certificate): Boolean {
        if (
            basicConstraints < CERTIFICATE_AUTHORITY_BASIC_CONSTRAINTS_MINIMUM ||
            !allowsCertificateSigning() ||
            subjectX500Principal != leaf.issuerX500Principal
        ) {
            return false
        }
        return try {
            leaf.verify(publicKey)
            true
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }
    }

    private companion object {
        const val X509_CERTIFICATE_TYPE = "X.509"
        const val CERTIFICATE_AUTHORITY_BASIC_CONSTRAINTS_MINIMUM = 0
        const val KEY_CERTIFICATE_SIGNING_USAGE_INDEX = 5
        const val CLEARED_BYTE: Byte = 0
    }
}
