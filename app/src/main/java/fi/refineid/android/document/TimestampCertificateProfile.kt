// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.MessageDigest
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date

/** RFC 3161 leaf-certificate constraints independent of trust-anchor handling. */
internal object TimestampCertificateProfile {
    fun isPermittedSigner(
        certificate: X509Certificate,
        generatedAt: Instant,
    ): Boolean =
        isValidAt(certificate, generatedAt) &&
            isEndEntity(certificate) &&
            hasCriticalTimestampingOnlyExtendedKeyUsage(certificate) &&
            hasCompatibleKeyUsage(certificate)

    fun tsaNameMatches(
        name: Rfc3161TstInfoParser.Rfc3161TsaName?,
        certificateDer: ByteArray,
        certificate: X509Certificate,
    ): Boolean {
        if (name == null) {
            return true
        }
        return name.useValue { value ->
            when (name.kind) {
                Rfc3161TstInfoParser.Rfc3161TsaName.Kind.DIRECTORY_NAME -> {
                    val subject = subjectName(certificateDer) ?: return@useValue false
                    try {
                        MessageDigest.isEqual(value, subject)
                    } finally {
                        subject.fill(ZERO_BYTE)
                    }
                }

                Rfc3161TstInfoParser.Rfc3161TsaName.Kind.MAILBOX -> {
                    mailboxMatches(value, certificate)
                }
            }
        }
    }

    private fun isValidAt(
        certificate: X509Certificate,
        generatedAt: Instant,
    ): Boolean =
        try {
            certificate.checkValidity(Date.from(generatedAt))
            true
        } catch (_: CertificateExpiredException) {
            false
        } catch (_: CertificateNotYetValidException) {
            false
        }

    private fun isEndEntity(certificate: X509Certificate): Boolean =
        certificate.basicConstraints == END_ENTITY_BASIC_CONSTRAINTS

    private fun hasCriticalTimestampingOnlyExtendedKeyUsage(certificate: X509Certificate): Boolean =
        try {
            certificate.criticalExtensionOIDs?.contains(TimestampCmsOids.EXTENDED_KEY_USAGE) == true &&
                certificate.extendedKeyUsage == listOf(TimestampCmsOids.TIMESTAMPING_KEY_PURPOSE)
        } catch (_: CertificateParsingException) {
            false
        }

    private fun hasCompatibleKeyUsage(certificate: X509Certificate): Boolean {
        val usage = certificate.keyUsage ?: return true
        val permitsSignature =
            usage.enabled(DIGITAL_SIGNATURE_KEY_USAGE_INDEX) ||
                usage.enabled(CONTENT_COMMITMENT_KEY_USAGE_INDEX)
        val permitsAuthority =
            usage.enabled(CERTIFICATE_SIGNING_KEY_USAGE_INDEX) ||
                usage.enabled(REVOCATION_LIST_SIGNING_KEY_USAGE_INDEX)
        return permitsSignature && !permitsAuthority
    }

    private fun mailboxMatches(
        expected: ByteArray,
        certificate: X509Certificate,
    ): Boolean {
        val mailbox = expected.toString(Charsets.US_ASCII)
        val names =
            try {
                certificate.subjectAlternativeNames
            } catch (_: CertificateParsingException) {
                return false
            } ?: return false
        return names.any { entry ->
            entry.size >= GENERAL_NAME_ENTRY_LENGTH &&
                entry[GENERAL_NAME_TYPE_INDEX] == RFC822_NAME_TYPE &&
                entry[GENERAL_NAME_VALUE_INDEX] == mailbox
        }
    }

    private fun subjectName(certificateDer: ByteArray): ByteArray? {
        val outer = DerReader(certificateDer)
        val certificate = outer.next() ?: return null
        if (certificate.tag != DerValues.TAG_SEQUENCE || !outer.isAtEnd) {
            return null
        }
        val certificateFields = outer.children(certificate)
        val tbs = certificateFields.next() ?: return null
        if (tbs.tag != DerValues.TAG_SEQUENCE) {
            return null
        }
        return subjectNameFromTbs(certificateFields.children(tbs))
    }

    private fun subjectNameFromTbs(fields: DerReader): ByteArray? {
        var serial = fields.next() ?: return null
        if (serial.tag == DerValues.TAG_CONTEXT_0_CONSTRUCTED) {
            serial = fields.next() ?: return null
        }
        if (serial.tag != DerValues.TAG_INTEGER) {
            return null
        }
        val signature = fields.next() ?: return null
        val issuer = fields.next() ?: return null
        val validity = fields.next() ?: return null
        val subject = fields.next() ?: return null
        return if (
            signature.tag == DerValues.TAG_SEQUENCE &&
            issuer.tag == DerValues.TAG_SEQUENCE &&
            validity.tag == DerValues.TAG_SEQUENCE &&
            subject.tag == DerValues.TAG_SEQUENCE
        ) {
            fields.raw(subject)
        } else {
            null
        }
    }

    private fun BooleanArray.enabled(index: Int): Boolean = getOrNull(index) == true

    private const val END_ENTITY_BASIC_CONSTRAINTS = -1
    private const val DIGITAL_SIGNATURE_KEY_USAGE_INDEX = 0
    private const val CONTENT_COMMITMENT_KEY_USAGE_INDEX = 1
    private const val CERTIFICATE_SIGNING_KEY_USAGE_INDEX = 5
    private const val REVOCATION_LIST_SIGNING_KEY_USAGE_INDEX = 6
    private const val GENERAL_NAME_ENTRY_LENGTH = 2
    private const val GENERAL_NAME_TYPE_INDEX = 0
    private const val GENERAL_NAME_VALUE_INDEX = 1
    private const val RFC822_NAME_TYPE = 1
    private const val ZERO_BYTE: Byte = 0
}
