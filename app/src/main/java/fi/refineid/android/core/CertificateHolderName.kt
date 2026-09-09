package fi.refineid.android.core

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

internal object CertificateHolderName {
    fun fromDer(der: ByteArray): String? =
        try {
            val factory = CertificateFactory.getInstance("X.509")
            val x509 = factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            val rfc2253 = x509.subjectX500Principal.getName("RFC2253")
            "(?:^|,)\\s*CN=([^,]+)".toRegex().find(rfc2253)?.groupValues?.get(1)
        } catch (_: Exception) {
            null
        }

    fun fromCertificate(certificate: NativeAuthenticationCertificate): String? =
        try {
            fromDer(certificate.copyDer())
        } catch (_: Exception) {
            null
        }
}
