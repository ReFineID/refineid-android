// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Base64

class ValidationCertificateInputTest {
    @Test
    fun acceptsExactDerAndStrictPem() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            val pem = pem(fixture.issuerCertificate)
            val fromDer = ValidationCertificateInput.derEncoded(fixture.issuerCertificate)
            val fromPem = ValidationCertificateInput.derEncoded(pem)
            try {
                assertArrayEquals(fixture.issuerCertificate, checkNotNull(fromDer))
                assertArrayEquals(fixture.issuerCertificate, checkNotNull(fromPem))
            } finally {
                fromDer?.fill(ZERO_BYTE)
                fromPem?.fill(ZERO_BYTE)
                pem.fill(ZERO_BYTE)
            }
        }
    }

    @Test
    fun rejectsTrailingDerAndAdditionalPemObject() {
        ValidationMaterialCollectorFixture.create().use { fixture ->
            val trailingDer = fixture.issuerCertificate + byteArrayOf(TRAILING_DER_MARKER)
            val certificatePem = pem(fixture.issuerCertificate)
            val duplicatePem = certificatePem + certificatePem
            try {
                assertNull(ValidationCertificateInput.derEncoded(trailingDer))
                assertNull(ValidationCertificateInput.derEncoded(duplicatePem))
            } finally {
                trailingDer.fill(ZERO_BYTE)
                certificatePem.fill(ZERO_BYTE)
                duplicatePem.fill(ZERO_BYTE)
            }
        }
    }

    private fun pem(certificate: ByteArray): ByteArray {
        val body =
            Base64
                .getMimeEncoder(PEM_LINE_LENGTH, PEM_LINE_SEPARATOR)
                .encodeToString(certificate)
        return (PEM_BEGIN + LINE_SEPARATOR + body + LINE_SEPARATOR + PEM_END + LINE_SEPARATOR)
            .encodeToByteArray()
    }

    private companion object {
        const val PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
        const val PEM_END = "-----END CERTIFICATE-----"
        const val LINE_SEPARATOR = "\n"
        const val PEM_LINE_LENGTH = 64
        const val TRAILING_DER_MARKER: Byte = 0
        const val ZERO_BYTE: Byte = 0
        val PEM_LINE_SEPARATOR = LINE_SEPARATOR.encodeToByteArray()
    }
}
