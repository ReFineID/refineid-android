// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress(
    "MagicNumber",
    "ComplexMethod",
    "LongMethod",
    "NestedBlockDepth",
    "ReturnCount",
    "LoopWithTooManyJumpStatements",
    "TooGenericExceptionCaught",
)

package fi.refineid.android.asic

import fi.refineid.android.document.DocumentSignatureVerdict
import fi.refineid.android.document.DocumentValidationResult
import fi.refineid.android.document.RevocationStatus
import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import java.net.URLDecoder
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.zip.ZipInputStream
import javax.xml.parsers.DocumentBuilderFactory

internal object AsicValidator {
    fun isAsic(bytes: ByteArray): Boolean = bytes.size >= 4 && bytes[0] == 0x50.toByte() && bytes[1] == 0x4B.toByte()

    fun validate(
        archiveBytes: ByteArray,
        trustAnchors: List<X509Certificate>,
        checkRevocation: (X509Certificate) -> RevocationStatus = { RevocationStatus.UNCHECKED },
    ): DocumentValidationResult {
        val entries = mutableMapOf<String, ByteArray>()
        try {
            ZipInputStream(ByteArrayInputStream(archiveBytes)).use { zip ->
                while (true) {
                    val entry = zip.nextEntry ?: break
                    if (!entry.isDirectory) {
                        entries[entry.name] = zip.readBytes()
                    }
                    zip.closeEntry()
                }
            }
        } catch (_: Exception) {
            return DocumentValidationResult.Malformed
        }

        val signatureXmlEntries =
            entries.filter { (name, _) ->
                name.startsWith("META-INF/") && name.endsWith(".xml") &&
                    (name.contains("signature", ignoreCase = true) || name.contains("signatures", ignoreCase = true))
            }

        if (signatureXmlEntries.isEmpty()) {
            return DocumentValidationResult.Unsigned
        }

        val verdicts = mutableListOf<DocumentSignatureVerdict>()
        for ((_, xmlBytes) in signatureXmlEntries) {
            val sigVerdicts =
                parseAndVerifyXml(xmlBytes, entries, trustAnchors, checkRevocation)
                    ?: return DocumentValidationResult.Malformed
            verdicts.addAll(sigVerdicts)
        }

        return if (verdicts.isEmpty()) {
            DocumentValidationResult.Unsigned
        } else {
            DocumentValidationResult.Completed(verdicts)
        }
    }

    private fun parseAndVerifyXml(
        xmlBytes: ByteArray,
        archiveEntries: Map<String, ByteArray>,
        trustAnchors: List<X509Certificate>,
        checkRevocation: (X509Certificate) -> RevocationStatus,
    ): List<DocumentSignatureVerdict>? {
        val xmlString = String(xmlBytes, Charsets.UTF_8)
        val factory =
            DocumentBuilderFactory.newInstance().apply {
                isNamespaceAware = true
                try {
                    setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
                } catch (_: Throwable) {
                    // Ignored on platforms without this feature
                }
            }
        val builder = factory.newDocumentBuilder()
        val doc =
            try {
                builder.parse(ByteArrayInputStream(xmlBytes))
            } catch (_: Exception) {
                return null
            }

        val signatures = doc.getElementsByTagNameNS("*", "Signature")
        if (signatures.length == 0) {
            return emptyList()
        }

        val results = mutableListOf<DocumentSignatureVerdict>()
        for (i in 0 until signatures.length) {
            val sigElement = signatures.item(i) as? Element ?: continue
            val verdict =
                verifySingleSignature(sigElement, xmlString, archiveEntries, trustAnchors, checkRevocation)
                    ?: return null
            results.add(verdict)
        }
        return results
    }

    private fun verifySingleSignature(
        sigElement: Element,
        xmlString: String,
        archiveEntries: Map<String, ByteArray>,
        trustAnchors: List<X509Certificate>,
        checkRevocation: (X509Certificate) -> RevocationStatus,
    ): DocumentSignatureVerdict? {
        val certNodes = sigElement.getElementsByTagNameNS("*", "X509Certificate")
        if (certNodes.length == 0) return null
        val certBase64 = certNodes.item(0).textContent.replace("\\s+".toRegex(), "")
        val certBytes =
            try {
                Base64.getDecoder().decode(certBase64)
            } catch (_: Exception) {
                return null
            }
        val signerCert =
            try {
                CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
            } catch (_: Exception) {
                return null
            }

        val timeNodes = sigElement.getElementsByTagNameNS("*", "SigningTime")
        val signingTime = if (timeNodes.length > 0) timeNodes.item(0).textContent.trim() else null

        val signedInfoNodes = sigElement.getElementsByTagNameNS("*", "SignedInfo")
        if (signedInfoNodes.length == 0) return null
        val signedInfoElem = signedInfoNodes.item(0) as Element

        val sigMethodElem = signedInfoElem.getElementsByTagNameNS("*", "SignatureMethod").item(0) as? Element
        val sigMethodUri = sigMethodElem?.getAttribute("Algorithm") ?: ""
        val (sigAlgorithm, digestAlgorithm) = mapAlgorithm(sigMethodUri)

        val refNodes = signedInfoElem.getElementsByTagNameNS("*", "Reference")
        var allDigestsMatch = true
        var hasFileReferences = false

        for (j in 0 until refNodes.length) {
            val refElem = refNodes.item(j) as? Element ?: continue
            val uri = refElem.getAttribute("URI") ?: ""
            val digestValElem = refElem.getElementsByTagNameNS("*", "DigestValue").item(0) as? Element ?: continue
            val expectedDigest =
                try {
                    Base64.getDecoder().decode(digestValElem.textContent.replace("\\s+".toRegex(), ""))
                } catch (_: Exception) {
                    allDigestsMatch = false
                    continue
                }
            val digestMethodElem = refElem.getElementsByTagNameNS("*", "DigestMethod").item(0) as? Element
            val refDigestAlg = mapDigestAlgorithm(digestMethodElem?.getAttribute("Algorithm"))

            if (!uri.startsWith("#")) {
                hasFileReferences = true
                val decodedName =
                    try {
                        URLDecoder.decode(uri, "UTF-8")
                    } catch (_: Exception) {
                        uri
                    }
                val fileContent = archiveEntries[decodedName] ?: archiveEntries[uri]
                if (fileContent == null) {
                    allDigestsMatch = false
                } else {
                    val computedDigest = MessageDigest.getInstance(refDigestAlg).digest(fileContent)
                    if (!computedDigest.contentEquals(expectedDigest)) {
                        allDigestsMatch = false
                    }
                }
            }
        }

        val sigValNodes = sigElement.getElementsByTagNameNS("*", "SignatureValue")
        if (sigValNodes.length == 0) return null
        val sigValBase64 = sigValNodes.item(0).textContent.replace("\\s+".toRegex(), "")
        val sigValBytes =
            try {
                Base64.getDecoder().decode(sigValBase64)
            } catch (_: Exception) {
                return null
            }

        val signedInfoSubstring = extractSignedInfoXml(xmlString)
        val signatureValid =
            try {
                val sig = Signature.getInstance(sigAlgorithm)
                sig.initVerify(signerCert.publicKey)
                sig.update(signedInfoSubstring.encodeToByteArray())
                sig.verify(sigValBytes)
            } catch (_: Exception) {
                false
            }

        val chainTrusted = isChainTrusted(signerCert, trustAnchors)
        val revocationStatus = if (chainTrusted) checkRevocation(signerCert) else RevocationStatus.UNCHECKED

        return DocumentSignatureVerdict(
            signerCommonName = commonNameOf(signerCert.subjectX500Principal.getName("RFC2253")),
            signerIssuer = commonNameOf(signerCert.issuerX500Principal.getName("RFC2253")),
            signerSerialNumber = serialNumberOf(signerCert),
            signingTime = signingTime,
            digestAlgorithm = digestAlgorithm,
            signatureAlgorithm = sigAlgorithm,
            coversWholeDocument = hasFileReferences,
            digestMatches = allDigestsMatch,
            signatureValid = signatureValid,
            chainTrusted = chainTrusted,
            hasSignatureTimestamp = false,
            isDocumentTimestamp = false,
            revocationStatus = revocationStatus,
        )
    }

    private fun extractSignedInfoXml(xml: String): String {
        val start = xml.indexOf("<ds:SignedInfo")
        val end = xml.indexOf("</ds:SignedInfo>")
        return if (start != -1 && end != -1) {
            xml.substring(start, end + "</ds:SignedInfo>".length)
        } else {
            val altStart = xml.indexOf("<SignedInfo")
            val altEnd = xml.indexOf("</SignedInfo>")
            if (altStart != -1 && altEnd != -1) {
                xml.substring(altStart, altEnd + "</SignedInfo>".length)
            } else {
                xml
            }
        }
    }

    private fun mapAlgorithm(uri: String): Pair<String, String> =
        when {
            uri.contains("rsa-sha384", ignoreCase = true) -> "SHA384withRSA" to "SHA-384"
            uri.contains("ecdsa-sha384", ignoreCase = true) -> "SHA384withECDSA" to "SHA-384"
            uri.contains("rsa-sha256", ignoreCase = true) -> "SHA256withRSA" to "SHA-256"
            uri.contains("ecdsa-sha256", ignoreCase = true) -> "SHA256withECDSA" to "SHA-256"
            uri.contains("rsa-sha512", ignoreCase = true) -> "SHA512withRSA" to "SHA-512"
            uri.contains("ecdsa-sha512", ignoreCase = true) -> "SHA512withECDSA" to "SHA-512"
            uri.contains("rsa-sha1", ignoreCase = true) -> "SHA1withRSA" to "SHA-1"
            else -> "SHA384withRSA" to "SHA-384"
        }

    private fun mapDigestAlgorithm(uri: String?): String =
        when {
            uri == null -> "SHA-384"
            uri.contains("sha384", ignoreCase = true) -> "SHA-384"
            uri.contains("sha256", ignoreCase = true) -> "SHA-256"
            uri.contains("sha512", ignoreCase = true) -> "SHA-512"
            uri.contains("sha1", ignoreCase = true) -> "SHA-1"
            else -> "SHA-384"
        }

    private fun isChainTrusted(
        certificate: X509Certificate,
        trustAnchors: List<X509Certificate>,
    ): Boolean =
        trustAnchors.any { anchor ->
            (
                certificate.issuerX500Principal == anchor.subjectX500Principal &&
                    runCatching { certificate.verify(anchor.publicKey) }.isSuccess
            ) ||
                (
                    certificate.subjectX500Principal == anchor.subjectX500Principal &&
                        certificate.encoded.contentEquals(anchor.encoded)
                )
        }

    private fun commonNameOf(rfc2253: String): String? {
        val match = "(?:^|,)\\s*CN=([^,]+)".toRegex().find(rfc2253)
        return match?.groupValues?.get(1)?.trim()
    }

    private fun serialNumberOf(certificate: X509Certificate): String? {
        val rfc2253 = certificate.subjectX500Principal.getName("RFC2253")
        val match = "(?:^|,)\\s*SERIALNUMBER=([^,]+)".toRegex(RegexOption.IGNORE_CASE).find(rfc2253)
        return match?.groupValues?.get(1)?.trim() ?: certificate.serialNumber?.toString(16)
    }
}
