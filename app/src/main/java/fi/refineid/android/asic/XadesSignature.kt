package fi.refineid.android.asic

import fi.refineid.android.core.NativeCardKeyProfile
import java.security.MessageDigest
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.Base64

/** One file carried and signed inside an ASiC-E container. */
internal class AsicDataObject(
    val name: String,
    val content: ByteArray,
    val mimeType: String,
)

/** The two signed subtrees plus the certificate they name. */
internal class XadesPlan(
    val signedInfo: String,
    private val signedProperties: String,
    private val certificateDer: ByteArray,
    private val objects: List<AsicDataObject>,
) {
    /**
     * The finished `signatures0.xml` at level B-B: the SignedInfo and
     * SignedProperties are inserted byte-for-byte as they were signed
     * and digested, so a verifier canonicalises them to the same bytes.
     */
    fun document(xmlSignature: ByteArray): String {
        val out = StringBuilder()
        out.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        out.append("<asic:XAdESSignatures xmlns:asic=\"").append(XadesSignature.NAMESPACE_ASIC).append("\">\n")
        out.append("<ds:Signature xmlns:ds=\"").append(XadesSignature.NAMESPACE_DSIG)
        out.append("\" Id=\"").append(XadesSignature.SIGNATURE_ID).append("\">\n")
        out.append(signedInfo).append("\n")
        out.append(XadesSignature.signatureValueElement(xmlSignature)).append("\n")
        out.append("<ds:KeyInfo>\n<ds:X509Data>\n")
        out.append("<ds:X509Certificate>").append(base64(certificateDer)).append("</ds:X509Certificate>\n")
        out.append("</ds:X509Data>\n</ds:KeyInfo>\n")
        out.append("<ds:Object>\n")
        out.append("<xades:QualifyingProperties xmlns:xades=\"").append(XadesSignature.NAMESPACE_XADES)
        out.append("\" Target=\"#").append(XadesSignature.SIGNATURE_ID).append("\">\n")
        out.append(signedProperties).append("\n")
        out.append("</xades:QualifyingProperties>\n")
        out.append("</ds:Object>\n")
        out.append("</ds:Signature>\n")
        out.append("</asic:XAdESSignatures>\n")
        return out.toString()
    }

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
}

/**
 * XAdES signature assembly for ASiC-E, ported from the reference
 * implementation. There is no canonicaliser here on purpose: every
 * element is emitted already in Exclusive XML Canonicalization form —
 * never self-closed, attributes in canonical order, namespace
 * declarations repeated on each subtree digested alone, and text
 * escaped by the canonicalisation rules — so canonicalising the output
 * is the identity function and the bytes are digested where they stand.
 */
internal object XadesSignature {
    const val NAMESPACE_DSIG = "http://www.w3.org/2000/09/xmldsig#"
    const val NAMESPACE_XADES = "http://uri.etsi.org/01903/v1.3.2#"
    const val NAMESPACE_ASIC = "http://uri.etsi.org/02918/v1.2.1#"
    const val DIGEST_METHOD_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    const val CANONICALIZATION_EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"
    const val SIGNATURE_METHOD_RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
    const val SIGNATURE_METHOD_ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"

    // The SignedProperties type has no minor version: it is a fixed
    // string in EN 319 132-1 and verifiers match it literally.
    const val SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties"
    const val SIGNATURE_ID = "SIG-1"
    const val SIGNED_PROPERTIES_ID = "SIG-1-SIGNEDPROPS"
    const val SIGNATURE_VALUE_ID = "SIG-1-SIGVAL"

    /** Build the plan: the SignedProperties digest feeds the SignedInfo. */
    fun plan(
        profile: NativeCardKeyProfile,
        objects: List<AsicDataObject>,
        certificateDer: ByteArray,
        signedAt: Instant,
    ): XadesPlan {
        val signedProperties = signedProperties(objects, certificateDer, signedAt)
        val signedInfo = signedInfo(profile, objects, sha384(signedProperties.encodeToByteArray()))
        return XadesPlan(
            signedInfo = signedInfo,
            signedProperties = signedProperties,
            certificateDer = certificateDer,
            objects = objects,
        )
    }

    /** The SignedInfo: what the card signs, SHA-384 over these UTF-8 octets. */
    fun signedInfo(
        profile: NativeCardKeyProfile,
        objects: List<AsicDataObject>,
        signedPropertiesDigest: ByteArray,
    ): String {
        val out = StringBuilder()
        out.append("<ds:SignedInfo xmlns:ds=\"").append(NAMESPACE_DSIG).append("\">\n")
        out.append("<ds:CanonicalizationMethod Algorithm=\"").append(CANONICALIZATION_EXCLUSIVE)
        out.append("\"></ds:CanonicalizationMethod>\n")
        out.append("<ds:SignatureMethod Algorithm=\"").append(signatureMethod(profile))
        out.append("\"></ds:SignatureMethod>\n")
        objects.forEachIndexed { index, obj ->
            out.append("<ds:Reference Id=\"").append(referenceId(index)).append("\" ")
            out.append("URI=\"").append(escapeAttribute(percentEncodePath(obj.name))).append("\">\n")
            out.append("<ds:DigestMethod Algorithm=\"").append(DIGEST_METHOD_SHA384).append("\"></ds:DigestMethod>\n")
            out.append("<ds:DigestValue>").append(base64(sha384(obj.content))).append("</ds:DigestValue>\n")
            out.append("</ds:Reference>\n")
        }
        out.append("<ds:Reference Id=\"").append(SIGNATURE_ID).append("-REF-SP\" ")
        out.append("Type=\"").append(SIGNED_PROPERTIES_TYPE).append("\" ")
        out.append("URI=\"#").append(SIGNED_PROPERTIES_ID).append("\">\n")
        out.append("<ds:Transforms>\n")
        out.append("<ds:Transform Algorithm=\"").append(CANONICALIZATION_EXCLUSIVE).append("\"></ds:Transform>\n")
        out.append("</ds:Transforms>\n")
        out.append("<ds:DigestMethod Algorithm=\"").append(DIGEST_METHOD_SHA384).append("\"></ds:DigestMethod>\n")
        out.append("<ds:DigestValue>").append(base64(signedPropertiesDigest)).append("</ds:DigestValue>\n")
        out.append("</ds:Reference>\n")
        out.append("</ds:SignedInfo>")
        return out.toString()
    }

    /** The SignedProperties subtree, digested on its own into the SignedInfo. */
    fun signedProperties(
        objects: List<AsicDataObject>,
        certificateDer: ByteArray,
        signedAt: Instant,
    ): String {
        val out = StringBuilder()
        out.append("<xades:SignedProperties xmlns:xades=\"").append(NAMESPACE_XADES)
        out.append("\" Id=\"").append(SIGNED_PROPERTIES_ID).append("\">\n")
        out.append("<xades:SignedSignatureProperties>\n")
        out.append("<xades:SigningTime>").append(dateTime(signedAt)).append("</xades:SigningTime>\n")
        out.append("<xades:SigningCertificateV2>\n<xades:Cert>\n<xades:CertDigest>\n")
        out.append("<ds:DigestMethod xmlns:ds=\"").append(NAMESPACE_DSIG)
        out.append("\" Algorithm=\"").append(DIGEST_METHOD_SHA384).append("\"></ds:DigestMethod>\n")
        out.append("<ds:DigestValue xmlns:ds=\"").append(NAMESPACE_DSIG).append("\">")
        out.append(base64(sha384(certificateDer))).append("</ds:DigestValue>\n")
        out.append("</xades:CertDigest>\n</xades:Cert>\n</xades:SigningCertificateV2>\n")
        out.append("</xades:SignedSignatureProperties>\n")
        out.append("<xades:SignedDataObjectProperties>\n")
        objects.forEachIndexed { index, obj ->
            out.append("<xades:DataObjectFormat ObjectReference=\"#").append(referenceId(index)).append("\">\n")
            out.append("<xades:MimeType>").append(escapeText(obj.mimeType)).append("</xades:MimeType>\n")
            out.append("</xades:DataObjectFormat>\n")
        }
        out.append("</xades:SignedDataObjectProperties>\n")
        out.append("</xades:SignedProperties>")
        return out.toString()
    }

    /** The `ds:SignatureValue` element, canonical and standalone. */
    fun signatureValueElement(xmlSignature: ByteArray): String =
        "<ds:SignatureValue xmlns:ds=\"" + NAMESPACE_DSIG + "\" Id=\"" +
            SIGNATURE_VALUE_ID + "\">" + base64(xmlSignature) + "</ds:SignatureValue>"

    /** SHA-384 over the canonicalised SignatureValue element (EN 319 132-1). */
    fun timestampDigest(xmlSignature: ByteArray): ByteArray =
        sha384(signatureValueElement(xmlSignature).encodeToByteArray())

    fun signatureMethod(profile: NativeCardKeyProfile): String =
        when (profile) {
            NativeCardKeyProfile.ECDSA_P256, NativeCardKeyProfile.ECDSA_P384 -> SIGNATURE_METHOD_ECDSA_SHA384
            NativeCardKeyProfile.RSA_2048, NativeCardKeyProfile.RSA_3072 -> SIGNATURE_METHOD_RSA_SHA384
        }

    fun referenceId(index: Int): String = SIGNATURE_ID + "-REF-" + index

    /**
     * Attribute-value escaping under Canonical XML: `&`, `<`, `"` and the
     * three whitespace controls — but never `>` and never `'`.
     */
    fun escapeAttribute(value: String): String {
        val out = StringBuilder(value.length)
        for (character in value) {
            when (character) {
                '&' -> out.append("&amp;")
                '<' -> out.append("&lt;")
                '"' -> out.append("&quot;")
                '\t' -> out.append("&#x9;")
                '\n' -> out.append("&#xA;")
                '\r' -> out.append("&#xD;")
                else -> out.append(character)
            }
        }
        return out.toString()
    }

    /** Text-node escaping under Canonical XML: `&`, `<`, `>` and `\r`. */
    fun escapeText(value: String): String {
        val out = StringBuilder(value.length)
        for (character in value) {
            when (character) {
                '&' -> out.append("&amp;")
                '<' -> out.append("&lt;")
                '>' -> out.append("&gt;")
                '\r' -> out.append("&#xD;")
                else -> out.append(character)
            }
        }
        return out.toString()
    }

    /**
     * Percent-encode a reference URI over UTF-8 bytes, leaving RFC 3986
     * unreserved characters and `/` untouched, uppercase hex elsewhere.
     */
    fun percentEncodePath(name: String): String {
        val out = StringBuilder(name.length)
        for (byte in name.encodeToByteArray()) {
            val value = byte.toInt() and BYTE_MASK
            if (value.toChar() in UNRESERVED) {
                out.append(value.toChar())
            } else {
                out.append('%').append(HEX[value ushr HALF_BYTE_BITS]).append(HEX[value and LOW_NIBBLE_MASK])
            }
        }
        return out.toString()
    }

    /** UTC xsd:dateTime, second precision, `Z` suffix, no fraction. */
    fun dateTime(instant: Instant): String =
        DateTimeFormatter.ISO_INSTANT.format(instant.truncatedTo(ChronoUnit.SECONDS))

    private fun sha384(content: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(content)

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private const val BYTE_MASK = 0xFF
    private const val HALF_BYTE_BITS = 4
    private const val LOW_NIBBLE_MASK = 0x0F
    private const val HEX = "0123456789ABCDEF"
    private val UNRESERVED =
        (('A'..'Z') + ('a'..'z') + ('0'..'9') + listOf('-', '.', '_', '~', '/')).toSet()
}
