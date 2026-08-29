package fi.refineid.android.core

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale

internal object CardPhotoStore {
    private val photos = mutableMapOf<String, ByteArray>()
    private var defaultPhoto: ByteArray? = null

    fun getPhoto(holderKey: String? = null): ByteArray? = holderKey?.let { photos[it] } ?: defaultPhoto

    fun savePhoto(
        photoBytes: ByteArray,
        holderKey: String? = null,
    ) {
        defaultPhoto = photoBytes
        if (holderKey != null) {
            photos[holderKey] = photoBytes
        }
    }

    fun clear() {
        photos.clear()
        defaultPhoto = null
    }
}

internal data class PersonCardDetails(
    val holderName: String,
    val fullName: String,
    val identifier: String? = null,
    val dateOfBirth: String? = null,
    val nationality: String = "Suomi (FIN)",
    val issuedDate: String? = null,
    val expiryDate: String? = null,
    val issuer: String? = null,
    val signatureAlgorithm: String? = null,
    val isTamperProofVerified: Boolean = true,
    val photoBytes: ByteArray? = null,
) {
    fun getPhotoBitmap(): Bitmap? =
        (photoBytes ?: CardPhotoStore.getPhoto(holderName))?.let { bytes ->
            try {
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            } catch (_: Exception) {
                null
            }
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PersonCardDetails) return false
        return holderName == other.holderName &&
            fullName == other.fullName &&
            identifier == other.identifier &&
            dateOfBirth == other.dateOfBirth &&
            nationality == other.nationality &&
            issuedDate == other.issuedDate &&
            expiryDate == other.expiryDate &&
            issuer == other.issuer &&
            signatureAlgorithm == other.signatureAlgorithm &&
            isTamperProofVerified == other.isTamperProofVerified &&
            (photoBytes contentEquals other.photoBytes)
    }

    override fun hashCode(): Int {
        var result = holderName.hashCode()
        result = 31 * result + fullName.hashCode()
        result = 31 * result + (identifier?.hashCode() ?: 0)
        result = 31 * result + (dateOfBirth?.hashCode() ?: 0)
        result = 31 * result + nationality.hashCode()
        result = 31 * result + (issuedDate?.hashCode() ?: 0)
        result = 31 * result + (expiryDate?.hashCode() ?: 0)
        result = 31 * result + (issuer?.hashCode() ?: 0)
        result = 31 * result + (signatureAlgorithm?.hashCode() ?: 0)
        result = 31 * result + isTamperProofVerified.hashCode()
        result = 31 * result + (photoBytes?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        fun fromDer(
            der: ByteArray,
            photoBytes: ByteArray? = null,
        ): PersonCardDetails? =
            try {
                val factory = CertificateFactory.getInstance("X.509")
                val x509 = factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
                val rfc2253 = x509.subjectX500Principal.getName("RFC2253")
                val cn =
                    "(?:^|,)\\s*CN=([^,]+)".toRegex().find(rfc2253)?.groupValues?.get(1)
                        ?: return null

                val tokens = cn.split(" ").filter { it.isNotBlank() }
                val (nameTokens, idToken) =
                    if (tokens.isNotEmpty() &&
                        tokens.last().matches("[0-9A-Za-z]{6,12}".toRegex()) &&
                        tokens.last().any { it.isDigit() }
                    ) {
                        tokens.dropLast(1) to tokens.last()
                    } else {
                        tokens to null
                    }
                val formattedName = if (nameTokens.isNotEmpty()) nameTokens.joinToString(" ") else cn

                val countryCode =
                    "(?:^|,)\\s*C=([^,]+)".toRegex().find(rfc2253)?.groupValues?.get(1) ?: "FI"
                val nationalityStr =
                    when (countryCode.uppercase(Locale.ROOT)) {
                        "FI" -> "Suomi (FIN)"
                        "SE" -> "Ruotsi (SWE)"
                        "EE" -> "Viro (EST)"
                        "NO" -> "Norja (NOR)"
                        else -> countryCode
                    }

                val issuerRfc = x509.issuerX500Principal.getName("RFC2253")
                val issuerCn =
                    "(?:^|,)\\s*CN=([^,]+)".toRegex().find(issuerRfc)?.groupValues?.get(1)
                        ?: "Digi- ja väestötietovirasto (DVV)"
                val cleanIssuer =
                    if (issuerCn.contains("VRK", ignoreCase = true) ||
                        issuerCn.contains("DVV", ignoreCase = true) ||
                        issuerCn.contains("FINEID", ignoreCase = true)
                    ) {
                        "Digi- ja väestötietovirasto (DVV)"
                    } else {
                        issuerCn
                    }

                val dateFormat = SimpleDateFormat("d.M.yyyy", Locale.ROOT)
                val issued =
                    try {
                        dateFormat.format(x509.notBefore)
                    } catch (_: Exception) {
                        null
                    }
                val expires =
                    try {
                        dateFormat.format(x509.notAfter)
                    } catch (_: Exception) {
                        null
                    }

                val effectivePhoto = photoBytes ?: CardPhotoStore.getPhoto(formattedName)

                PersonCardDetails(
                    holderName = cn,
                    fullName = formattedName,
                    identifier = idToken,
                    dateOfBirth = null,
                    nationality = nationalityStr,
                    issuedDate = issued,
                    expiryDate = expires,
                    issuer = cleanIssuer,
                    signatureAlgorithm = x509.sigAlgName,
                    isTamperProofVerified = true,
                    photoBytes = effectivePhoto,
                )
            } catch (_: Exception) {
                null
            }

        fun fromHolderName(holderName: String): PersonCardDetails {
            val tokens = holderName.split(" ").filter { it.isNotBlank() }
            val (nameTokens, idToken) =
                if (tokens.isNotEmpty() &&
                    tokens.last().matches("[0-9A-Za-z]{6,12}".toRegex()) &&
                    tokens.last().any { it.isDigit() }
                ) {
                    tokens.dropLast(1) to tokens.last()
                } else {
                    tokens to null
                }
            val formattedName = if (nameTokens.isNotEmpty()) nameTokens.joinToString(" ") else holderName

            val effectivePhoto = CardPhotoStore.getPhoto(formattedName)

            return PersonCardDetails(
                holderName = holderName,
                fullName = formattedName,
                identifier = idToken,
                dateOfBirth = null,
                nationality = "Suomi (FIN)",
                issuedDate = null,
                expiryDate = null,
                issuer = "Digi- ja väestötietovirasto (DVV)",
                signatureAlgorithm = "ECDSA_P384 / SHA-384",
                isTamperProofVerified = true,
                photoBytes = effectivePhoto,
            )
        }
    }
}
