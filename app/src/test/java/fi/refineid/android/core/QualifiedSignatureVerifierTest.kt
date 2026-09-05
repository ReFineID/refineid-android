package fi.refineid.android.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class QualifiedSignatureVerifierTest {
    @Test
    fun verifiesRsaSha384AndRejectsDifferentContent() {
        val keyPair =
            KeyPairGenerator
                .getInstance(RSA_KEY_ALGORITHM)
                .apply { initialize(RSA_3072_KEY_LENGTH_BITS) }
                .generateKeyPair()
        val signature =
            sign(
                keyPair = keyPair,
                algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                content = SIGNED_ATTRIBUTES,
            )

        assertTrue(
            QualifiedSignatureVerifier.verify(
                publicKey = keyPair.public,
                algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                content = SIGNED_ATTRIBUTES,
                signature = signature,
            ),
        )
        assertFalse(
            QualifiedSignatureVerifier.verify(
                publicKey = keyPair.public,
                algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                content = DIFFERENT_ATTRIBUTES,
                signature = signature,
            ),
        )
    }

    @Test
    fun verifiesP384Sha384FromTheRawCardShape() {
        val keyPair =
            KeyPairGenerator
                .getInstance(EC_KEY_ALGORITHM)
                .apply { initialize(ECGenParameterSpec(P384_CURVE_NAME)) }
                .generateKeyPair()
        val derSignature =
            sign(
                keyPair = keyPair,
                algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
                content = SIGNED_ATTRIBUTES,
            )
        val rawSignature = derP384EcdsaToRaw(derSignature)

        assertTrue(
            QualifiedSignatureVerifier.verify(
                publicKey = keyPair.public,
                algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
                content = SIGNED_ATTRIBUTES,
                signature = rawSignature,
            ),
        )
        rawSignature[FIRST_SIGNATURE_BYTE_OFFSET] =
            (
                rawSignature[FIRST_SIGNATURE_BYTE_OFFSET].toInt() xor
                    SINGLE_BIT_CORRUPTION_MASK
            ).toByte()
        assertFalse(
            QualifiedSignatureVerifier.verify(
                publicKey = keyPair.public,
                algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
                content = SIGNED_ATTRIBUTES,
                signature = rawSignature,
            ),
        )
    }

    @Test
    fun verifiesPrehashedRsaSha384AndRejectsDifferentDigest() {
        val keyPair =
            KeyPairGenerator
                .getInstance(RSA_KEY_ALGORITHM)
                .apply { initialize(RSA_3072_KEY_LENGTH_BITS) }
                .generateKeyPair()
        val digest =
            java.security.MessageDigest
                .getInstance("SHA-384")
                .digest(SIGNED_ATTRIBUTES)
        val signature =
            sign(
                keyPair = keyPair,
                algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                content = SIGNED_ATTRIBUTES,
            )

        assertTrue(
            QualifiedSignatureVerifier.verifyPrehashed(
                publicKey = keyPair.public,
                algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                digest = digest,
                signature = signature,
            ),
        )
        val differentDigest =
            java.security.MessageDigest
                .getInstance("SHA-384")
                .digest(DIFFERENT_ATTRIBUTES)
        assertFalse(
            QualifiedSignatureVerifier.verifyPrehashed(
                publicKey = keyPair.public,
                algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                digest = differentDigest,
                signature = signature,
            ),
        )
    }

    @Test
    fun verifiesPrehashedP384Sha384FromTheRawCardShape() {
        val keyPair =
            KeyPairGenerator
                .getInstance(EC_KEY_ALGORITHM)
                .apply { initialize(ECGenParameterSpec(P384_CURVE_NAME)) }
                .generateKeyPair()
        val digest =
            java.security.MessageDigest
                .getInstance("SHA-384")
                .digest(SIGNED_ATTRIBUTES)
        val derSignature =
            sign(
                keyPair = keyPair,
                algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
                content = SIGNED_ATTRIBUTES,
            )
        val rawSignature = derP384EcdsaToRaw(derSignature)

        assertTrue(
            QualifiedSignatureVerifier.verifyPrehashed(
                publicKey = keyPair.public,
                algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
                digest = digest,
                signature = rawSignature,
            ),
        )
        val differentDigest =
            java.security.MessageDigest
                .getInstance("SHA-384")
                .digest(DIFFERENT_ATTRIBUTES)
        assertFalse(
            QualifiedSignatureVerifier.verifyPrehashed(
                publicKey = keyPair.public,
                algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
                digest = differentDigest,
                signature = rawSignature,
            ),
        )
    }

    private fun sign(
        keyPair: KeyPair,
        algorithm: QualifiedSigningAlgorithm,
        content: ByteArray,
    ): ByteArray =
        Signature
            .getInstance(
                when (algorithm) {
                    QualifiedSigningAlgorithm.RSA_PKCS1_SHA384 -> JCA_SHA384_WITH_RSA
                    QualifiedSigningAlgorithm.ECDSA_P384_SHA384 -> JCA_SHA384_WITH_ECDSA
                },
            ).apply {
                initSign(keyPair.private)
                update(content)
            }.sign()

    private fun derP384EcdsaToRaw(der: ByteArray): ByteArray {
        var offset = DER_INITIAL_OFFSET
        require(der[offset++].toUnsignedInt() == DER_SEQUENCE_TAG)
        val sequenceLength = readDerLength(der, offset)
        offset += sequenceLength.encodedByteCount
        require(offset + sequenceLength.value == der.size)
        val r = readDerInteger(der, offset)
        offset = r.nextOffset
        val s = readDerInteger(der, offset)
        require(s.nextOffset == der.size)
        return ByteArray(P384_RAW_SIGNATURE_LENGTH).also { raw ->
            copyUnsignedCoordinate(r.bytes, raw, FIRST_COORDINATE_DESTINATION_OFFSET)
            copyUnsignedCoordinate(s.bytes, raw, P384_COORDINATE_LENGTH)
        }
    }

    private fun readDerInteger(
        der: ByteArray,
        start: Int,
    ): DerInteger {
        var offset = start
        require(der[offset++].toUnsignedInt() == DER_INTEGER_TAG)
        val length = readDerLength(der, offset)
        offset += length.encodedByteCount
        require(
            length.value in
                DER_MINIMUM_INTEGER_LENGTH..P384_COORDINATE_LENGTH + DER_OPTIONAL_SIGN_PREFIX_LENGTH,
        )
        return DerInteger(
            bytes = der.copyOfRange(offset, offset + length.value),
            nextOffset = offset + length.value,
        )
    }

    private fun readDerLength(
        der: ByteArray,
        offset: Int,
    ): DerLength {
        val first = der[offset].toUnsignedInt()
        if (first < DER_LONG_FORM_MARKER) {
            return DerLength(first, DER_SHORT_LENGTH_ENCODED_BYTE_COUNT)
        }
        val byteCount = first and DER_LENGTH_VALUE_MASK
        require(byteCount in DER_MINIMUM_LENGTH_OCTETS..DER_MAXIMUM_LENGTH_OCTETS)
        var value = DER_INITIAL_LENGTH_VALUE
        repeat(byteCount) { index ->
            value =
                (value shl Byte.SIZE_BITS) or
                der[offset + DER_LENGTH_PREFIX_BYTE_COUNT + index].toUnsignedInt()
        }
        return DerLength(value, DER_LENGTH_PREFIX_BYTE_COUNT + byteCount)
    }

    private fun copyUnsignedCoordinate(
        integer: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
    ) {
        val sourceOffset =
            if (
                integer.size > DER_MINIMUM_INTEGER_LENGTH &&
                integer[FIRST_INTEGER_BYTE_OFFSET] == ZERO_BYTE
            ) {
                DER_OPTIONAL_SIGN_PREFIX_LENGTH
            } else {
                FIRST_INTEGER_BYTE_OFFSET
            }
        val sourceLength = integer.size - sourceOffset
        require(sourceLength <= P384_COORDINATE_LENGTH)
        integer.copyInto(
            destination = destination,
            destinationOffset = destinationOffset + P384_COORDINATE_LENGTH - sourceLength,
            startIndex = sourceOffset,
        )
    }

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private data class DerLength(
        val value: Int,
        val encodedByteCount: Int,
    )

    private data class DerInteger(
        val bytes: ByteArray,
        val nextOffset: Int,
    )

    private companion object {
        val SIGNED_ATTRIBUTES = "qualified signed attributes".encodeToByteArray()
        val DIFFERENT_ATTRIBUTES = "different signed attributes".encodeToByteArray()

        const val RSA_KEY_ALGORITHM = "RSA"
        const val EC_KEY_ALGORITHM = "EC"
        const val P384_CURVE_NAME = "secp384r1"
        const val JCA_SHA384_WITH_RSA = "SHA384withRSA"
        const val JCA_SHA384_WITH_ECDSA = "SHA384withECDSA"
        const val P384_COORDINATE_LENGTH = P384_COORDINATE_LENGTH_BITS / Byte.SIZE_BITS
        const val ECDSA_COORDINATE_COUNT = 2
        const val P384_RAW_SIGNATURE_LENGTH =
            P384_COORDINATE_LENGTH * ECDSA_COORDINATE_COUNT
        const val FIRST_SIGNATURE_BYTE_OFFSET = 0
        const val SINGLE_BIT_CORRUPTION_MASK = 1
        const val DER_INITIAL_OFFSET = 0
        const val FIRST_COORDINATE_DESTINATION_OFFSET = 0
        const val FIRST_INTEGER_BYTE_OFFSET = 0
        const val DER_MINIMUM_INTEGER_LENGTH = 1
        const val DER_OPTIONAL_SIGN_PREFIX_LENGTH = 1
        const val DER_MINIMUM_LENGTH_OCTETS = 1
        const val DER_MAXIMUM_LENGTH_OCTETS = 2
        const val DER_SHORT_LENGTH_ENCODED_BYTE_COUNT = 1
        const val DER_LENGTH_PREFIX_BYTE_COUNT = 1
        const val DER_INITIAL_LENGTH_VALUE = 0
        const val ZERO_BYTE: Byte = 0
        const val DER_SEQUENCE_TAG = 0x30
        const val DER_INTEGER_TAG = 0x02
        const val DER_LONG_FORM_MARKER = 0x80
        const val DER_LENGTH_VALUE_MASK = 0x7F
    }
}
