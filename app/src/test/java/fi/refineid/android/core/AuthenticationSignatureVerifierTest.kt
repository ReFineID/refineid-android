package fi.refineid.android.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

class AuthenticationSignatureVerifierTest {
    @Test
    fun verifiesEveryRsaAuthenticationSchemeAndRejectsAnotherMessage() {
        val keyPair =
            KeyPairGenerator
                .getInstance("RSA")
                .apply { initialize(RSA_3072_KEY_LENGTH_BITS) }
                .generateKeyPair()

        for (algorithm in listOf(
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA256,
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA384,
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA512,
        )) {
            val signature = sign(keyPair, algorithm, MESSAGE)
            val digest = digest(algorithm, MESSAGE)
            val otherDigest = digest(algorithm, OTHER_MESSAGE)
            assertTrue(
                AuthenticationSignatureVerifier.verify(
                    publicKey = keyPair.public,
                    algorithm = algorithm,
                    message = MESSAGE,
                    signature = signature,
                ),
            )
            assertFalse(
                AuthenticationSignatureVerifier.verify(
                    publicKey = keyPair.public,
                    algorithm = algorithm,
                    message = OTHER_MESSAGE,
                    signature = signature,
                ),
            )
            assertTrue(
                AuthenticationSignatureVerifier.verifyPrehashed(
                    publicKey = keyPair.public,
                    algorithm = algorithm,
                    digest = digest,
                    signature = signature,
                ),
            )
            assertFalse(
                AuthenticationSignatureVerifier.verifyPrehashed(
                    publicKey = keyPair.public,
                    algorithm = algorithm,
                    digest = otherDigest,
                    signature = signature,
                ),
            )
        }
    }

    @Test
    fun verifiesBothP384AuthenticationSchemesFromRawCardShape() {
        val keyPair =
            KeyPairGenerator
                .getInstance("EC")
                .apply { initialize(ECGenParameterSpec("secp384r1")) }
                .generateKeyPair()

        for (algorithm in listOf(
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA256,
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA384,
        )) {
            val derSignature = sign(keyPair, algorithm, MESSAGE)
            val rawSignature = derP384EcdsaToRaw(derSignature)
            val digest = digest(algorithm, MESSAGE)
            val otherDigest = digest(algorithm, OTHER_MESSAGE)
            assertTrue(
                AuthenticationSignatureVerifier.verify(
                    publicKey = keyPair.public,
                    algorithm = algorithm,
                    message = MESSAGE,
                    signature = rawSignature,
                ),
            )
            assertTrue(
                AuthenticationSignatureVerifier.verifyPrehashed(
                    publicKey = keyPair.public,
                    algorithm = algorithm,
                    digest = digest,
                    signature = rawSignature,
                ),
            )
            assertFalse(
                AuthenticationSignatureVerifier.verifyPrehashed(
                    publicKey = keyPair.public,
                    algorithm = algorithm,
                    digest = otherDigest,
                    signature = rawSignature,
                ),
            )
            rawSignature[FIRST_SIGNATURE_BYTE_OFFSET] =
                (
                    rawSignature[FIRST_SIGNATURE_BYTE_OFFSET].toInt() xor
                        SINGLE_BIT_CORRUPTION_MASK
                ).toByte()
            assertFalse(
                AuthenticationSignatureVerifier.verify(
                    publicKey = keyPair.public,
                    algorithm = algorithm,
                    message = MESSAGE,
                    signature = rawSignature,
                ),
            )
        }
    }

    private fun sign(
        keyPair: KeyPair,
        algorithm: AuthenticationSigningAlgorithm,
        message: ByteArray,
    ): ByteArray {
        val signer =
            Signature.getInstance(
                when (algorithm) {
                    AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256 -> "SHA256withRSA"
                    AuthenticationSigningAlgorithm.RSA_PSS_SHA256 -> "RSASSA-PSS"
                    AuthenticationSigningAlgorithm.ECDSA_P384_SHA256 -> "SHA256withECDSA"
                    AuthenticationSigningAlgorithm.ECDSA_P384_SHA384 -> "SHA384withECDSA"
                    AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384 -> "SHA384withRSA"
                    AuthenticationSigningAlgorithm.RSA_PSS_SHA384 -> "RSASSA-PSS"
                    AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512 -> "SHA512withRSA"
                    AuthenticationSigningAlgorithm.RSA_PSS_SHA512 -> "RSASSA-PSS"
                },
            )
        if (algorithm.isRsaPss()) {
            signer.setParameter(algorithm.digest.rsaPssParameters())
        }
        signer.initSign(keyPair.private)
        signer.update(message)
        return signer.sign()
    }

    private fun digest(
        algorithm: AuthenticationSigningAlgorithm,
        message: ByteArray,
    ): ByteArray = MessageDigest.getInstance(algorithm.digest.jcaName).digest(message)

    private fun AuthenticationSigningAlgorithm.isRsaPss(): Boolean =
        when (this) {
            AuthenticationSigningAlgorithm.RSA_PSS_SHA256,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA384,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA512,
            -> true

            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA256,
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA384,
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384,
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512,
            -> false
        }

    private fun AuthenticationDigest.rsaPssParameters(): PSSParameterSpec =
        PSSParameterSpec(
            jcaName,
            MASK_GENERATION_FUNCTION_NAME,
            when (this) {
                AuthenticationDigest.SHA256 -> MGF1ParameterSpec.SHA256
                AuthenticationDigest.SHA384 -> MGF1ParameterSpec.SHA384
                AuthenticationDigest.SHA512 -> MGF1ParameterSpec.SHA512
            },
            length,
            PSSParameterSpec.DEFAULT.trailerField,
        )

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
        val MESSAGE = "authentication request".encodeToByteArray()
        val OTHER_MESSAGE = "different request".encodeToByteArray()

        const val MASK_GENERATION_FUNCTION_NAME = "MGF1"

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
