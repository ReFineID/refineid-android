package fi.refineid.android.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec

@RunWith(AndroidJUnit4::class)
internal class AuthenticationSignatureVerifierInstrumentedTest {
    @Test
    fun verifiesEveryPrehashedCardAlgorithmWithAndroidProviders() {
        val rsaKeyPair =
            KeyPairGenerator
                .getInstance(JCA_RSA_KEY_ALGORITHM)
                .apply { initialize(RSA_3072_KEY_LENGTH_BITS) }
                .generateKeyPair()
        val ecKeyPair =
            KeyPairGenerator
                .getInstance(JCA_EC_KEY_ALGORITHM)
                .apply { initialize(ECGenParameterSpec(P384_CURVE_NAME)) }
                .generateKeyPair()

        for (algorithm in AuthenticationSigningAlgorithm.entries) {
            val keyPair =
                when (algorithm.keyProfile) {
                    NativeAuthenticationKeyProfile.RSA_3072 -> rsaKeyPair

                    NativeAuthenticationKeyProfile.ECDSA_P384 -> ecKeyPair

                    NativeAuthenticationKeyProfile.RSA_2048,
                    NativeAuthenticationKeyProfile.ECDSA_P256,
                    -> throw AssertionError("unexpected authentication key profile")
                }
            val providerSignature = sign(keyPair, algorithm, SYNTHETIC_MESSAGE)
            val cardSignature =
                when (algorithm.keyProfile) {
                    NativeAuthenticationKeyProfile.RSA_3072 -> {
                        providerSignature
                    }

                    NativeAuthenticationKeyProfile.ECDSA_P384 -> {
                        derP384EcdsaToRaw(providerSignature).also {
                            providerSignature.fill(ZERO_BYTE)
                        }
                    }

                    NativeAuthenticationKeyProfile.RSA_2048,
                    NativeAuthenticationKeyProfile.ECDSA_P256,
                    -> {
                        throw AssertionError("unexpected authentication key profile")
                    }
                }
            val digest = digest(algorithm, SYNTHETIC_MESSAGE)
            val alteredDigest = digest.copyOf()
            alteredDigest[FIRST_BYTE_OFFSET] =
                (
                    alteredDigest[FIRST_BYTE_OFFSET].toInt() xor
                        SINGLE_BIT_CORRUPTION_MASK
                ).toByte()

            try {
                assertTrue(
                    AuthenticationSignatureVerifier.verify(
                        publicKey = keyPair.public,
                        algorithm = algorithm,
                        message = SYNTHETIC_MESSAGE,
                        signature = cardSignature,
                    ),
                )
                assertTrue(
                    AuthenticationSignatureVerifier.verifyPrehashed(
                        publicKey = keyPair.public,
                        algorithm = algorithm,
                        digest = digest,
                        signature = cardSignature,
                    ),
                )
                assertFalse(
                    AuthenticationSignatureVerifier.verifyPrehashed(
                        publicKey = keyPair.public,
                        algorithm = algorithm,
                        digest = alteredDigest,
                        signature = cardSignature,
                    ),
                )
            } finally {
                cardSignature.fill(ZERO_BYTE)
                digest.fill(ZERO_BYTE)
                alteredDigest.fill(ZERO_BYTE)
            }
        }
    }

    private fun sign(
        keyPair: KeyPair,
        algorithm: AuthenticationSigningAlgorithm,
        message: ByteArray,
    ): ByteArray {
        val signer = Signature.getInstance(algorithm.jcaSignatureName())
        signer.initSign(keyPair.private)
        signer.update(message)
        return signer.sign()
    }

    private fun digest(
        algorithm: AuthenticationSigningAlgorithm,
        message: ByteArray,
    ): ByteArray = MessageDigest.getInstance(algorithm.jcaDigestName()).digest(message)

    private fun AuthenticationSigningAlgorithm.jcaSignatureName(): String =
        when (this) {
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256 -> JCA_SHA256_WITH_RSA
            AuthenticationSigningAlgorithm.RSA_PSS_SHA256 -> JCA_RSA_PSS
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA256 -> JCA_SHA256_WITH_ECDSA
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA384 -> JCA_SHA384_WITH_ECDSA
        }

    private fun AuthenticationSigningAlgorithm.jcaDigestName(): String =
        when (this) {
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA256,
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA256,
            -> JCA_SHA256_DIGEST

            AuthenticationSigningAlgorithm.ECDSA_P384_SHA384 -> JCA_SHA384_DIGEST
        }

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
            r.bytes.fill(ZERO_BYTE)
            s.bytes.fill(ZERO_BYTE)
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
                integer[FIRST_BYTE_OFFSET] == ZERO_BYTE
            ) {
                DER_OPTIONAL_SIGN_PREFIX_LENGTH
            } else {
                FIRST_BYTE_OFFSET
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
        const val JCA_RSA_KEY_ALGORITHM = "RSA"
        const val JCA_EC_KEY_ALGORITHM = "EC"
        const val P384_CURVE_NAME = "secp384r1"
        const val JCA_SHA256_WITH_RSA = "SHA256withRSA"
        const val JCA_RSA_PSS = "SHA256withRSA/PSS"
        const val JCA_SHA256_WITH_ECDSA = "SHA256withECDSA"
        const val JCA_SHA384_WITH_ECDSA = "SHA384withECDSA"
        const val JCA_SHA256_DIGEST = "SHA-256"
        const val JCA_SHA384_DIGEST = "SHA-384"

        val SYNTHETIC_MESSAGE = "prehashed browser authentication".encodeToByteArray()

        const val P384_COORDINATE_LENGTH = P384_COORDINATE_LENGTH_BITS / Byte.SIZE_BITS
        const val ECDSA_COORDINATE_COUNT = 2
        const val P384_RAW_SIGNATURE_LENGTH =
            P384_COORDINATE_LENGTH * ECDSA_COORDINATE_COUNT
        const val FIRST_BYTE_OFFSET = 0
        const val FIRST_COORDINATE_DESTINATION_OFFSET = 0
        const val SINGLE_BIT_CORRUPTION_MASK = 1
        const val DER_INITIAL_OFFSET = 0
        const val DER_MINIMUM_INTEGER_LENGTH = 1
        const val DER_OPTIONAL_SIGN_PREFIX_LENGTH = 1
        const val DER_MINIMUM_LENGTH_OCTETS = 1
        const val DER_MAXIMUM_LENGTH_OCTETS = 2
        const val DER_SHORT_LENGTH_ENCODED_BYTE_COUNT = 1
        const val DER_LENGTH_PREFIX_BYTE_COUNT = 1
        const val DER_INITIAL_LENGTH_VALUE = 0
        const val DER_SEQUENCE_TAG = 0x30
        const val DER_INTEGER_TAG = 0x02
        const val DER_LONG_FORM_MARKER = 0x80
        const val DER_LENGTH_VALUE_MASK = 0x7F
        const val ZERO_BYTE: Byte = 0
    }
}
