package fi.refineid.android.core

import java.math.BigInteger
import java.security.MessageDigest
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey

/** RFC 8017 EMSA-PSS verification when the caller already owns a SHA-2 digest. */
internal object RsaPssPrehashedVerifier {
    fun verify(
        publicKey: PublicKey,
        digestAlgorithm: AuthenticationDigest,
        digest: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val digestLength = digestAlgorithm.length
        if (digest.size != digestLength) {
            return false
        }
        val rsaPublicKey = publicKey as? RSAPublicKey ?: return false
        val modulusLength = byteLength(rsaPublicKey.modulus.bitLength())
        if (signature.size != modulusLength) {
            return false
        }
        val encodedMessageBitLength = rsaPublicKey.modulus.bitLength() - PSS_BIT_LENGTH_REDUCTION
        val encodedMessageLength = byteLength(encodedMessageBitLength)
        if (
            encodedMessageLength <
            digestLength + digestLength + PSS_FIXED_LENGTH_BYTES
        ) {
            return false
        }

        val recovered = recoverEncodedMessage(rsaPublicKey, signature) ?: return false
        val leadingByteCount = recovered.size - encodedMessageLength
        if (
            leadingByteCount < 0 ||
            recovered.copyOfRange(FIRST_BYTE_OFFSET, leadingByteCount).any { it != ZERO_BYTE }
        ) {
            recovered.fill(ZERO_BYTE)
            return false
        }
        val encodedMessage = recovered.copyOfRange(leadingByteCount, recovered.size)
        recovered.fill(ZERO_BYTE)
        return verifyEncodedMessage(
            encodedMessage = encodedMessage,
            encodedMessageBitLength = encodedMessageBitLength,
            digestAlgorithm = digestAlgorithm,
            digest = digest,
        )
    }

    private fun verifyEncodedMessage(
        encodedMessage: ByteArray,
        encodedMessageBitLength: Int,
        digestAlgorithm: AuthenticationDigest,
        digest: ByteArray,
    ): Boolean {
        val digestLength = digestAlgorithm.length
        val saltLength = digestLength
        val encodedMessageLength = encodedMessage.size
        val maskedDataBlockLength =
            encodedMessageLength - digestLength - PSS_TRAILER_LENGTH_BYTES
        val hashOffset = maskedDataBlockLength
        val trailerOffset = encodedMessage.lastIndex
        if (encodedMessage[trailerOffset] != PSS_TRAILER_FIELD) {
            encodedMessage.fill(ZERO_BYTE)
            return false
        }

        val maskedDataBlock =
            encodedMessage.copyOfRange(FIRST_BYTE_OFFSET, maskedDataBlockLength)
        val hash =
            encodedMessage.copyOfRange(
                hashOffset,
                hashOffset + digestLength,
            )
        encodedMessage.fill(ZERO_BYTE)
        val unusedBitCount = encodedMessageLength * Byte.SIZE_BITS - encodedMessageBitLength
        if (!hasValidUnusedBits(maskedDataBlock, unusedBitCount)) {
            maskedDataBlock.fill(ZERO_BYTE)
            hash.fill(ZERO_BYTE)
            return false
        }

        val dataBlockMask =
            maskGenerationFunction(
                seed = hash,
                outputLength = maskedDataBlockLength,
                digestAlgorithm = digestAlgorithm,
            )
        val dataBlock =
            ByteArray(maskedDataBlockLength) { index ->
                (maskedDataBlock[index].toUnsignedInt() xor dataBlockMask[index].toUnsignedInt())
                    .toByte()
            }
        maskedDataBlock.fill(ZERO_BYTE)
        dataBlockMask.fill(ZERO_BYTE)
        clearUnusedBits(dataBlock, unusedBitCount)

        val paddingLength =
            encodedMessageLength -
                digestLength -
                saltLength -
                PSS_FIXED_LENGTH_BYTES
        if (
            dataBlock.copyOfRange(FIRST_BYTE_OFFSET, paddingLength).any { it != ZERO_BYTE } ||
            dataBlock[paddingLength] != PSS_DATA_BLOCK_DELIMITER
        ) {
            dataBlock.fill(ZERO_BYTE)
            hash.fill(ZERO_BYTE)
            return false
        }

        val saltOffset = paddingLength + PSS_DELIMITER_LENGTH_BYTES
        val salt = dataBlock.copyOfRange(saltOffset, dataBlock.size)
        dataBlock.fill(ZERO_BYTE)
        val hashInput =
            ByteArray(PSS_HASH_PREFIX_LENGTH_BYTES + digest.size + salt.size).also { bytes ->
                digest.copyInto(bytes, destinationOffset = PSS_HASH_PREFIX_LENGTH_BYTES)
                salt.copyInto(
                    bytes,
                    destinationOffset = PSS_HASH_PREFIX_LENGTH_BYTES + digest.size,
                )
            }
        salt.fill(ZERO_BYTE)
        val expectedHash = MessageDigest.getInstance(digestAlgorithm.jcaName).digest(hashInput)
        hashInput.fill(ZERO_BYTE)
        return try {
            MessageDigest.isEqual(hash, expectedHash)
        } finally {
            hash.fill(ZERO_BYTE)
            expectedHash.fill(ZERO_BYTE)
        }
    }

    private fun recoverEncodedMessage(
        publicKey: RSAPublicKey,
        signature: ByteArray,
    ): ByteArray? {
        val signatureValue = BigInteger(POSITIVE_BIG_INTEGER_SIGNUM, signature)
        if (signatureValue >= publicKey.modulus) {
            return null
        }
        val recoveredValue = signatureValue.modPow(publicKey.publicExponent, publicKey.modulus)
        return toFixedLength(
            value = recoveredValue,
            length = byteLength(publicKey.modulus.bitLength()),
        )
    }

    private fun toFixedLength(
        value: BigInteger,
        length: Int,
    ): ByteArray? {
        val signedBytes = value.toByteArray()
        val sourceOffset =
            if (
                signedBytes.size > length &&
                signedBytes[FIRST_BYTE_OFFSET] == ZERO_BYTE
            ) {
                POSITIVE_SIGN_PREFIX_LENGTH_BYTES
            } else {
                NO_SIGN_PREFIX_LENGTH_BYTES
            }
        val sourceLength = signedBytes.size - sourceOffset
        if (sourceLength > length) {
            signedBytes.fill(ZERO_BYTE)
            return null
        }
        return ByteArray(length).also { fixed ->
            signedBytes.copyInto(
                destination = fixed,
                destinationOffset = length - sourceLength,
                startIndex = sourceOffset,
            )
            signedBytes.fill(ZERO_BYTE)
        }
    }

    private fun maskGenerationFunction(
        seed: ByteArray,
        outputLength: Int,
        digestAlgorithm: AuthenticationDigest,
    ): ByteArray {
        val output = ByteArray(outputLength)
        val digest = MessageDigest.getInstance(digestAlgorithm.jcaName)
        var outputOffset = FIRST_BYTE_OFFSET
        var counter = MGF1_INITIAL_COUNTER
        while (outputOffset < output.size) {
            val counterBytes = encodeCounter(counter)
            digest.update(seed)
            val block = digest.digest(counterBytes)
            counterBytes.fill(ZERO_BYTE)
            val copyLength = minOf(block.size, output.size - outputOffset)
            block.copyInto(
                destination = output,
                destinationOffset = outputOffset,
                startIndex = FIRST_BYTE_OFFSET,
                endIndex = copyLength,
            )
            block.fill(ZERO_BYTE)
            outputOffset += copyLength
            counter += MGF1_COUNTER_INCREMENT
        }
        return output
    }

    private fun encodeCounter(counter: Int): ByteArray =
        ByteArray(MGF1_COUNTER_LENGTH_BYTES) { index ->
            val shift =
                (MGF1_COUNTER_LENGTH_BYTES - LAST_ELEMENT_DISTANCE - index) * Byte.SIZE_BITS
            (counter ushr shift).toByte()
        }

    private fun hasValidUnusedBits(
        maskedDataBlock: ByteArray,
        unusedBitCount: Int,
    ): Boolean {
        if (unusedBitCount == NO_UNUSED_BITS) {
            return true
        }
        if (unusedBitCount !in MINIMUM_UNUSED_BIT_COUNT until Byte.SIZE_BITS) {
            return false
        }
        val forbiddenMask =
            UNSIGNED_BYTE_MAX shl (Byte.SIZE_BITS - unusedBitCount) and UNSIGNED_BYTE_MAX
        return maskedDataBlock[FIRST_BYTE_OFFSET].toUnsignedInt() and forbiddenMask == 0
    }

    private fun clearUnusedBits(
        dataBlock: ByteArray,
        unusedBitCount: Int,
    ) {
        if (unusedBitCount != NO_UNUSED_BITS) {
            val permittedMask = UNSIGNED_BYTE_MAX ushr unusedBitCount
            dataBlock[FIRST_BYTE_OFFSET] =
                (dataBlock[FIRST_BYTE_OFFSET].toUnsignedInt() and permittedMask).toByte()
        }
    }

    private fun byteLength(bitLength: Int): Int = (bitLength + BYTE_LENGTH_ROUNDING_BITS) / Byte.SIZE_BITS

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private const val POSITIVE_BIG_INTEGER_SIGNUM = 1
    private const val PSS_BIT_LENGTH_REDUCTION = 1
    private const val PSS_TRAILER_LENGTH_BYTES = 1
    private const val PSS_DELIMITER_LENGTH_BYTES = 1
    private const val PSS_FIXED_LENGTH_BYTES =
        PSS_TRAILER_LENGTH_BYTES + PSS_DELIMITER_LENGTH_BYTES
    private const val PSS_HASH_PREFIX_LENGTH_BYTES = 8
    private const val MGF1_COUNTER_LENGTH_BYTES = 4
    private const val MGF1_INITIAL_COUNTER = 0
    private const val MGF1_COUNTER_INCREMENT = 1
    private const val FIRST_BYTE_OFFSET = 0
    private const val POSITIVE_SIGN_PREFIX_LENGTH_BYTES = 1
    private const val NO_SIGN_PREFIX_LENGTH_BYTES = 0
    private const val LAST_ELEMENT_DISTANCE = 1
    private const val NO_UNUSED_BITS = 0
    private const val MINIMUM_UNUSED_BIT_COUNT = 1
    private const val BYTE_LENGTH_ROUNDING_BITS = Byte.SIZE_BITS - 1
    private val UNSIGNED_BYTE_MAX = UByte.MAX_VALUE.toInt()
    private const val PSS_DATA_BLOCK_DELIMITER: Byte = 0x01
    private val PSS_TRAILER_FIELD: Byte = 0xBC.toByte()
    private const val ZERO_BYTE: Byte = 0
}
