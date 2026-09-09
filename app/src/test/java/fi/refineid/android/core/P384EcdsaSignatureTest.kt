@file:Suppress("MagicNumber")

package fi.refineid.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.security.SecureRandom

class P384EcdsaSignatureTest {
    @Test
    fun roundtripPreservesRawSignature() {
        val random = SecureRandom()
        for (i in 0 until 50) {
            val raw = ByteArray(96).also { random.nextBytes(it) }
            val der = P384EcdsaSignature.toDer(raw)
            val recovered = P384EcdsaSignature.fromDer(der)
            assertArrayEquals("Failed on iteration $i", raw, recovered)
        }
    }

    @Test
    fun fromDerHandlesAlreadyRawSignature() {
        val raw = ByteArray(96) { it.toByte() }
        val result = P384EcdsaSignature.fromDer(raw)
        assertArrayEquals(raw, result)
    }

    @Test
    fun roundtripWithHighBitSetCoordinates() {
        val raw = ByteArray(96)
        raw[0] = 0x80.toByte()
        raw[1] = 0x01
        raw[48] = 0xFF.toByte()
        raw[49] = 0x7F
        val der = P384EcdsaSignature.toDer(raw)
        val recovered = P384EcdsaSignature.fromDer(der)
        assertArrayEquals(raw, recovered)
    }

    @Test
    fun roundtripWithLeadingZerosCoordinates() {
        val raw = ByteArray(96)
        raw[0] = 0x00
        raw[1] = 0x05
        raw[48] = 0x00
        raw[49] = 0x09
        val der = P384EcdsaSignature.toDer(raw)
        val recovered = P384EcdsaSignature.fromDer(der)
        assertArrayEquals(raw, recovered)
    }

    @Test(expected = IllegalArgumentException::class)
    fun fromDerRejectsInvalidHeader() {
        val invalid = byteArrayOf(0x02, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06)
        P384EcdsaSignature.fromDer(invalid)
    }
}
