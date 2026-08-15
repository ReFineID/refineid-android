package fi.refineid.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeAuthenticationCertificateReplyTest {
    @Test
    fun decodesOwnedCertificateAndClearsTheNativeReply() {
        val reply =
            byteArrayOf(
                CERTIFICATE_SUCCEEDED,
                KEY_PROFILE_RSA_2048,
                SYNTHETIC_DER_TAG,
                SYNTHETIC_DER_LENGTH,
            )

        val result =
            NativeAuthenticationCertificateReply.decode(reply)
                as NativeAuthenticationCertificateReadResult.Success

        assertTrue(reply.all { byte -> byte == 0.toByte() })
        assertEquals(NativeAuthenticationKeyProfile.RSA_2048, result.certificate.keyProfile)
        assertEquals(SYNTHETIC_DER.size, result.certificate.derLength)
        val copied = result.certificate.copyDer()
        assertArrayEquals(SYNTHETIC_DER, copied)
        copied.fill(0)

        result.certificate.close()
        assertThrows(IllegalStateException::class.java) {
            result.certificate.copyDer()
        }
    }

    @Test
    fun decodesEachOneByteFailureAndClearsItsReply() {
        val cases =
            listOf(
                CERTIFICATE_CARD_UNAVAILABLE to
                    NativeAuthenticationCertificateReadFailure.CARD_UNAVAILABLE,
                CERTIFICATE_REJECTED to
                    NativeAuthenticationCertificateReadFailure.REJECTED,
                CERTIFICATE_TRANSPORT_ERROR to
                    NativeAuthenticationCertificateReadFailure.TRANSPORT_ERROR,
                CERTIFICATE_INVALID to
                    NativeAuthenticationCertificateReadFailure.INVALID_CERTIFICATE,
                CERTIFICATE_BRIDGE_ERROR to
                    NativeAuthenticationCertificateReadFailure.BRIDGE_ERROR,
            )

        for ((tag, expected) in cases) {
            val reply = byteArrayOf(tag)
            val result =
                NativeAuthenticationCertificateReply.decode(reply)
                    as NativeAuthenticationCertificateReadResult.Failure

            assertEquals(expected, result.kind)
            assertArrayEquals(CLEARED_FAILURE_REPLY, reply)
        }
    }

    @Test
    fun rejectsPayloadBearingFailureAndUnknownProfile() {
        val payloadBearingFailure =
            byteArrayOf(CERTIFICATE_REJECTED, SYNTHETIC_DER_TAG)
        val unknownProfile =
            byteArrayOf(CERTIFICATE_SUCCEEDED, UNKNOWN_KEY_PROFILE, SYNTHETIC_DER_TAG)

        assertBridgeFailure(NativeAuthenticationCertificateReply.decode(payloadBearingFailure))
        assertBridgeFailure(NativeAuthenticationCertificateReply.decode(unknownProfile))
        assertTrue(payloadBearingFailure.all { byte -> byte == 0.toByte() })
        assertTrue(unknownProfile.all { byte -> byte == 0.toByte() })
    }

    private fun assertBridgeFailure(result: NativeAuthenticationCertificateReadResult) {
        assertEquals(
            NativeAuthenticationCertificateReadFailure.BRIDGE_ERROR,
            (result as NativeAuthenticationCertificateReadResult.Failure).kind,
        )
    }

    private companion object {
        const val CERTIFICATE_BRIDGE_ERROR: Byte = 0
        const val CERTIFICATE_SUCCEEDED: Byte = 1
        const val CERTIFICATE_CARD_UNAVAILABLE: Byte = 2
        const val CERTIFICATE_REJECTED: Byte = 3
        const val CERTIFICATE_TRANSPORT_ERROR: Byte = 4
        const val CERTIFICATE_INVALID: Byte = 5
        const val KEY_PROFILE_RSA_2048: Byte = 0
        const val UNKNOWN_KEY_PROFILE: Byte = 0x7F
        const val SYNTHETIC_DER_TAG: Byte = 0x30
        const val SYNTHETIC_DER_LENGTH: Byte = 0
        val CLEARED_FAILURE_REPLY = byteArrayOf(0)
        val SYNTHETIC_DER = byteArrayOf(SYNTHETIC_DER_TAG, SYNTHETIC_DER_LENGTH)
    }
}
