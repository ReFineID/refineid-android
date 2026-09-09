package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RappPairingCodeTest {
    @Test
    fun testPairingCodeDeterministic() {
        val code = "507313"
        val offerId1 = RappPairingCode.offerIdentifier(code)
        val offerId2 = RappPairingCode.offerIdentifier(code)
        assertEquals(offerId1.toList(), offerId2.toList())

        val secret1 = RappPairingCode.pairingSecret(code)
        val secret2 = RappPairingCode.pairingSecret(code)
        assertEquals(secret1.toList(), secret2.toList())
        assertTrue(RappPairingCode.isValid(code))
    }
}
