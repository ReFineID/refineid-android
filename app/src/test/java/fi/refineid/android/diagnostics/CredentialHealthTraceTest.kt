// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.diagnostics

import fi.refineid.android.core.CardActivationNeeds
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.NativePin1State
import fi.refineid.android.core.NativePin2State
import fi.refineid.android.core.NativePinReferenceScheme
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialHealthTraceTest {
    @Test
    fun healthTraceNamesStatesAndNeedsWithoutSecrets() {
        AppTrace.clearTraceLog()
        AppTrace.credentialHealth(
            CredentialHealth(
                pin1State = NativePin1State.Remaining(attempts = 3),
                pin2State = NativePin2State.Verified,
                pukState = NativePin1State.NoInformation,
                scheme = NativePinReferenceScheme.CITIZEN,
                activationScheme = CardManagementScheme.PRESET_PIN,
                activationNeeds = CardActivationNeeds(pin1 = false, pin2 = true),
            ),
        )
        val line = AppTrace.getTraceLog().last()
        assertTrue(line.contains("pin1=remaining-3"))
        assertTrue(line.contains("needs-pin1=false"))
        assertTrue(line.contains("needs-pin2=true"))
        assertTrue(line.contains("activation-scheme=PRESET_PIN"))
    }
}
