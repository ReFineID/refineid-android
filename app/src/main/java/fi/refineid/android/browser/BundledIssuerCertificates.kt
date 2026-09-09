// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.browser

import android.content.Context
import fi.refineid.android.R
import fi.refineid.android.trust.PinnedCertificateBundle
import fi.refineid.android.trust.PinnedCertificateResource
import java.security.cert.X509Certificate

/** Loads only fingerprint-pinned public FINEID intermediate certificates. */
internal object BundledIssuerCertificates {
    fun load(context: Context): List<X509Certificate> =
        PinnedCertificateBundle.load(context = context, resources = RESOURCES)

    private val RESOURCES =
        listOf(
            PinnedCertificateResource(
                R.raw.fineid_intermediate_00_citizen_g3,
                "39A835B14B6B6313F778371C79CB434DD518C8FD325B749D9BE669DFF20384E8",
            ),
            PinnedCertificateResource(
                R.raw.fineid_intermediate_01_citizen_g4e,
                "AAD1BEAC4696102A88BF9D518D64F8B014F78F9B152579C959998313197924D7",
            ),
            PinnedCertificateResource(
                R.raw.fineid_intermediate_02_citizen_g4r,
                "2176C05E69EE24946A140D13F9EFA222B3F1E768E1E2A67B313969CC03B82064",
            ),
            PinnedCertificateResource(
                R.raw.fineid_intermediate_03_organisation_g4r,
                "DFC3E965176F883A9CF0F68CEAEEAB663EDFD8E79DE3294373C28A856984006F",
            ),
        )
}
