// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.asic

internal class PreparedAsicSignature(
    val plan: XadesPlan,
    val objects: List<AsicDataObject>,
    val rawSignature: ByteArray,
    val certificateDer: ByteArray,
) : AutoCloseable {
    private var isClosed = false

    override fun close() {
        if (!isClosed) {
            rawSignature.fill(0)
            certificateDer.fill(0)
            isClosed = true
        }
    }
}

internal sealed interface PreparedAsicSignatureResult {
    class Success(
        val prepared: PreparedAsicSignature,
    ) : PreparedAsicSignatureResult

    class Failure(
        val reason: AsicSigningFailure,
    ) : PreparedAsicSignatureResult
}
