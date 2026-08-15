// Copyright 2026 ReFineID contributors. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import java.io.ByteArrayOutputStream

/** Retains a response only while every byte remains inside its declared limit. */
internal class SigningNetworkResponseBody(
    private val limit: Int,
) {
    private val output = ByteArrayOutputStream()

    init {
        require(limit > MINIMUM_RESPONSE_LIMIT)
    }

    val size: Int
        get() = output.size()

    fun append(
        source: ByteArray,
        length: Int,
    ): Boolean {
        if (
            length < MINIMUM_CHUNK_LENGTH ||
            length > source.size ||
            output.size() > limit - length
        ) {
            return false
        }
        output.write(source, FIRST_BYTE_OFFSET, length)
        return true
    }

    fun toByteArray(): ByteArray = output.toByteArray()

    private companion object {
        const val MINIMUM_RESPONSE_LIMIT = 0
        const val MINIMUM_CHUNK_LENGTH = 0
        const val FIRST_BYTE_OFFSET = 0
    }
}
