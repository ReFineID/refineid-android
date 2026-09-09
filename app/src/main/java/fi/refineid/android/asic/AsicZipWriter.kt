package fi.refineid.android.asic

import java.io.ByteArrayOutputStream

/**
 * A minimal ZIP writer for ASiC-E containers, ported from the reference
 * implementation. ETSI EN 319 162-1 requires the `mimetype` entry first
 * and uncompressed with no extra field; this writer stores every entry
 * uncompressed, which satisfies that rule by construction and keeps the
 * archive verifiable without a decompressor. Timestamps are zeroed so a
 * container is byte-identical for identical inputs.
 */
internal class AsicZipWriter {
    private class Entry(
        val name: ByteArray,
        val isAscii: Boolean,
        val crc: Int,
        val length: Int,
        val offset: Int,
    )

    private val body = ByteArrayOutputStream()
    private val entries = mutableListOf<Entry>()
    private var failed = false

    fun add(
        name: String,
        content: ByteArray,
    ) {
        val nameBytes = name.encodeToByteArray()
        val offset = body.size()
        if (nameBytes.size > MAXIMUM_SHORT || content.size < 0) {
            failed = true
            return
        }
        entries +=
            Entry(
                name = nameBytes,
                isAscii = name.all { it.code < ASCII_LIMIT },
                crc = Crc32.of(content),
                length = content.size,
                offset = offset,
            )
        writeLocalHeader(entries.last())
        body.write(content)
    }

    /** The finished archive, or null when a 32-bit field overflowed. */
    fun finish(): ByteArray? {
        if (failed || entries.size > MAXIMUM_SHORT) {
            return null
        }
        val directoryOffset = body.size()
        entries.forEach(::writeCentralRecord)
        val directoryLength = body.size() - directoryOffset
        writeInt(EOCD_SIGNATURE)
        writeShort(0)
        writeShort(0)
        writeShort(entries.size)
        writeShort(entries.size)
        writeInt(directoryLength)
        writeInt(directoryOffset)
        writeShort(0)
        return body.toByteArray()
    }

    private fun writeLocalHeader(entry: Entry) {
        writeInt(LOCAL_SIGNATURE)
        writeShort(VERSION)
        writeShort(flags(entry))
        writeShort(METHOD_STORED)
        writeShort(0)
        writeShort(0)
        writeInt(entry.crc)
        writeInt(entry.length)
        writeInt(entry.length)
        writeShort(entry.name.size)
        writeShort(0)
        body.write(entry.name)
    }

    private fun writeCentralRecord(entry: Entry) {
        writeInt(CENTRAL_SIGNATURE)
        writeShort(VERSION)
        writeShort(VERSION)
        writeShort(flags(entry))
        writeShort(METHOD_STORED)
        writeShort(0)
        writeShort(0)
        writeInt(entry.crc)
        writeInt(entry.length)
        writeInt(entry.length)
        writeShort(entry.name.size)
        writeShort(0)
        writeShort(0)
        writeShort(0)
        writeShort(0)
        writeInt(0)
        writeInt(entry.offset)
        body.write(entry.name)
    }

    private fun flags(entry: Entry): Int = if (entry.isAscii) 0 else UTF8_NAME_FLAG

    private fun writeShort(value: Int) {
        body.write(value and BYTE_MASK)
        body.write((value ushr Byte.SIZE_BITS) and BYTE_MASK)
    }

    private fun writeInt(value: Int) {
        writeShort(value and SHORT_MASK)
        writeShort((value ushr Short.SIZE_BITS) and SHORT_MASK)
    }

    private companion object {
        const val LOCAL_SIGNATURE = 0x04034B50
        const val CENTRAL_SIGNATURE = 0x02014B50
        const val EOCD_SIGNATURE = 0x06054B50
        const val VERSION = 20
        const val METHOD_STORED = 0
        const val UTF8_NAME_FLAG = 0x0800
        const val MAXIMUM_SHORT = 0xFFFF
        const val ASCII_LIMIT = 0x80
        const val BYTE_MASK = 0xFF
        const val SHORT_MASK = 0xFFFF
    }
}

/** Reflected CRC-32 over the IEEE polynomial, as ZIP requires. */
internal object Crc32 {
    private const val POLYNOMIAL = 0xEDB88320.toInt()
    private const val ROUNDS_PER_BYTE = 8
    private const val BYTE_MASK = 0xFF

    fun of(content: ByteArray): Int {
        var crc = -1
        for (byte in content) {
            crc = crc xor (byte.toInt() and BYTE_MASK)
            repeat(ROUNDS_PER_BYTE) {
                crc =
                    if (crc and 1 != 0) {
                        (crc ushr 1) xor POLYNOMIAL
                    } else {
                        crc ushr 1
                    }
            }
        }
        return crc.inv()
    }
}
