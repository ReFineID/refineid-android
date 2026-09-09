// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/** One top-level PDF dictionary key and the exact byte range of its value. */
internal data class PdfDictionaryEntry(
    val name: String,
    val rawName: String,
    val valueRange: PdfBytes.Range,
)

/** A token-aware PDF dictionary retaining the original spelling of every value. */
internal class PdfDictionarySyntax(
    text: String,
) {
    private val source = strictLatin1(text)
    val entries: List<PdfDictionaryEntry>
    private val closingOffset: Int

    init {
        val parser = PdfValueParser(source)
        val parsed = parser.dictionary()
        parser.requireEnd()
        entries = parsed.entries
        closingOffset = parsed.closingOffset
    }

    fun entry(name: String): PdfDictionaryEntry? = entries.firstOrNull { entry -> entry.name == name }

    fun value(entry: PdfDictionaryEntry): String =
        latin1(source.copyOfRange(entry.valueRange.start, entry.valueRange.endExclusive))

    fun encoded(): String = latin1(source.copyOf())

    fun replacing(
        name: String,
        value: String,
    ): String {
        if (!PdfValueParser.isPlainName(name)) {
            throw unreadable()
        }
        val encodedValue = strictLatin1(value)
        val existing = entry(name)
        val updated =
            if (existing == null) {
                val insertion = strictLatin1("\n/$name $value\n")
                source.replacing(
                    start = closingOffset,
                    endExclusive = closingOffset,
                    replacement = insertion,
                )
            } else {
                source.replacing(
                    start = existing.valueRange.start,
                    endExclusive = existing.valueRange.endExclusive,
                    replacement = encodedValue,
                )
            }
        return latin1(updated).also(::PdfDictionarySyntax)
    }

    private fun ByteArray.replacing(
        start: Int,
        endExclusive: Int,
        replacement: ByteArray,
    ): ByteArray {
        val removedLength = endExclusive - start
        val resultSize =
            try {
                Math.addExact(size - removedLength, replacement.size)
            } catch (_: ArithmeticException) {
                throw unreadable()
            }
        return ByteArray(resultSize).also { result ->
            copyInto(
                destination = result,
                startIndex = FIRST_BYTE_OFFSET,
                endIndex = start,
            )
            replacement.copyInto(result, destinationOffset = start)
            copyInto(
                destination = result,
                destinationOffset = start + replacement.size,
                startIndex = endExclusive,
            )
        }
    }

    private companion object {
        const val FIRST_BYTE_OFFSET = 0

        fun strictLatin1(text: String): ByteArray {
            if (text.any { character -> character.code > MAXIMUM_LATIN1_CODE_POINT }) {
                throw unreadable()
            }
            return text.toByteArray(Charsets.ISO_8859_1)
        }

        fun latin1(bytes: ByteArray): String = String(bytes, Charsets.ISO_8859_1)

        fun unreadable(): PdfSigningException = PdfSigningException(PdfSigningFailure.STRUCTURE_UNREADABLE)

        const val MAXIMUM_LATIN1_CODE_POINT = 0xFF
    }
}
