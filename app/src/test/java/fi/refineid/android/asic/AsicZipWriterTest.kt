package fi.refineid.android.asic

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.util.zip.ZipInputStream

internal class AsicZipWriterTest {
    @Test
    fun crc32MatchesTheKnownCheckValue() {
        // The ZIP appnote's canonical CRC-32 check value for "123456789".
        assertEquals(0xCBF43926.toInt(), Crc32.of("123456789".encodeToByteArray()))
    }

    @Test
    fun storesEntriesUncompressedInInsertionOrderAndReReads() {
        val writer = AsicZipWriter()
        writer.add("mimetype", MIME_TYPE.encodeToByteArray())
        writer.add("dossier.pdf", PDF_BODY)
        writer.add("META-INF/signatures0.xml", XML_BODY)
        val archive = writer.finish()
        assertNotNull(archive)

        val names = mutableListOf<String>()
        ZipInputStream(ByteArrayInputStream(archive!!)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                names += entry.name
                val body = zip.readBytes()
                when (entry.name) {
                    "mimetype" -> assertEquals(MIME_TYPE, body.decodeToString())
                    "dossier.pdf" -> assertTrue(body.contentEquals(PDF_BODY))
                    "META-INF/signatures0.xml" -> assertTrue(body.contentEquals(XML_BODY))
                }
                // STORED means the standard decoder reads it with no inflater.
                assertEquals(java.util.zip.ZipEntry.STORED, entry.method)
            }
        }
        assertEquals(listOf("mimetype", "dossier.pdf", "META-INF/signatures0.xml"), names)
    }

    @Test
    fun identicalInputsProduceByteIdenticalArchives() {
        assertTrue(build().contentEquals(build()))
    }

    private fun build(): ByteArray {
        val writer = AsicZipWriter()
        writer.add("mimetype", MIME_TYPE.encodeToByteArray())
        writer.add("annex one.txt", "hello".encodeToByteArray())
        return checkNotNull(writer.finish())
    }

    private companion object {
        const val MIME_TYPE = "application/vnd.etsi.asic-e+zip"
        val PDF_BODY = "%PDF-1.4 body".encodeToByteArray()
        val XML_BODY = "<x/>".encodeToByteArray()
    }
}
