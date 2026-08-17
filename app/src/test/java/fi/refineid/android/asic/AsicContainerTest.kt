// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.asic

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

class AsicContainerTest {
    private fun obj(
        name: String,
        content: String = "hello",
        mimeType: String = "application/pdf",
    ) = AsicDataObject(name = name, content = content.encodeToByteArray(), mimeType = mimeType)

    @Test
    fun mimetypeIsTheFirstStoredEntryAndCarriesTheContainerMediaType() {
        val archive = AsicContainer.container(listOf(obj("a.pdf")), "<sig/>".encodeToByteArray())
        assertNotNull(archive)
        val entries = readEntries(archive!!)
        assertEquals("mimetype", entries.first().name)
        assertEquals(ZipEntry.STORED, entries.first().method)
        assertEquals(AsicContainer.MIME_TYPE, String(entries.first().content))
    }

    @Test
    fun entryOrderIsMimetypeThenFilesThenMetaInf() {
        val archive =
            AsicContainer.container(
                listOf(obj("first.pdf"), obj("second.txt", mimeType = "text/plain")),
                "<sig/>".encodeToByteArray(),
            )
        val names = readEntries(archive!!).map { it.name }
        assertEquals(
            listOf(
                "mimetype",
                "first.pdf",
                "second.txt",
                "META-INF/manifest.xml",
                "META-INF/signatures0.xml",
            ),
            names,
        )
    }

    @Test
    fun theSignatureBytesAreCarriedVerbatim() {
        val signature = "<asic:XAdESSignatures/>".encodeToByteArray()
        val archive = AsicContainer.container(listOf(obj("a.pdf")), signature)
        val stored = readEntries(archive!!).single { it.name == "META-INF/signatures0.xml" }
        assertEquals(String(signature), String(stored.content))
    }

    @Test
    fun manifestListsTheContainerRootAndEveryFileWithItsMediaType() {
        val manifest =
            String(AsicContainer.manifest(listOf(obj("räätäli.pdf", mimeType = "application/pdf"))))
        assertTrue(manifest.contains("manifest:full-path=\"/\""))
        assertTrue(manifest.contains("manifest:media-type=\"${AsicContainer.MIME_TYPE}\""))
        // The name is percent-encoded over UTF-8 in the reference URI form.
        assertTrue(manifest.contains("r%C3%A4%C3%A4t%C3%A4li.pdf"))
    }

    @Test
    fun reservedAndUnsafeNamesAreRefusedBeforeSigning() {
        assertFalse(AsicContainer.areNamesUsable(listOf(obj("mimetype"))))
        assertFalse(AsicContainer.areNamesUsable(listOf(obj("META-INF/anything.xml"))))
        assertFalse(AsicContainer.areNamesUsable(listOf(obj("/absolute.pdf"))))
        assertFalse(AsicContainer.areNamesUsable(listOf(obj("../escape.pdf"))))
        assertFalse(AsicContainer.areNamesUsable(listOf(obj("a\\b.pdf"))))
        assertFalse(AsicContainer.areNamesUsable(listOf(obj("nested//empty.pdf"))))
        assertFalse(AsicContainer.areNamesUsable(listOf(obj(""))))
        // A duplicate name would leave a reader to choose which entry wins.
        assertFalse(AsicContainer.areNamesUsable(listOf(obj("same.pdf"), obj("same.pdf"))))
    }

    @Test
    fun ordinaryNestedNamesAreAccepted() {
        assertTrue(AsicContainer.areNamesUsable(listOf(obj("dir/report.pdf"), obj("b.txt"))))
    }

    @Test
    fun anUnusableNameProducesNoContainer() {
        assertNull(AsicContainer.container(listOf(obj("../escape.pdf")), "<sig/>".encodeToByteArray()))
    }

    private class StoredEntry(
        val name: String,
        val method: Int,
        val content: ByteArray,
    )

    private fun readEntries(archive: ByteArray): List<StoredEntry> {
        val out = mutableListOf<StoredEntry>()
        ZipInputStream(archive.inputStream()).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                out += StoredEntry(entry.name, entry.method, zip.readBytes())
                entry = zip.nextEntry
            }
        }
        return out
    }
}
