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
        // The full path in manifest.xml matches the ZIP entry name verbatim (XML-escaped, not percent-encoded).
        assertTrue(manifest.contains("manifest:full-path=\"räätäli.pdf\""))
        assertTrue(manifest.contains("manifest:media-type=\"application/pdf\""))
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

    @Test
    fun asicValidatorDetectsZipHeaderAndRejectsUnsignedContainers() {
        val archive = AsicContainer.container(listOf(obj("a.pdf")), "<sig/>".encodeToByteArray())
        assertNotNull(archive)
        assertTrue(AsicValidator.isAsic(archive!!))
        assertFalse(AsicValidator.isAsic("not a zip".encodeToByteArray()))
        val result = AsicValidator.validate(archive, emptyList())
        assertEquals(fi.refineid.android.document.DocumentValidationResult.Unsigned, result)
    }

    @Test
    fun asicValidatorValidatesEcdsaSignedContainerWhenTrustAnchorsProvided() {
        val file = java.io.File("/Users/pk/src/refineid-android/tmp/container.asice")
        if (file.exists()) {
            val bytes = file.readBytes()
            val rawFiles =
                listOf(
                    "/Users/pk/src/refineid-android/app/src/main/res/raw/fineid_intermediate_00_citizen_g3.pem",
                    "/Users/pk/src/refineid-android/app/src/main/res/raw/fineid_intermediate_01_citizen_g4e.pem",
                    "/Users/pk/src/refineid-android/app/src/main/res/raw/fineid_intermediate_02_citizen_g4r.pem",
                    "/Users/pk/src/refineid-android/app/src/main/res/raw/fineid_intermediate_03_organisation_g4r.pem",
                )
            val cf =
                java.security.cert.CertificateFactory
                    .getInstance("X.509")
            val trustAnchors =
                rawFiles.mapNotNull { path ->
                    val f = java.io.File(path)
                    if (f.exists()) {
                        cf.generateCertificate(
                            f.inputStream(),
                        ) as java.security.cert.X509Certificate
                    } else {
                        null
                    }
                }
            val result = AsicValidator.validate(bytes, trustAnchors)
            assertTrue(result is fi.refineid.android.document.DocumentValidationResult.Completed)
            val completed = result as fi.refineid.android.document.DocumentValidationResult.Completed
            assertEquals(1, completed.signatures.size)
            val verdict = completed.signatures.first()
            assertTrue(verdict.signatureValid)
            assertTrue(verdict.digestMatches)
            assertTrue(verdict.coversWholeDocument)
            assertTrue(verdict.chainTrusted)
            assertTrue(verdict.isValid)
        }
    }

    @Test
    fun xadesPlanGeneratesUnsignedPropertiesWithTimestampsAndValidationMaterial() {
        val plan =
            XadesSignature.plan(
                profile = fi.refineid.android.core.NativeCardKeyProfile.ECDSA_P384,
                objects = listOf(obj("doc.pdf")),
                certificateDer = "cert".encodeToByteArray(),
                signedAt = java.time.Instant.parse("2026-08-29T12:00:00Z"),
            )
        val token = "sample-token".encodeToByteArray()
        val doc =
            plan.document(
                xmlSignature = ByteArray(96) { 1 },
                timestampTokens = listOf(token),
                material = null,
            )
        assertTrue(doc.contains("<xades:UnsignedProperties>"))
        assertTrue(doc.contains("<xades:UnsignedSignatureProperties>"))
        assertTrue(doc.contains("<xades:SignatureTimeStamp Id=\"SIG-1-TS-0\">"))
        assertTrue(doc.contains("<xades:EncapsulatedTimeStamp>"))
    }

    @Test
    fun preparedAsicSignatureClearsSensitiveMaterialOnClose() {
        val plan =
            XadesSignature.plan(
                profile = fi.refineid.android.core.NativeCardKeyProfile.ECDSA_P384,
                objects = listOf(obj("doc.pdf")),
                certificateDer = "cert".encodeToByteArray(),
                signedAt = java.time.Instant.parse("2026-08-29T12:00:00Z"),
            )
        val rawSig = ByteArray(96) { 0x42 }
        val certDer = ByteArray(100) { 0x24 }
        val prepared = PreparedAsicSignature(plan, listOf(obj("doc.pdf")), rawSig, certDer)
        prepared.close()
        assertTrue(rawSig.all { it == 0.toByte() })
        assertTrue(certDer.all { it == 0.toByte() })
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
