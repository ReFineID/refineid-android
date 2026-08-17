// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.asic

/**
 * ASiC-E containers: a ZIP holding documents and the XAdES signature over them
 * (ETSI EN 319 162-1), ported from the reference implementation.
 *
 * Where PAdES puts the signature inside the document, ASiC puts the documents
 * and the signature side by side in one archive. That is the right shape when
 * the document is not a PDF, or when a submission is a set of files one
 * signature should cover.
 *
 * The signature under `META-INF/signatures0.xml` carries one `ds:Reference` per
 * file, so it covers the files directly. The `META-INF/manifest.xml` inventory
 * records media types and is not signed; the signed copy of each media type is
 * in the signature's `DataObjectFormat`. EN 319 162-1 annex A.1 requires the
 * first archive entry to be `mimetype`, stored uncompressed; [AsicZipWriter]
 * stores every entry uncompressed, satisfying that by construction.
 */
internal object AsicContainer {
    /** Media type of an ASiC-E container. */
    const val MIME_TYPE = "application/vnd.etsi.asic-e+zip"

    /** Extension the container is saved under (`.bdoc` is the same format). */
    const val FILE_EXTENSION = "asice"

    private const val MIMETYPE_ENTRY = "mimetype"
    private const val MANIFEST_ENTRY = "META-INF/manifest.xml"
    private const val SIGNATURE_ENTRY = "META-INF/signatures0.xml"
    private const val MANIFEST_NAMESPACE = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
    private const val RESERVED_FOLDER = "META-INF"

    /**
     * Whether every file can be carried under the name it was given. `mimetype`
     * and `META-INF/` belong to the container, and a name used twice leaves a
     * reader to choose which entry wins. Absolute paths, parent-directory
     * components, backslashes and control characters have no one portable
     * archive meaning, so they are refused rather than mangled. Asked before the
     * card signs, so a set that cannot be carried costs no PIN attempt.
     */
    fun areNamesUsable(objects: List<AsicDataObject>): Boolean {
        val seen = mutableSetOf<String>()
        for (obj in objects) {
            if (!isNameUsable(obj.name) || !seen.add(obj.name)) {
                return false
            }
        }
        return true
    }

    private fun isNameUsable(name: String): Boolean {
        if (name.isEmpty() || isReservedName(name) || hasUnsafePathShape(name)) {
            return false
        }
        return name.split("/").all { it.isNotEmpty() && it != "." && it != ".." }
    }

    private fun isReservedName(name: String): Boolean {
        val folded = name.lowercase()
        return folded == MIMETYPE_ENTRY ||
            folded == RESERVED_FOLDER.lowercase() ||
            folded.startsWith(RESERVED_FOLDER.lowercase() + "/")
    }

    private fun hasUnsafePathShape(name: String): Boolean =
        name.startsWith("/") || name.contains('\\') || name.any { it.isISOControl() }

    /**
     * Writes the finished `.asice` archive. [signatureXml] is a complete
     * `META-INF/signatures0.xml`. Entry order is load-bearing: `mimetype` first,
     * then the data objects, then the inventory and the signature under
     * `META-INF/`. Null when a name cannot be carried, or when an entry cannot
     * be described by the 32-bit ZIP fields.
     */
    fun container(
        objects: List<AsicDataObject>,
        signatureXml: ByteArray,
    ): ByteArray? {
        if (!areNamesUsable(objects)) {
            return null
        }
        val archive = AsicZipWriter()
        archive.add(MIMETYPE_ENTRY, MIME_TYPE.encodeToByteArray())
        for (obj in objects) {
            archive.add(obj.name, obj.content)
        }
        archive.add(MANIFEST_ENTRY, manifest(objects))
        archive.add(SIGNATURE_ENTRY, signatureXml)
        return archive.finish()
    }

    /**
     * The OpenDocument inventory: one entry per file, plus the container itself.
     * Nothing signs this, so it is an aid to readers rather than evidence.
     */
    fun manifest(objects: List<AsicDataObject>): ByteArray {
        val out = StringBuilder()
        out.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        out.append("<manifest:manifest xmlns:manifest=\"").append(MANIFEST_NAMESPACE).append("\">\n")
        out.append("  <manifest:file-entry manifest:full-path=\"/\" manifest:media-type=\"")
        out.append(MIME_TYPE).append("\"/>\n")
        for (obj in objects) {
            val path = XadesSignature.escapeAttribute(XadesSignature.percentEncodePath(obj.name))
            val media = XadesSignature.escapeAttribute(obj.mimeType)
            out.append("  <manifest:file-entry manifest:full-path=\"").append(path)
            out.append("\" manifest:media-type=\"").append(media).append("\"/>\n")
        }
        out.append("</manifest:manifest>\n")
        return out.toString().encodeToByteArray()
    }
}
