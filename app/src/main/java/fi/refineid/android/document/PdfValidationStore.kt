// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.io.ByteArrayOutputStream

private data class PdfValidationStoreContext(
    val document: ByteArray,
    val index: PdfDocumentIndex,
    val root: PdfDocumentIndex.Reference,
    val declaredSize: Int,
    val catalog: String,
    val previous: PdfValidationStorePrevious,
)

private data class PdfValidationStoreAddedMaterial(
    val certificates: List<PdfDocumentIndex.Reference>,
    val ocspResponses: List<PdfDocumentIndex.Reference>,
    val revocationLists: List<PdfDocumentIndex.Reference>,
)

private data class PdfValidationStoreMaterialCopies(
    val certificates: List<ByteArray>,
    val ocspResponses: List<ByteArray>,
    val revocationLists: List<ByteArray>,
)

/** Appends certificate and revocation evidence as one byte-preserving DSS revision. */
internal object PdfValidationStore {
    fun append(
        document: ByteArray,
        material: PdfValidationMaterial,
    ): ByteArray =
        material.useCopies { certificates, ocspResponses, revocationLists ->
            if (certificates.isEmpty() && ocspResponses.isEmpty() && revocationLists.isEmpty()) {
                return@useCopies document.copyOf()
            }
            val index = PdfDocumentIndex.parse(document)
            val root =
                PdfDocumentIndex.reference(PdfFormat.ROOT_KEY, index.trailer)
                    ?: throw unreadable()
            val declaredSize =
                PdfDocumentIndex.integer(PdfFormat.SIZE_KEY, index.trailer)
                    ?: throw unreadable()
            val catalog = index.body(root, document) ?: throw unreadable()
            val previous = PdfValidationStoreSyntax.previousStore(catalog, index, document)
            appendRevision(
                context =
                    PdfValidationStoreContext(
                        document = document,
                        index = index,
                        root = root,
                        declaredSize = declaredSize,
                        catalog = catalog,
                        previous = previous,
                    ),
                material =
                    PdfValidationStoreMaterialCopies(
                        certificates = certificates,
                        ocspResponses = ocspResponses,
                        revocationLists = revocationLists,
                    ),
            )
        }

    private fun appendRevision(
        context: PdfValidationStoreContext,
        material: PdfValidationStoreMaterialCopies,
    ): ByteArray {
        val output = PdfValidationStoreOutput(context.document)
        val offsets = mutableMapOf<PdfDocumentIndex.Reference, Int>()
        var nextNumber =
            maxOf(
                context.declaredSize,
                increment(context.index.highestObjectNumber),
                MINIMUM_NEW_OBJECT_NUMBER,
            )
        val added =
            appendMaterial(
                material = material,
                output = output,
                offsets = offsets,
                firstObjectNumber = nextNumber,
            )
        nextNumber = added.nextObjectNumber
        val store = PdfDocumentIndex.Reference(nextNumber, NEW_OBJECT_GENERATION)
        nextNumber = increment(nextNumber)
        offsets[store] = output.size
        output.writeLatin1(store.encodedObjectHeader())
        output.writeLatin1(storeDictionary(context.previous, added.material))
        output.writeLatin1(INDIRECT_OBJECT_SUFFIX)

        offsets[context.root] = output.size
        output.writeLatin1(context.root.encodedObjectHeader())
        output.writeLatin1(PdfValidationStoreSyntax.catalogReferencing(store, context.catalog))
        output.writeLatin1(INDIRECT_OBJECT_SUFFIX)

        val xrefOffset = output.size
        output.write(
            PdfIncrementalSigner.crossReferenceSection(
                offsets = offsets,
                size = maxOf(context.declaredSize, nextNumber),
                root = context.root,
                xrefOffset = xrefOffset,
                index = context.index,
            ),
        )
        return output.toByteArray()
    }

    private fun appendMaterial(
        material: PdfValidationStoreMaterialCopies,
        output: PdfValidationStoreOutput,
        offsets: MutableMap<PdfDocumentIndex.Reference, Int>,
        firstObjectNumber: Int,
    ): AddedMaterialResult {
        var nextNumber = firstObjectNumber
        val addedCertificates =
            appendBlobs(orderedUnique(material.certificates), output, offsets, nextNumber)
        nextNumber = addedCertificates.nextObjectNumber
        val addedOcsp =
            appendBlobs(orderedUnique(material.ocspResponses), output, offsets, nextNumber)
        nextNumber = addedOcsp.nextObjectNumber
        val addedCrls =
            appendBlobs(orderedUnique(material.revocationLists), output, offsets, nextNumber)
        return AddedMaterialResult(
            material =
                PdfValidationStoreAddedMaterial(
                    certificates = addedCertificates.references,
                    ocspResponses = addedOcsp.references,
                    revocationLists = addedCrls.references,
                ),
            nextObjectNumber = addedCrls.nextObjectNumber,
        )
    }

    private fun appendBlobs(
        blobs: List<ByteArray>,
        output: PdfValidationStoreOutput,
        offsets: MutableMap<PdfDocumentIndex.Reference, Int>,
        firstObjectNumber: Int,
    ): AddedBlobResult {
        val references = mutableListOf<PdfDocumentIndex.Reference>()
        var nextNumber = firstObjectNumber
        for (blob in blobs) {
            val reference = PdfDocumentIndex.Reference(nextNumber, NEW_OBJECT_GENERATION)
            nextNumber = increment(nextNumber)
            offsets[reference] = output.size
            output.writeLatin1(reference.encodedObjectHeader())
            output.writeLatin1("<< /Length ${blob.size} >>\nstream\n")
            output.write(blob)
            output.writeLatin1(STREAM_OBJECT_SUFFIX)
            references += reference
        }
        return AddedBlobResult(references = references, nextObjectNumber = nextNumber)
    }

    private fun storeDictionary(
        previous: PdfValidationStorePrevious,
        added: PdfValidationStoreAddedMaterial,
    ): String {
        val entries = mutableListOf(DSS_TYPE_ENTRY)
        addReferenceEntry(entries, CERTIFICATES_KEY, previous.certificates + added.certificates)
        addReferenceEntry(entries, OCSP_RESPONSES_KEY, previous.ocspResponses + added.ocspResponses)
        addReferenceEntry(entries, REVOCATION_LISTS_KEY, previous.revocationLists + added.revocationLists)
        previous.vri?.let { value -> entries += "$VRI_KEY $value" }
        entries += previous.otherEntries
        return entries.joinToString(prefix = "<< ", postfix = " >>", separator = " ")
    }

    private fun addReferenceEntry(
        entries: MutableList<String>,
        key: String,
        references: List<PdfDocumentIndex.Reference>,
    ) {
        val unique = references.distinct()
        if (unique.isNotEmpty()) {
            entries +=
                unique.joinToString(
                    prefix = "$key [",
                    postfix = "]",
                    separator = " ",
                    transform = PdfDocumentIndex.Reference::encodedIndirectReference,
                )
        }
    }

    private fun orderedUnique(values: List<ByteArray>): List<ByteArray> {
        val unique = mutableListOf<ByteArray>()
        for (value in values) {
            if (unique.none { existing -> existing.contentEquals(value) }) {
                unique += value
            }
        }
        return unique
    }

    private fun increment(value: Int): Int =
        try {
            Math.incrementExact(value)
        } catch (_: ArithmeticException) {
            throw unreadable()
        }

    private fun unreadable(): PdfSigningException = PdfSigningException(PdfSigningFailure.STRUCTURE_UNREADABLE)

    private data class AddedBlobResult(
        val references: List<PdfDocumentIndex.Reference>,
        val nextObjectNumber: Int,
    )

    private data class AddedMaterialResult(
        val material: PdfValidationStoreAddedMaterial,
        val nextObjectNumber: Int,
    )

    private const val MINIMUM_NEW_OBJECT_NUMBER = 1
    private const val NEW_OBJECT_GENERATION = 0
    private const val DSS_TYPE_ENTRY = "/Type /DSS"
    private const val CERTIFICATES_KEY = "/Certs"
    private const val OCSP_RESPONSES_KEY = "/OCSPs"
    private const val REVOCATION_LISTS_KEY = "/CRLs"
    private const val VRI_KEY = "/VRI"
    private const val INDIRECT_OBJECT_SUFFIX = "\nendobj\n"
    private const val STREAM_OBJECT_SUFFIX = "\nendstream\nendobj\n"
}

private class PdfValidationStoreOutput(
    document: ByteArray,
) {
    private val output = ByteArrayOutputStream(document.size)

    init {
        write(document)
        if (document.lastOrNull() != PdfFormat.LINE_FEED_BYTE) {
            output.write(PdfFormat.LINE_FEED_BYTE.toUByte().toInt())
        }
    }

    val size: Int
        get() = output.size()

    fun write(bytes: ByteArray) {
        output.write(bytes)
    }

    fun writeLatin1(text: String) {
        write(PdfValueLexemes.strictLatin1(text) ?: throw unreadable())
    }

    fun toByteArray(): ByteArray = output.toByteArray()

    private fun unreadable(): PdfSigningException = PdfSigningException(PdfSigningFailure.STRUCTURE_UNREADABLE)
}
