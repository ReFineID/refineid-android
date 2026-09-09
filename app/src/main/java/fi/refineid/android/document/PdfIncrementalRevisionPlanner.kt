// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.util.Locale

internal data class PdfRevisionSource(
    val document: ByteArray,
    val index: PdfDocumentIndex,
    val root: PdfDocumentIndex.Reference,
)

internal data class PdfIncrementalRevisionPlan(
    val page: PdfDocumentIndex.Reference,
    val stampPlacementRect: String,
    val mutations: Map<PdfDocumentIndex.Reference, String>,
)

/** Resolves and reissues the page/form objects that must reference a new signature widget. */
internal object PdfIncrementalRevisionPlanner {
    fun plan(
        source: PdfRevisionSource,
        field: PdfDocumentIndex.Reference,
    ): PdfIncrementalRevisionPlan {
        val mutations = MutationAccumulator(source)
        val catalogBody = mutations.body(source.root)
        val catalog = PdfDictionarySyntax(catalogBody)
        val page = lastPage(source, catalog)
        val pageBodyBefore = mutations.body(page)
        val stampRect = computeStampPlacement(pageBodyBefore)
        appendToNamedReferenceArray(
            owner = page,
            entryName = ANNOTATIONS_NAME,
            field = field,
            mutations = mutations,
        )
        appendToForm(
            catalog = PdfDictionarySyntax(mutations.body(source.root)),
            field = field,
            source = source,
            mutations = mutations,
        )
        return PdfIncrementalRevisionPlan(
            page = page,
            stampPlacementRect = stampRect,
            mutations = mutations.entries(),
        )
    }

    private fun lastPage(
        source: PdfRevisionSource,
        catalog: PdfDictionarySyntax,
    ): PdfDocumentIndex.Reference {
        val pagesEntry = catalog.entry(PAGES_NAME) ?: throw unreadable()
        var current =
            PdfValueParser.reference(catalog.value(pagesEntry))
                ?: throw unreadable()
        val visited = mutableSetOf<PdfDocumentIndex.Reference>()
        repeat(PdfFormat.MAXIMUM_PAGE_TREE_DEPTH) {
            if (!visited.add(current)) {
                throw unreadable()
            }
            val body = source.index.body(current, source.document) ?: throw unreadable()
            val syntax = PdfDictionarySyntax(body)
            val type = syntax.entry(TYPE_NAME)?.let { entry -> PdfValueLexemes.name(syntax.value(entry)) }
            val kids = syntax.entry(KIDS_NAME)
            if (kids == null) {
                if (type != PAGE_TYPE_NAME) {
                    throw unreadable()
                }
                return current
            }
            if (type != PAGES_TYPE_NAME) {
                throw unreadable()
            }
            val references = references(syntax.value(kids), source) ?: throw unreadable()
            current = references.lastOrNull() ?: throw unreadable()
        }
        throw unreadable()
    }

    private fun computeStampPlacement(
        pageBody: String,
        reach: Double = PdfStampRenderer.STAMP_REACH,
    ): String {
        val (pageWidth, _) = mediaBox(pageBody)
        val already = stampsAlreadyOn(pageBody)
        val margin = 20.0
        val gap = 16.0
        val step = reach * 2 + gap
        val firstX = pageWidth - reach - margin
        val firstY = reach + margin
        val perRow = maxOf(1, ((firstX - reach) / step).toInt() + 1)
        val centreX = firstX - (already % perRow) * step
        val centreY = firstY + (already / perRow) * step
        val x1 = centreX - reach
        val y1 = centreY - reach
        val x2 = centreX + reach
        val y2 = centreY + reach
        return String.format(Locale.US, "[%.2f %.2f %.2f %.2f]", x1, y1, x2, y2)
    }

    private fun mediaBox(pageBody: String): Pair<Double, Double> {
        val syntax = PdfDictionarySyntax(pageBody)
        val entry = syntax.entry("/MediaBox") ?: return Pair(595.28, 841.89)
        val value = syntax.value(entry)
        val match =
            Regex("""\[\s*([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s*\]""").find(value)
                ?: return Pair(595.28, 841.89)
        val x1 = match.groupValues[1].toDoubleOrNull() ?: 0.0
        val y1 = match.groupValues[2].toDoubleOrNull() ?: 0.0
        val x2 = match.groupValues[3].toDoubleOrNull() ?: 595.28
        val y2 = match.groupValues[4].toDoubleOrNull() ?: 841.89
        return Pair(kotlin.math.abs(x2 - x1), kotlin.math.abs(y2 - y1))
    }

    private fun stampsAlreadyOn(pageBody: String): Int {
        val syntax = PdfDictionarySyntax(pageBody)
        val entry = syntax.entry("/Annots") ?: return 0
        val value = syntax.value(entry)
        return Regex("""\d+\s+\d+\s+R""").findAll(value).count()
    }

    private fun appendToNamedReferenceArray(
        owner: PdfDocumentIndex.Reference,
        entryName: String,
        field: PdfDocumentIndex.Reference,
        mutations: MutationAccumulator,
    ) {
        val body = mutations.body(owner)
        val syntax = PdfDictionarySyntax(body)
        val updated =
            appendToReferenceArray(
                syntax = syntax,
                entryName = entryName,
                field = field,
                mutations = mutations,
            )
        if (updated != body) {
            mutations.put(owner, updated)
        }
    }

    private fun appendToForm(
        catalog: PdfDictionarySyntax,
        field: PdfDocumentIndex.Reference,
        source: PdfRevisionSource,
        mutations: MutationAccumulator,
    ) {
        val formEntry = catalog.entry(ACRO_FORM_NAME)
        if (formEntry == null) {
            val form =
                PdfDictionarySyntax(EMPTY_DICTIONARY)
                    .replacing(FIELDS_NAME, referenceArray(listOf(field)))
                    .let(::PdfDictionarySyntax)
                    .withSignatureFlags()
            mutations.put(
                source.root,
                catalog.replacing(ACRO_FORM_NAME, form),
            )
            return
        }
        val formValue = catalog.value(formEntry)
        val formReference = PdfValueParser.reference(formValue)
        if (formReference != null) {
            val body = mutations.body(formReference)
            val updated =
                appendToReferenceArray(
                    syntax = PdfDictionarySyntax(body),
                    entryName = FIELDS_NAME,
                    field = field,
                    mutations = mutations,
                ).let(::PdfDictionarySyntax).withSignatureFlags()
            mutations.put(formReference, updated)
            return
        }
        val updatedInline =
            appendToReferenceArray(
                syntax = PdfDictionarySyntax(formValue),
                entryName = FIELDS_NAME,
                field = field,
                mutations = mutations,
            ).let(::PdfDictionarySyntax).withSignatureFlags()
        mutations.put(
            source.root,
            catalog.replacing(ACRO_FORM_NAME, updatedInline),
        )
    }

    private fun appendToReferenceArray(
        syntax: PdfDictionarySyntax,
        entryName: String,
        field: PdfDocumentIndex.Reference,
        mutations: MutationAccumulator,
    ): String {
        val entry =
            syntax.entry(entryName)
                ?: return syntax.replacing(entryName, referenceArray(listOf(field)))
        val value = syntax.value(entry)
        val indirect = PdfValueParser.reference(value)
        if (indirect != null) {
            val existing = mutations.body(indirect)
            val references = PdfValueParser.referenceArray(existing) ?: throw unreadable()
            mutations.put(indirect, referenceArray(appending(field, references)))
            return syntax.encoded()
        }
        val references = PdfValueParser.referenceArray(value) ?: throw unreadable()
        return syntax.replacing(entryName, referenceArray(appending(field, references)))
    }

    private fun PdfDictionarySyntax.withSignatureFlags(): String {
        val flags =
            entry(SIGNATURE_FLAGS_NAME)?.let { entry ->
                PdfValueParser.unsignedInteger(value(entry)) ?: throw unreadable()
            } ?: NO_SIGNATURE_FLAGS
        return replacing(
            name = SIGNATURE_FLAGS_NAME,
            value = (flags or REQUIRED_SIGNATURE_FLAGS).toString(),
        )
    }

    private fun references(
        value: String,
        source: PdfRevisionSource,
    ): List<PdfDocumentIndex.Reference>? {
        PdfValueParser.referenceArray(value)?.let { return it }
        val indirect = PdfValueParser.reference(value) ?: return null
        val body = source.index.body(indirect, source.document) ?: return null
        return PdfValueParser.referenceArray(body)
    }

    private fun appending(
        field: PdfDocumentIndex.Reference,
        references: List<PdfDocumentIndex.Reference>,
    ): List<PdfDocumentIndex.Reference> =
        if (field in references) {
            references
        } else {
            references + field
        }

    private fun referenceArray(references: List<PdfDocumentIndex.Reference>): String =
        references.joinToString(
            prefix = "[",
            postfix = "]",
            separator = " ",
            transform = PdfDocumentIndex.Reference::encodedIndirectReference,
        )

    private class MutationAccumulator(
        private val source: PdfRevisionSource,
    ) {
        private val mutations = linkedMapOf<PdfDocumentIndex.Reference, String>()

        fun body(reference: PdfDocumentIndex.Reference): String =
            mutations[reference]
                ?: source.index.body(reference, source.document)
                ?: throw unreadable()

        fun put(
            reference: PdfDocumentIndex.Reference,
            body: String,
        ) {
            mutations[reference] = body
        }

        fun entries(): Map<PdfDocumentIndex.Reference, String> = mutations.toMap()
    }

    private fun unreadable(): PdfSigningException = PdfSigningException(PdfSigningFailure.STRUCTURE_UNREADABLE)

    private const val TYPE_NAME = "Type"
    private const val PAGE_TYPE_NAME = "Page"
    private const val PAGES_TYPE_NAME = "Pages"
    private const val PAGES_NAME = "Pages"
    private const val KIDS_NAME = "Kids"
    private const val ANNOTATIONS_NAME = "Annots"
    private const val ACRO_FORM_NAME = "AcroForm"
    private const val FIELDS_NAME = "Fields"
    private const val SIGNATURE_FLAGS_NAME = "SigFlags"
    private const val EMPTY_DICTIONARY = "<< >>"
    private const val NO_SIGNATURE_FLAGS = 0
    private const val SIGNATURES_EXIST_FLAG = 1
    private const val APPEND_ONLY_FLAG = 2
    private const val REQUIRED_SIGNATURE_FLAGS = SIGNATURES_EXIST_FLAG or APPEND_ONLY_FLAG
}
