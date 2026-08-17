package fi.refineid.android.ui

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import fi.refineid.android.R
import fi.refineid.android.asic.AsicContainer
import fi.refineid.android.asic.AsicDataObject
import fi.refineid.android.asic.AsicSigningCoordinator
import fi.refineid.android.asic.AsicSigningFailure
import fi.refineid.android.asic.AsicSigningResult
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.document.PdfSignatureClaim
import fi.refineid.android.document.PreparedQualifiedPdfSignature
import fi.refineid.android.document.QualifiedPdfArchivalCompletion
import fi.refineid.android.document.QualifiedPdfArchivalFailure
import fi.refineid.android.document.QualifiedPdfArchivalResult
import fi.refineid.android.document.QualifiedPdfPreparationResult
import fi.refineid.android.document.QualifiedPdfSigningCoordinator
import fi.refineid.android.document.QualifiedPdfSigningFailure
import fi.refineid.android.document.SignedDocumentName
import fi.refineid.android.document.SignedPdfDocument
import fi.refineid.android.document.ValidationMaterialCollectionFailure
import fi.refineid.android.settings.TimestampAuthorityRepository
import fi.refineid.android.settings.TimestampAuthorityStoreException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import java.io.IOException
import java.time.Instant

/**
 * How a signing request reaches the card. A wired reader already holds
 * an open session, so signing runs at once; a contactless card is not
 * assumed present, so [begin] waits for the holder to tap and hands
 * control back once the transient session is open. The access number is
 * supplied only when no card has been primed.
 */
internal class DocumentSignTap(
    val begin: (canBytes: ByteArray?, onReady: () -> Unit, onNoCard: () -> Unit) -> Unit,
    val end: () -> Unit,
    val canRequired: Boolean,
)

/** Debug-only PAdES-B-LTA file-picker harness. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DocumentSigningHarness(
    signingAvailable: Boolean,
    cardService: QualifiedCardService?,
    tap: DocumentSignTap?,
    timestampAuthorityRepository: TimestampAuthorityRepository?,
) {
    if (
        !signingAvailable ||
        cardService == null ||
        timestampAuthorityRepository == null
    ) {
        return
    }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    // The tap's begin/end are stable controller references, so it is
    // deliberately not a session key: a fresh DocumentSignTap on each
    // recomposition must not discard a document already chosen. The tap
    // is captured through a holder the session reads at sign time.
    val tapHolder =
        remember {
            object {
                var value: DocumentSignTap? = null
            }
        }
    tapHolder.value = tap
    val session =
        remember(cardService, context.contentResolver, scope, timestampAuthorityRepository) {
            DocumentSigningHarnessSession(
                context = context.applicationContext,
                contentResolver = context.contentResolver,
                cardService = cardService,
                scope = scope,
                timestampAuthorityRepository = timestampAuthorityRepository,
                tap = { tapHolder.value },
            )
        }
    DisposableEffect(session) {
        onDispose(session::close)
    }
    val sourcePicker =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { source ->
            source?.let(session::select)
        }
    val filesPicker =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { sources ->
            if (sources.isNotEmpty()) {
                session.selectMany(sources)
            }
        }
    val pdfDestinationPicker =
        rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument(PDF_MEDIA_TYPE),
        ) { destination ->
            session.saveTo(destination)
        }
    val containerDestinationPicker =
        rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument(AsicContainer.MIME_TYPE),
        ) { destination ->
            session.saveTo(destination)
        }
    // Signing chooses the destination only once there is a signed file to
    // save, so the save panel opens with the suggested name after the tap.
    LaunchedEffect(session.saveRequest) {
        session.saveRequest?.let { request ->
            if (request.isContainer) {
                containerDestinationPicker.launch(request.suggestedName)
            } else {
                pdfDestinationPicker.launch(request.suggestedName)
            }
        }
    }

    DocumentSigningCard(
        hasDocument = session.hasDocument,
        canRequired = tap?.canRequired == true,
        status = session.status,
        format = session.format,
        onSelectFormat = session::selectFormat,
        onChooseDocument = {
            when (session.format) {
                SignatureFormat.PDF -> sourcePicker.launch(arrayOf(PDF_MEDIA_TYPE))
                SignatureFormat.CONTAINER -> filesPicker.launch(arrayOf(ANY_MEDIA_TYPE))
            }
        },
        onSign = session::sign,
    )
}

/** A signed file waiting for the holder to choose where it lands. */
internal data class DocumentSaveRequest(
    val suggestedName: String,
    val isContainer: Boolean = false,
)

private class DocumentSigningHarnessSession(
    private val context: Context,
    private val contentResolver: ContentResolver,
    cardService: QualifiedCardService,
    private val scope: CoroutineScope,
    private val timestampAuthorityRepository: TimestampAuthorityRepository,
    private val tap: () -> DocumentSignTap?,
) : AutoCloseable {
    private val coordinator = QualifiedPdfSigningCoordinator(cardService)
    private val asicCoordinator = AsicSigningCoordinator(cardService)
    private var selected by mutableStateOf<SelectedPdfDocument?>(null)
    private var selectedFiles by mutableStateOf<List<AsicDataObject>?>(null)
    private var isClosed = false
    private var signingSetupJob: Job? = null
    private var pendingArchivalSources: DebugDocumentSigningSources? = null
    private var archivalJob: Job? = null
    private var signedDocument: SignedPdfDocument? = null
    private var signedContainer: ByteArray? = null

    var status by mutableStateOf(DocumentSigningStatus.IDLE)
        private set

    var format by mutableStateOf(SignatureFormat.PDF)
        private set

    var saveRequest by mutableStateOf<DocumentSaveRequest?>(null)
        private set

    val hasDocument: Boolean
        get() = if (format == SignatureFormat.PDF) selected != null else selectedFiles != null

    fun select(source: Uri) {
        if (isClosed || isWorking()) {
            return
        }
        AppTrace.documentInputStarted()
        status = DocumentSigningStatus.READING
        scope.launch {
            var loaded: SelectedPdfDocument? = null
            try {
                loaded =
                    withContext(Dispatchers.IO) {
                        SelectedPdfDocument.read(contentResolver, source)
                    }
                if (!isClosed) {
                    selected?.close()
                    selected = loaded
                    loaded = null
                    discardSigned()
                    status = DocumentSigningStatus.IDLE
                    AppTrace.documentInputCompleted(
                        isAccepted = true,
                        documentLength = selected?.length,
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: IOException) {
                failInput()
            } catch (_: SecurityException) {
                failInput()
            } catch (_: RuntimeException) {
                failInput()
            } finally {
                loaded?.close()
            }
        }
    }

    /** Switch the target format; a PDF and a file set are not interchangeable. */
    fun selectFormat(next: SignatureFormat) {
        if (isClosed || isWorking() || next == format) {
            return
        }
        selected?.close()
        selected = null
        selectedFiles = null
        discardSigned()
        format = next
        if (status != DocumentSigningStatus.IDLE) {
            status = DocumentSigningStatus.IDLE
        }
    }

    /** Choose the set of files a single ASiC-E signature will cover. */
    fun selectMany(sources: List<Uri>) {
        if (isClosed || isWorking()) {
            return
        }
        AppTrace.documentInputStarted()
        status = DocumentSigningStatus.READING
        scope.launch {
            try {
                val objects =
                    withContext(Dispatchers.IO) {
                        sources.map { source ->
                            AsicDataObject(
                                name = displayName(source),
                                content = readBytes(source),
                                mimeType = contentResolver.getType(source) ?: ANY_MEDIA_TYPE,
                            )
                        }
                    }
                if (!isClosed) {
                    selected?.close()
                    selected = null
                    selectedFiles = objects
                    discardSigned()
                    status = DocumentSigningStatus.IDLE
                    AppTrace.documentInputCompleted(
                        isAccepted = true,
                        documentLength = objects.sumOf { it.content.size },
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: IOException) {
                failInput()
            } catch (_: SecurityException) {
                failInput()
            } catch (_: RuntimeException) {
                failInput()
            }
        }
    }

    private fun readBytes(source: Uri): ByteArray =
        contentResolver.openInputStream(source)?.use { it.readBytes() }
            ?: throw IOException("file cannot be opened")

    /**
     * Commit the chosen document. A wired session signs at once; a
     * contactless card first waits for the tap behind a hold prompt.
     */
    fun sign(
        pin2: Pin2Submission,
        can: CanSubmission?,
    ) {
        if (isClosed || isWorking() || !hasDocument) {
            pin2.close()
            can?.close()
            return
        }
        withOpenCard(pin2, can) { granted ->
            when (format) {
                SignatureFormat.PDF -> prepare(granted)
                SignatureFormat.CONTAINER -> prepareContainer(granted)
            }
        }
    }

    private fun withOpenCard(
        pin2: Pin2Submission,
        can: CanSubmission?,
        run: (Pin2Submission) -> Unit,
    ) {
        val activeTap = tap()
        if (activeTap == null) {
            can?.close()
            run(pin2)
            return
        }
        val canBytes = can?.transfer()
        status = DocumentSigningStatus.HOLD_CARD
        activeTap.begin(
            canBytes,
            {
                if (!isClosed) {
                    run(pin2)
                } else {
                    pin2.close()
                }
            },
            {
                pin2.close()
                if (!isClosed) {
                    status = DocumentSigningStatus.NO_CARD
                }
            },
        )
    }

    private fun prepareContainer(pin2: Pin2Submission) {
        val files = selectedFiles
        if (isClosed || files == null) {
            pin2.close()
            tap()?.end?.invoke()
            return
        }
        status = DocumentSigningStatus.SIGNING
        asicCoordinator.sign(files, pin2) { result ->
            tap()?.end?.invoke()
            containerSigningCompleted(result)
        }
    }

    private fun containerSigningCompleted(result: AsicSigningResult) {
        if (isClosed) {
            return
        }
        when (result) {
            is AsicSigningResult.Failure -> {
                status = result.reason.status()
            }

            is AsicSigningResult.Success -> {
                discardSigned()
                signedContainer = result.container
                saveRequest = DocumentSaveRequest(suggestedName = containerName(), isContainer = true)
            }
        }
    }

    private fun containerName(): String {
        val files = selectedFiles
        val original = if (files != null && files.size == 1) files[0].name else DEFAULT_CONTAINER_NAME
        val phrase =
            context.getString(
                R.string.signed_at,
                SignedDocumentName.instantStamp(Instant.now()),
            )
        return SignedDocumentName.suggested(
            originalName = original,
            signedAtPhrase = phrase,
            extensionOverride = AsicContainer.FILE_EXTENSION,
        )
    }

    private fun prepare(pin2: Pin2Submission) {
        val input = selected
        if (isClosed || input == null) {
            pin2.close()
            tap()?.end?.invoke()
            return
        }
        status = DocumentSigningStatus.SIGNING
        val suggestedName = suggestedName(input.source)
        val running =
            scope.launch {
                var ownedPin2: Pin2Submission? = pin2
                try {
                    val sources =
                        withContext(Dispatchers.IO) {
                            DebugDocumentSigningSources.create(
                                context = context,
                                transferredConfigurations = timestampAuthorityRepository.load(),
                            )
                        }
                    var sourcesTransferred = false
                    try {
                        pendingArchivalSources = sources
                        input.useBytes { bytes ->
                            coordinator.prepare(
                                document = bytes,
                                claim =
                                    PdfSignatureClaim(
                                        signedAt = Instant.now(),
                                        reason = null,
                                        location = null,
                                    ),
                                pin2 = checkNotNull(ownedPin2),
                                onResult = { result ->
                                    tap()?.end?.invoke()
                                    if (pendingArchivalSources === sources) {
                                        pendingArchivalSources = null
                                    }
                                    preparationCompleted(
                                        result = result,
                                        suggestedName = suggestedName,
                                        archivalSources = sources,
                                    )
                                },
                            )
                        }
                        ownedPin2 = null
                        sourcesTransferred = true
                    } finally {
                        if (!sourcesTransferred) {
                            pendingArchivalSources = null
                            sources.close()
                        }
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: TimestampAuthorityStoreException) {
                    tap()?.end?.invoke()
                    if (!isClosed) {
                        status = DocumentSigningStatus.UNAVAILABLE
                    }
                } catch (_: RuntimeException) {
                    tap()?.end?.invoke()
                    if (!isClosed) {
                        status = DocumentSigningStatus.ERROR
                    }
                } finally {
                    ownedPin2?.close()
                }
            }
        signingSetupJob = running
    }

    fun saveTo(destination: Uri?) {
        saveRequest = null
        val container = signedContainer
        val document = signedDocument
        if (destination == null || (container == null && document == null)) {
            discardSigned()
            if (!isClosed && status != DocumentSigningStatus.IDLE) {
                status = DocumentSigningStatus.IDLE
            }
            return
        }
        signedContainer = null
        signedDocument = null
        status = DocumentSigningStatus.SAVING
        scope.launch {
            val saved =
                if (container != null) {
                    val ok = saveBytes(container, destination)
                    AppTrace.documentOutputCompleted(isSuccessful = ok, documentLength = container.size)
                    ok
                } else {
                    checkNotNull(document)
                    val ok = save(document, destination)
                    AppTrace.documentOutputCompleted(isSuccessful = ok, documentLength = document.length)
                    ok
                }
            if (!isClosed) {
                if (saved) {
                    selected?.close()
                    selected = null
                    selectedFiles = null
                    status = DocumentSigningStatus.SIGNED
                } else {
                    status = DocumentSigningStatus.ERROR
                }
            }
        }
    }

    private suspend fun saveBytes(
        bytes: ByteArray,
        output: Uri,
    ): Boolean =
        try {
            withContext(Dispatchers.IO) {
                contentResolver.openOutputStream(output, WRITE_MODE)?.use { stream ->
                    stream.write(bytes)
                    stream.flush()
                } ?: throw IOException("container destination cannot be opened")
            }
            true
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }

    override fun close() {
        if (isClosed) {
            return
        }
        isClosed = true
        selected?.close()
        selected = null
        selectedFiles = null
        signingSetupJob?.cancel()
        pendingArchivalSources?.close()
        pendingArchivalSources = null
        archivalJob?.cancel()
        discardSigned()
    }

    private fun preparationCompleted(
        result: QualifiedPdfPreparationResult,
        suggestedName: String,
        archivalSources: DebugDocumentSigningSources,
    ) {
        if (isClosed) {
            result.closePreparedSignature()
            archivalSources.close()
            return
        }
        when (result) {
            is QualifiedPdfPreparationResult.Failure -> {
                archivalSources.close()
                status = result.kind.status()
            }

            is QualifiedPdfPreparationResult.Success -> {
                completeArchival(result.prepared, suggestedName, archivalSources)
            }
        }
    }

    private fun completeArchival(
        prepared: PreparedQualifiedPdfSignature,
        suggestedName: String,
        archivalSources: DebugDocumentSigningSources,
    ) {
        val running =
            scope.launch(start = CoroutineStart.UNDISPATCHED) {
                try {
                    val result =
                        runInterruptible(Dispatchers.IO) {
                            QualifiedPdfArchivalCompletion.complete(
                                prepared = prepared,
                                timestampSource = archivalSources.timestamp,
                                validationSource = archivalSources.validation,
                            )
                        }
                    archivalCompleted(result, suggestedName)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (interrupted: InterruptedException) {
                    throw CancellationException("archival signing was interrupted").also { cancellation ->
                        cancellation.initCause(interrupted)
                    }
                } catch (_: RuntimeException) {
                    if (!isClosed) {
                        status = DocumentSigningStatus.ERROR
                    }
                } finally {
                    archivalSources.close()
                }
            }
        archivalJob = running
        running.invokeOnCompletion { prepared.close() }
    }

    private fun archivalCompleted(
        result: QualifiedPdfArchivalResult,
        suggestedName: String,
    ) {
        if (isClosed) {
            result.closeDocument()
            return
        }
        when (result) {
            is QualifiedPdfArchivalResult.Failure -> {
                status = result.kind.status()
            }

            is QualifiedPdfArchivalResult.Success -> {
                // The card work is done; choose where the signed file lands.
                discardSigned()
                signedDocument = result.document
                saveRequest = DocumentSaveRequest(suggestedName = suggestedName)
            }
        }
    }

    private suspend fun save(
        document: SignedPdfDocument,
        output: Uri,
    ): Boolean =
        try {
            withContext(Dispatchers.IO) {
                contentResolver.openOutputStream(output, WRITE_MODE)?.use { stream ->
                    document.useBytes(stream::write)
                    stream.flush()
                } ?: throw IOException("signed PDF destination cannot be opened")
            }
            true
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        } finally {
            document.close()
        }

    private fun suggestedName(source: Uri): String {
        val original = displayName(source)
        val phrase =
            context.getString(
                R.string.signed_at,
                SignedDocumentName.instantStamp(Instant.now()),
            )
        return SignedDocumentName.suggested(originalName = original, signedAtPhrase = phrase)
    }

    private fun displayName(source: Uri): String {
        val projection = arrayOf(OpenableColumns.DISPLAY_NAME)
        val name =
            try {
                contentResolver.query(source, projection, null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (index >= 0) cursor.getString(index) else null
                    } else {
                        null
                    }
                }
            } catch (_: RuntimeException) {
                null
            }
        return name?.takeIf { it.isNotBlank() } ?: DEFAULT_DOCUMENT_NAME
    }

    private fun failInput() {
        if (!isClosed) {
            status = DocumentSigningStatus.ERROR
            AppTrace.documentInputCompleted(isAccepted = false, documentLength = null)
        }
    }

    private fun discardSigned() {
        saveRequest = null
        signedDocument?.close()
        signedDocument = null
        signedContainer = null
    }

    private fun isWorking(): Boolean =
        status == DocumentSigningStatus.READING ||
            status == DocumentSigningStatus.HOLD_CARD ||
            status == DocumentSigningStatus.SIGNING ||
            status == DocumentSigningStatus.SAVING

    private fun QualifiedPdfPreparationResult.closePreparedSignature() {
        if (this is QualifiedPdfPreparationResult.Success) {
            prepared.close()
        }
    }

    private fun QualifiedPdfArchivalResult.closeDocument() {
        if (this is QualifiedPdfArchivalResult.Success) {
            document.close()
        }
    }

    private fun QualifiedPdfArchivalFailure.status(): DocumentSigningStatus =
        when (this) {
            is QualifiedPdfArchivalFailure.Timestamp,
            QualifiedPdfArchivalFailure.ValidationUnavailable,
            -> {
                DocumentSigningStatus.UNAVAILABLE
            }

            // The card produced a valid signature; only the long-term
            // validation refused, because the certificate is revoked. That
            // is a certificate fact, not a signing fault, so it reads apart
            // from a generic error.
            is QualifiedPdfArchivalFailure.Validation -> {
                if (kind == ValidationMaterialCollectionFailure.REVOKED) {
                    DocumentSigningStatus.CERT_REVOKED
                } else {
                    DocumentSigningStatus.ERROR
                }
            }

            is QualifiedPdfArchivalFailure.Cms,
            is QualifiedPdfArchivalFailure.Document,
            QualifiedPdfArchivalFailure.InternalError,
            -> {
                DocumentSigningStatus.ERROR
            }
        }

    private fun QualifiedPdfSigningFailure.status(): DocumentSigningStatus =
        when (this) {
            is QualifiedPdfSigningFailure.Card -> {
                when (kind) {
                    fi.refineid.android.core.QualifiedSignFailure.WRONG_PIN -> {
                        DocumentSigningStatus.WRONG_PIN
                    }

                    fi.refineid.android.core.QualifiedSignFailure.PIN_LOCKED -> {
                        DocumentSigningStatus.PIN_LOCKED
                    }

                    fi.refineid.android.core.QualifiedSignFailure.CARD_UNAVAILABLE,
                    fi.refineid.android.core.QualifiedSignFailure.TRANSPORT_ERROR,
                    fi.refineid.android.core.QualifiedSignFailure.SAFETY_REFUSED,
                    -> {
                        DocumentSigningStatus.UNAVAILABLE
                    }

                    fi.refineid.android.core.QualifiedSignFailure.INVALID_PIN,
                    fi.refineid.android.core.QualifiedSignFailure.VERIFICATION_REJECTED,
                    fi.refineid.android.core.QualifiedSignFailure.CERTIFICATE_REJECTED,
                    fi.refineid.android.core.QualifiedSignFailure.INVALID_CERTIFICATE,
                    fi.refineid.android.core.QualifiedSignFailure.CERTIFICATE_MISMATCH,
                    fi.refineid.android.core.QualifiedSignFailure.KEY_PROFILE_MISMATCH,
                    fi.refineid.android.core.QualifiedSignFailure.SIGNING_REJECTED,
                    fi.refineid.android.core.QualifiedSignFailure.LOCAL_VERIFICATION_FAILED,
                    fi.refineid.android.core.QualifiedSignFailure.BRIDGE_ERROR,
                    -> {
                        DocumentSigningStatus.ERROR
                    }
                }
            }

            is QualifiedPdfSigningFailure.Certificate,
            QualifiedPdfSigningFailure.KeyProfileUnsupported,
            -> {
                DocumentSigningStatus.UNAVAILABLE
            }

            is QualifiedPdfSigningFailure.Cms,
            is QualifiedPdfSigningFailure.Document,
            QualifiedPdfSigningFailure.InternalError,
            -> {
                DocumentSigningStatus.ERROR
            }
        }

    private fun AsicSigningFailure.status(): DocumentSigningStatus =
        when (this) {
            AsicSigningFailure.KeyProfileUnsupported,
            is AsicSigningFailure.Certificate,
            -> DocumentSigningStatus.UNAVAILABLE

            AsicSigningFailure.UnusableNames,
            AsicSigningFailure.ContainerOverflow,
            -> DocumentSigningStatus.ERROR

            is AsicSigningFailure.Card -> kind.status()
        }

    private fun fi.refineid.android.core.QualifiedSignFailure.status(): DocumentSigningStatus =
        when (this) {
            fi.refineid.android.core.QualifiedSignFailure.WRONG_PIN -> DocumentSigningStatus.WRONG_PIN

            fi.refineid.android.core.QualifiedSignFailure.PIN_LOCKED -> DocumentSigningStatus.PIN_LOCKED

            fi.refineid.android.core.QualifiedSignFailure.CARD_UNAVAILABLE,
            fi.refineid.android.core.QualifiedSignFailure.TRANSPORT_ERROR,
            fi.refineid.android.core.QualifiedSignFailure.SAFETY_REFUSED,
            -> DocumentSigningStatus.UNAVAILABLE

            fi.refineid.android.core.QualifiedSignFailure.INVALID_PIN,
            fi.refineid.android.core.QualifiedSignFailure.VERIFICATION_REJECTED,
            fi.refineid.android.core.QualifiedSignFailure.CERTIFICATE_REJECTED,
            fi.refineid.android.core.QualifiedSignFailure.INVALID_CERTIFICATE,
            fi.refineid.android.core.QualifiedSignFailure.CERTIFICATE_MISMATCH,
            fi.refineid.android.core.QualifiedSignFailure.KEY_PROFILE_MISMATCH,
            fi.refineid.android.core.QualifiedSignFailure.SIGNING_REJECTED,
            fi.refineid.android.core.QualifiedSignFailure.LOCAL_VERIFICATION_FAILED,
            fi.refineid.android.core.QualifiedSignFailure.BRIDGE_ERROR,
            -> DocumentSigningStatus.ERROR
        }

    private companion object {
        const val WRITE_MODE = "w"
        const val DEFAULT_DOCUMENT_NAME = "document.pdf"
        const val DEFAULT_CONTAINER_NAME = "container"
    }
}

private const val PDF_MEDIA_TYPE = "application/pdf"
private const val ANY_MEDIA_TYPE = "*/*"
