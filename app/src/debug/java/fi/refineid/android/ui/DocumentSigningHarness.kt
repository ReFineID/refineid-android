package fi.refineid.android.ui

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.document.PdfSignatureClaim
import fi.refineid.android.document.PreparedQualifiedPdfSignature
import fi.refineid.android.document.QualifiedPdfArchivalCompletion
import fi.refineid.android.document.QualifiedPdfArchivalFailure
import fi.refineid.android.document.QualifiedPdfArchivalResult
import fi.refineid.android.document.QualifiedPdfPreparationResult
import fi.refineid.android.document.QualifiedPdfSigningCoordinator
import fi.refineid.android.document.QualifiedPdfSigningFailure
import fi.refineid.android.document.SignedPdfDocument
import fi.refineid.android.settings.TimestampAuthorityRepository
import fi.refineid.android.settings.TimestampAuthorityStoreException
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot
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

/** Debug-only PAdES-B-LTA file-picker harness. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DocumentSigningHarness(
    snapshot: UsbReaderSnapshot,
    cardService: QualifiedCardService?,
    timestampAuthorityRepository: TimestampAuthorityRepository?,
) {
    if (
        cardService == null ||
        timestampAuthorityRepository == null ||
        snapshot.status != ReaderConnectionStatus.READY ||
        snapshot.cardPresence != CardPresence.PRESENT
    ) {
        return
    }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val session =
        remember(cardService, context.contentResolver, scope, timestampAuthorityRepository) {
            DocumentSigningHarnessSession(
                context = context.applicationContext,
                contentResolver = context.contentResolver,
                cardService = cardService,
                scope = scope,
                timestampAuthorityRepository = timestampAuthorityRepository,
            )
        }
    DisposableEffect(session) {
        onDispose(session::close)
    }
    val sourcePicker =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { source ->
            source?.let(session::select)
        }
    val destinationPicker =
        rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument(PDF_MEDIA_TYPE),
        ) { destination ->
            destination?.let(session::chooseDestination)
        }

    DocumentSigningCard(
        hasDocument = session.hasDocument,
        hasDestination = session.hasDestination,
        status = session.status,
        onChooseDocument = { sourcePicker.launch(arrayOf(PDF_MEDIA_TYPE)) },
        onChooseDestination = { destinationPicker.launch(SIGNED_PDF_FILENAME) },
        onSign = session::sign,
    )
}

private class DocumentSigningHarnessSession(
    private val context: Context,
    private val contentResolver: ContentResolver,
    cardService: QualifiedCardService,
    private val scope: CoroutineScope,
    private val timestampAuthorityRepository: TimestampAuthorityRepository,
) : AutoCloseable {
    private val coordinator = QualifiedPdfSigningCoordinator(cardService)
    private var selected by mutableStateOf<SelectedPdfDocument?>(null)
    private var destination by mutableStateOf<Uri?>(null)
    private var isClosed = false
    private var signingSetupJob: Job? = null
    private var pendingArchivalSources: DebugDocumentSigningSources? = null
    private var archivalJob: Job? = null

    var status by mutableStateOf(DocumentSigningStatus.IDLE)
        private set

    val hasDocument: Boolean
        get() = selected != null

    val hasDestination: Boolean
        get() = destination != null

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
                    destination = null
                    status = DocumentSigningStatus.IDLE
                    AppTrace.documentInputCompleted(
                        isAccepted = true,
                        documentLength = selected?.length,
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: IOException) {
                if (!isClosed) {
                    status = DocumentSigningStatus.ERROR
                    AppTrace.documentInputCompleted(isAccepted = false, documentLength = null)
                }
            } catch (_: SecurityException) {
                if (!isClosed) {
                    status = DocumentSigningStatus.ERROR
                    AppTrace.documentInputCompleted(isAccepted = false, documentLength = null)
                }
            } catch (_: RuntimeException) {
                if (!isClosed) {
                    status = DocumentSigningStatus.ERROR
                    AppTrace.documentInputCompleted(isAccepted = false, documentLength = null)
                }
            } finally {
                loaded?.close()
            }
        }
    }

    fun chooseDestination(chosen: Uri) {
        if (isClosed || isWorking()) {
            return
        }
        if (chosen == selected?.source) {
            destination = null
            status = DocumentSigningStatus.ERROR
            AppTrace.documentDestinationSelected(isAccepted = false)
            return
        }
        destination = chosen
        status = DocumentSigningStatus.IDLE
        AppTrace.documentDestinationSelected(isAccepted = true)
    }

    fun sign(pin2: Pin2Submission) {
        val input = selected
        val output = destination
        if (isClosed || isWorking() || input == null || output == null) {
            pin2.close()
            return
        }
        status = DocumentSigningStatus.SIGNING
        val running =
            scope.launch {
                var ownedPin2: Pin2Submission? = pin2
                try {
                    withContext(Dispatchers.IO) {
                        val sources =
                            DebugDocumentSigningSources.create(
                                context = context,
                                transferredConfigurations = timestampAuthorityRepository.load(),
                            )
                        var sourcesTransferred = false
                        try {
                            withContext(Dispatchers.Main.immediate) main@{
                                if (isClosed) {
                                    return@main
                                }
                                pendingArchivalSources = sources
                                try {
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
                                                if (pendingArchivalSources === sources) {
                                                    pendingArchivalSources = null
                                                }
                                                preparationCompleted(
                                                    result = result,
                                                    output = output,
                                                    archivalSources = sources,
                                                )
                                            },
                                        )
                                    }
                                } catch (failure: RuntimeException) {
                                    if (pendingArchivalSources === sources) {
                                        pendingArchivalSources = null
                                    }
                                    throw failure
                                }
                                ownedPin2 = null
                                sourcesTransferred = true
                            }
                        } finally {
                            if (!sourcesTransferred) {
                                sources.close()
                            }
                        }
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: TimestampAuthorityStoreException) {
                    if (!isClosed) {
                        status = DocumentSigningStatus.UNAVAILABLE
                    }
                } catch (_: RuntimeException) {
                    if (!isClosed) {
                        status = DocumentSigningStatus.ERROR
                    }
                } finally {
                    ownedPin2?.close()
                }
            }
        signingSetupJob = running
    }

    override fun close() {
        if (isClosed) {
            return
        }
        isClosed = true
        selected?.close()
        selected = null
        destination = null
        signingSetupJob?.cancel()
        pendingArchivalSources?.close()
        pendingArchivalSources = null
        archivalJob?.cancel()
    }

    private fun preparationCompleted(
        result: QualifiedPdfPreparationResult,
        output: Uri,
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
                completeArchival(result.prepared, output, archivalSources)
            }
        }
    }

    private fun completeArchival(
        prepared: PreparedQualifiedPdfSignature,
        output: Uri,
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
                    archivalCompleted(result, output)
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

    private suspend fun archivalCompleted(
        result: QualifiedPdfArchivalResult,
        output: Uri,
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
                status = DocumentSigningStatus.SAVING
                val documentLength = result.document.length
                val saved = save(result.document, output)
                AppTrace.documentOutputCompleted(
                    isSuccessful = saved,
                    documentLength = documentLength,
                )
                if (!isClosed) {
                    if (saved) {
                        selected?.close()
                        selected = null
                        destination = null
                        status = DocumentSigningStatus.SIGNED
                    } else {
                        status = DocumentSigningStatus.ERROR
                    }
                }
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

    private fun isWorking(): Boolean =
        status == DocumentSigningStatus.READING ||
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
            -> DocumentSigningStatus.UNAVAILABLE

            is QualifiedPdfArchivalFailure.Cms,
            is QualifiedPdfArchivalFailure.Document,
            is QualifiedPdfArchivalFailure.Validation,
            QualifiedPdfArchivalFailure.InternalError,
            -> DocumentSigningStatus.ERROR
        }

    private fun QualifiedPdfSigningFailure.status(): DocumentSigningStatus =
        when (this) {
            is QualifiedPdfSigningFailure.Card -> {
                when (kind) {
                    QualifiedSignFailure.WRONG_PIN -> DocumentSigningStatus.WRONG_PIN

                    QualifiedSignFailure.PIN_LOCKED -> DocumentSigningStatus.PIN_LOCKED

                    QualifiedSignFailure.CARD_UNAVAILABLE,
                    QualifiedSignFailure.TRANSPORT_ERROR,
                    QualifiedSignFailure.SAFETY_REFUSED,
                    -> DocumentSigningStatus.UNAVAILABLE

                    QualifiedSignFailure.INVALID_PIN,
                    QualifiedSignFailure.VERIFICATION_REJECTED,
                    QualifiedSignFailure.CERTIFICATE_REJECTED,
                    QualifiedSignFailure.INVALID_CERTIFICATE,
                    QualifiedSignFailure.CERTIFICATE_MISMATCH,
                    QualifiedSignFailure.KEY_PROFILE_MISMATCH,
                    QualifiedSignFailure.SIGNING_REJECTED,
                    QualifiedSignFailure.LOCAL_VERIFICATION_FAILED,
                    QualifiedSignFailure.BRIDGE_ERROR,
                    -> DocumentSigningStatus.ERROR
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

    private companion object {
        const val WRITE_MODE = "w"
    }
}

private const val PDF_MEDIA_TYPE = "application/pdf"
private const val SIGNED_PDF_FILENAME = "ReFineID-signed.pdf"
