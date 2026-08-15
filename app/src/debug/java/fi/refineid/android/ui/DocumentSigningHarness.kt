package fi.refineid.android.ui

import android.content.ContentResolver
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
import fi.refineid.android.document.QualifiedPdfSigningCoordinator
import fi.refineid.android.document.QualifiedPdfSigningFailure
import fi.refineid.android.document.QualifiedPdfSigningResult
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.time.Instant

/** Debug-only PAdES-B-B file-picker harness; archival completion is not implied. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DocumentSigningHarness(
    snapshot: UsbReaderSnapshot,
    cardService: QualifiedCardService?,
) {
    if (
        cardService == null ||
        snapshot.status != ReaderConnectionStatus.READY ||
        snapshot.cardPresence != CardPresence.PRESENT
    ) {
        return
    }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val session =
        remember(cardService, context.contentResolver, scope) {
            DocumentSigningHarnessSession(
                contentResolver = context.contentResolver,
                cardService = cardService,
                scope = scope,
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
    private val contentResolver: ContentResolver,
    cardService: QualifiedCardService,
    private val scope: CoroutineScope,
) : AutoCloseable {
    private val coordinator = QualifiedPdfSigningCoordinator(cardService)
    private var selected by mutableStateOf<SelectedPdfDocument?>(null)
    private var destination by mutableStateOf<Uri?>(null)
    private var isClosed = false

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
        try {
            input.useBytes { bytes ->
                coordinator.sign(
                    document = bytes,
                    claim =
                        PdfSignatureClaim(
                            signedAt = Instant.now(),
                            reason = null,
                            location = null,
                        ),
                    pin2 = pin2,
                    onResult = { result -> signingCompleted(result, output) },
                )
            }
        } catch (_: RuntimeException) {
            pin2.close()
            status = DocumentSigningStatus.ERROR
        }
    }

    override fun close() {
        if (isClosed) {
            return
        }
        isClosed = true
        selected?.close()
        selected = null
        destination = null
    }

    private fun signingCompleted(
        result: QualifiedPdfSigningResult,
        output: Uri,
    ) {
        if (isClosed) {
            result.closeDocument()
            return
        }
        scope.launch(start = CoroutineStart.UNDISPATCHED) {
            when (result) {
                is QualifiedPdfSigningResult.Failure -> {
                    status = result.kind.status()
                }

                is QualifiedPdfSigningResult.Success -> {
                    status = DocumentSigningStatus.SAVING
                    val documentLength = result.document.length
                    val saved = save(result, output)
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
    }

    private suspend fun save(
        result: QualifiedPdfSigningResult.Success,
        output: Uri,
    ): Boolean =
        try {
            withContext(Dispatchers.IO) {
                contentResolver.openOutputStream(output, WRITE_MODE)?.use { stream ->
                    result.document.useBytes(stream::write)
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
            result.document.close()
        }

    private fun isWorking(): Boolean =
        status == DocumentSigningStatus.READING ||
            status == DocumentSigningStatus.SIGNING ||
            status == DocumentSigningStatus.SAVING

    private fun QualifiedPdfSigningResult.closeDocument() {
        if (this is QualifiedPdfSigningResult.Success) {
            document.close()
        }
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
