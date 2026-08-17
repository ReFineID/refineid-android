// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.asic

import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import java.time.Instant

/** Why a container could not be produced. */
internal sealed interface AsicSigningFailure {
    /** No files, or a name the container cannot carry. Refused before the card is touched. */
    data object UnusableNames : AsicSigningFailure

    /** The signing key is one no qualified algorithm covers. */
    data object KeyProfileUnsupported : AsicSigningFailure

    /** The finished entries overflowed the container's 32-bit fields. */
    data object ContainerOverflow : AsicSigningFailure

    /** The qualified certificate could not be read. */
    data class Certificate(
        val kind: NativeCertificateReadFailure,
    ) : AsicSigningFailure

    /** The card refused or failed the signature. */
    data class Card(
        val kind: QualifiedSignFailure,
    ) : AsicSigningFailure
}

/** The container bytes, or why they could not be produced. */
internal sealed interface AsicSigningResult {
    class Success(
        val container: ByteArray,
    ) : AsicSigningResult

    class Failure(
        val reason: AsicSigningFailure,
    ) : AsicSigningResult
}

/**
 * Signs a set of files into one ASiC-E container at level XAdES-B, ported from
 * the reference `AsicSigner`. One signature over the whole set: one PIN 2 use
 * covering every file, attesting them as a single act.
 *
 * The order is forced by what each step attests, as in the PDF coordinator: the
 * certificate is read, the XAdES `SignedInfo` is built inside the card session
 * where the certificate first exists, and the card signs it. The container is
 * assembled only once the signature document is complete, because a container
 * is one write with no revision to extend later.
 */
internal class AsicSigningCoordinator(
    private val cardService: QualifiedCardService,
    private val now: () -> Instant = Instant::now,
) {
    fun sign(
        objects: List<AsicDataObject>,
        pin2: Pin2Submission,
        onResult: (AsicSigningResult) -> Unit,
    ) {
        // Asked before the card is touched: a set that cannot be carried is
        // refused while a refusal is still free, sparing a PIN attempt.
        if (objects.isEmpty() || !AsicContainer.areNamesUsable(objects)) {
            pin2.close()
            onResult(AsicSigningResult.Failure(AsicSigningFailure.UnusableNames))
            return
        }
        cardService.requestQualifiedCertificate { certificateResult ->
            certificateReceived(certificateResult, objects, pin2, onResult)
        }
    }

    private fun certificateReceived(
        result: NativeCertificateReadResult<NativeQualifiedCertificate>,
        objects: List<AsicDataObject>,
        pin2: Pin2Submission,
        onResult: (AsicSigningResult) -> Unit,
    ) {
        when (result) {
            is NativeCertificateReadResult.Failure -> {
                pin2.close()
                onResult(AsicSigningResult.Failure(AsicSigningFailure.Certificate(result.kind)))
            }

            is NativeCertificateReadResult.Success -> {
                signWithCertificate(result.certificate, objects, pin2, onResult)
            }
        }
    }

    private fun signWithCertificate(
        certificate: NativeQualifiedCertificate,
        objects: List<AsicDataObject>,
        pin2: Pin2Submission,
        onResult: (AsicSigningResult) -> Unit,
    ) {
        val algorithm =
            QualifiedSigningAlgorithm.entries.firstOrNull { it.keyProfile == certificate.keyProfile }
        if (algorithm == null) {
            certificate.close()
            pin2.close()
            onResult(AsicSigningResult.Failure(AsicSigningFailure.KeyProfileUnsupported))
            return
        }
        val plan =
            XadesSignature.plan(
                profile = certificate.keyProfile,
                objects = objects,
                certificateDer = certificate.copyDer(),
                signedAt = now(),
            )
        cardService.requestQualifiedSignature(
            algorithm = algorithm,
            pin2 = pin2,
            content = plan.signedInfo.encodeToByteArray(),
            expectedCertificate = certificate,
        ) { signatureResult ->
            signatureReceived(signatureResult, plan, objects, certificate, onResult)
        }
    }

    private fun signatureReceived(
        result: QualifiedSignResult,
        plan: XadesPlan,
        objects: List<AsicDataObject>,
        certificate: NativeQualifiedCertificate,
        onResult: (AsicSigningResult) -> Unit,
    ) {
        certificate.close()
        when (result) {
            is QualifiedSignResult.Failure -> {
                onResult(AsicSigningResult.Failure(AsicSigningFailure.Card(result.kind)))
            }

            is QualifiedSignResult.Success -> {
                // The card's raw signature is already the XAdES SignatureValue
                // form: r||s for ECDSA, the PKCS#1 block for RSA.
                val document = result.signature.useBytes { plan.document(it) }
                result.signature.close()
                val archive = AsicContainer.container(objects, document.encodeToByteArray())
                onResult(
                    if (archive == null) {
                        AsicSigningResult.Failure(AsicSigningFailure.ContainerOverflow)
                    } else {
                        AsicSigningResult.Success(archive)
                    },
                )
            }
        }
    }
}
