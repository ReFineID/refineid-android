package fi.refineid.android.core

/**
 * Passive-authentication surface of the native core: the installed
 * CSCA trust anchors and the verdict of the last card read.
 *
 * The card is trusted to deliver its own Document Signer Certificate
 * inside EF.SOD, but never to vouch for itself; the anchors installed
 * here are the verifier-owned root that closes the DSC-to-CSCA hop.
 */
internal object NativeVerification {
    /** Passive authentication was not attempted for the last read. */
    const val CARD_VERIFICATION_NOT_PERFORMED = 0

    /** Passive authentication ran and the document verified. */
    const val CARD_VERIFICATION_PASSED = 1

    /**
     * Whether the last card read passed passive authentication: the
     * EF.SOD signature, the DG1 and DG2 hashes, and the chain from the
     * card-delivered Document Signer Certificate to an installed CSCA
     * trust anchor.
     */
    fun readCardVerificationPassed(): Boolean =
        if (!NativeCore.isLoaded) {
            false
        } else {
            try {
                readCardVerificationNative() == CARD_VERIFICATION_PASSED
            } catch (_: LinkageError) {
                false
            } catch (_: RuntimeException) {
                false
            }
        }

    /**
     * Replace the installed CSCA trust anchors with `anchors` (one DER
     * certificate each). Returns how many anchors were accepted.
     */
    fun installCscaAnchors(anchors: List<ByteArray>): Int =
        if (!NativeCore.isLoaded) {
            0
        } else {
            try {
                clearCscaAnchorsNative()
                var installed = 0
                for (anchor in anchors) {
                    installed += addCscaAnchorNative(anchor)
                }
                installed
            } catch (_: LinkageError) {
                0
            } catch (_: RuntimeException) {
                0
            }
        }

    @JvmStatic
    private external fun readCardVerificationNative(): Int

    @JvmStatic
    private external fun addCscaAnchorNative(anchorDer: ByteArray): Int

    @JvmStatic
    private external fun clearCscaAnchorsNative(): Int
}
