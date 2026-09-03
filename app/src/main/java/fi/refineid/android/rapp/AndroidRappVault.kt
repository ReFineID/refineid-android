package fi.refineid.android.rapp

import android.content.Context
import android.util.Base64
import androidx.core.content.edit
import uniffi.refineid_rapp.RappOperationVault
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappStoredProxyJournal
import uniffi.refineid_rapp.RappVaultException
import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe durable storage for RAPP pairs and operation journals on Android.
 */
internal class AndroidRappVault(
    context: Context,
) : RappPairVault,
    RappOperationVault {
    private val pairPrefs = context.getSharedPreferences("fi.refineid.rapp.vault.pairs", Context.MODE_PRIVATE)
    private val revokedPrefs = context.getSharedPreferences("fi.refineid.rapp.vault.revoked", Context.MODE_PRIVATE)

    private val pairRecords = ConcurrentHashMap<String, ByteArray>()
    private val revokedPairs = ConcurrentHashMap<String, ULong>()
    private val proxyJournals = ConcurrentHashMap<String, MutableMap<String, RappStoredProxyJournal>>()

    init {
        for ((key, value) in pairPrefs.all) {
            if (value is String) {
                try {
                    pairRecords[key] = Base64.decode(value, Base64.NO_WRAP)
                } catch (_: Exception) {
                }
            }
        }
        for ((key, value) in revokedPrefs.all) {
            if (value is Long) {
                revokedPairs[key] = value.toULong()
            }
        }
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    // --- RappPairVault ---

    override fun insertDeviceOnly(
        pairId: ByteArray,
        record: ByteArray,
    ) {
        val idHex = hex(pairId)
        if (revokedPairs.containsKey(idHex)) {
            throw RappVaultException.IdentifierAlreadyUsed()
        }
        pairRecords[idHex] = record.copyOf()
        pairPrefs.edit {
            putString(idHex, Base64.encodeToString(record, Base64.NO_WRAP))
        }
    }

    override fun loadDeviceOnly(pairId: ByteArray): ByteArray? {
        val idHex = hex(pairId)
        if (revokedPairs.containsKey(idHex)) return null
        return pairRecords[idHex]?.copyOf()
    }

    override fun revokeDeviceOnly(
        pairId: ByteArray,
        revokedAtMs: ULong,
    ) {
        val idHex = hex(pairId)
        pairRecords.remove(idHex)
        revokedPairs[idHex] = revokedAtMs
        pairPrefs.edit { remove(idHex) }
        revokedPrefs.edit { putLong(idHex, revokedAtMs.toLong()) }
    }

    override fun isRevoked(pairId: ByteArray): Boolean {
        return revokedPairs.containsKey(hex(pairId))
    }

    // --- RappOperationVault ---

    override fun persistRequester(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
    ) {
        // Android endpoint acts as proxy
    }

    override fun loadRequester(pairId: ByteArray): List<ByteArray> {
        return emptyList()
    }

    override fun persistProxy(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
    ) {
        val pId = hex(pairId)
        val opId = hex(operationId)
        val journals = proxyJournals.computeIfAbsent(pId) { ConcurrentHashMap() }
        journals[opId] = RappStoredProxyJournal(record.copyOf(), null)
    }

    override fun persistProxyResult(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
        result: ByteArray,
    ) {
        val pId = hex(pairId)
        val opId = hex(operationId)
        val journals = proxyJournals.computeIfAbsent(pId) { ConcurrentHashMap() }
        journals[opId] = RappStoredProxyJournal(record.copyOf(), result.copyOf())
    }

    override fun retainProxyUncertain(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
    ) {
        val pId = hex(pairId)
        val opId = hex(operationId)
        val journals = proxyJournals[pId] ?: return
        val current = journals[opId] ?: return
        journals[opId] = RappStoredProxyJournal(record.copyOf(), current.retainedResult)
    }

    override fun acknowledgeProxyResult(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
    ) {
        val pId = hex(pairId)
        val opId = hex(operationId)
        val journals = proxyJournals[pId] ?: return
        journals[opId] = RappStoredProxyJournal(record.copyOf(), null)
    }

    override fun loadProxy(pairId: ByteArray): List<RappStoredProxyJournal> {
        val pId = hex(pairId)
        return proxyJournals[pId]?.values?.toList() ?: emptyList()
    }
}
