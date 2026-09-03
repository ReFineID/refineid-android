package fi.refineid.android.rapp

import android.content.Context
import android.util.Base64
import androidx.core.content.edit
import org.json.JSONArray
import org.json.JSONObject

internal data class PairedPeer(
    val pairIdHex: String,
    val displayName: String,
    val platform: String,
    val createdAtMs: Long,
)

/** Persists authenticated RAPP paired devices locally on Android. */
internal class RappPairCatalog(
    context: Context,
) {
    private val prefs = context.getSharedPreferences("fi.refineid.rapp.pairs", Context.MODE_PRIVATE)

    companion object {
        private const val KEY_PAIRS = "paired_devices"
        private const val KEY_SELECTED = "selected_pair_id"
    }

    fun listPairs(): List<PairedPeer> {
        val raw = prefs.getString(KEY_PAIRS, null) ?: return emptyList()
        val result = mutableListOf<PairedPeer>()
        try {
            val arr = JSONArray(raw)
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                result.add(
                    PairedPeer(
                        pairIdHex = obj.getString("pairIdHex"),
                        displayName = obj.getString("displayName"),
                        platform = obj.getString("platform"),
                        createdAtMs = obj.getLong("createdAtMs"),
                    ),
                )
            }
        } catch (_: Exception) {
        }
        return result
    }

    fun savePair(
        pairId: ByteArray,
        displayName: String,
        platform: String,
        createdAtMs: Long,
    ) {
        val hex = pairId.joinToString("") { "%02x".format(it) }
        val current =
            listOf(
                PairedPeer(
                    pairIdHex = hex,
                    displayName = displayName,
                    platform = platform,
                    createdAtMs = createdAtMs,
                ),
            )
        val arr = JSONArray()
        for (p in current) {
            val obj = JSONObject()
            obj.put("pairIdHex", p.pairIdHex)
            obj.put("displayName", p.displayName)
            obj.put("platform", p.platform)
            obj.put("createdAtMs", p.createdAtMs)
            arr.put(obj)
        }
        prefs.edit { putString(KEY_PAIRS, arr.toString()) }
    }

    fun removePair(pairIdHex: String) {
        val current = listPairs().filter { it.pairIdHex != pairIdHex }
        val arr = JSONArray()
        for (p in current) {
            val obj = JSONObject()
            obj.put("pairIdHex", p.pairIdHex)
            obj.put("displayName", p.displayName)
            obj.put("platform", p.platform)
            obj.put("createdAtMs", p.createdAtMs)
            arr.put(obj)
        }
        prefs.edit { putString(KEY_PAIRS, arr.toString()) }
    }

    fun clearAll() {
        prefs.edit { remove(KEY_PAIRS) }
    }
}
