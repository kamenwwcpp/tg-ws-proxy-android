package org.flowseal.tgwsproxy

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

private const val releasePage = "https://github.com/kamenwwcpp/tg-ws-proxy-android/releases/tag/"
private val VERSION_NUMBER_REGEX = Regex("\\d+(?:\\.\\d+)*")
data class AppRelease(val version: String, val url: String)

suspend fun checkForUpdate(): AppRelease? = withContext(Dispatchers.IO) {
    val conn = URL("https://api.github.com/repos/kamenwwcpp/tg-ws-proxy-android/releases/latest")
        .openConnection() as HttpURLConnection
    try {
        conn.connectTimeout = 5000
        conn.readTimeout = 5000
        conn.setRequestProperty("Accept", "application/vnd.github+json")
        if (conn.responseCode != 200) return@withContext null
        val release = conn.inputStream.bufferedReader().use { JSONObject(it.readText()) }
        val tag = release.optString("tag_name")
        if (!Regex("v?\\d+(?:\\.\\d+){2}").matches(tag) ||
            release.optBoolean("draft") || release.optBoolean("prerelease") ||
            !isNewerVersion(BuildConfig.VERSION_NAME, tag)) return@withContext null
        AppRelease(tag, releasePage + tag)
    } catch (e: IOException) {
        Log.d("AppUpdate", "Release check failed", e)
        null
    } catch (e: org.json.JSONException) {
        Log.w("AppUpdate", "Invalid release response", e)
        null
    } finally {
        conn.disconnect()
    }
}
fun isNewerVersion(local: String, remote: String): Boolean {
    val localParts = versionParts(local)
    val remoteParts = versionParts(remote)
    if (remoteParts.isEmpty()) return false

    val maxLen = maxOf(localParts.size, remoteParts.size)

    for (i in 0 until maxLen) {
        val l = localParts.getOrElse(i) { 0 }
        val r = remoteParts.getOrElse(i) { 0 }
        if (r > l) return true
        if (r < l) return false
    }

    return false
}

private fun versionParts(version: String): List<Int> {
    val normalized = VERSION_NUMBER_REGEX.find(version.trim())?.value ?: return emptyList()
    return normalized.split(".").mapNotNull { it.toIntOrNull() }
}
