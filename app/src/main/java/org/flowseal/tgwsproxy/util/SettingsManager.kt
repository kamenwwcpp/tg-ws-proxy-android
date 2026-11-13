package org.flowseal.tgwsproxy.util

import android.content.Context
import android.content.SharedPreferences
import java.security.SecureRandom
import androidx.datastore.preferences.preferencesDataStore
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.booleanPreferencesKey
import kotlinx.coroutines.flow.first

private val Context.legacySettings by preferencesDataStore(name = "proxy_settings")

object SettingsManager {

    private const val PREFS_NAME = "tg_ws_proxy_prefs"

    private const val KEY_PORT = "pref_port"
    private const val KEY_DOMAIN = "pref_domain"
    private const val KEY_SECRET = "pref_secret"
    private const val KEY_CF_FALLBACK = "pref_cf_fallback"
    private const val KEY_AUTO_START = "pref_auto_start"
    private const val KEY_DYNAMIC_DOMAINS = "pref_dynamic_domains"
    private const val KEY_LAST_DOMAIN_UPDATE = "pref_last_domain_update"

    const val DEFAULT_PORT = 1443
    const val DEFAULT_DOMAIN = "google.com"
    const val CANONICAL_KEY_HEX = "d41d8cd98f00b204e9800998ecf8427e"
    const val DEFAULT_SECRET = "eed41d8cd98f00b204e9800998ecf8427e676f6f676c652e636f6d"

    const val CFPROXY_DOMAINS_URL = "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"

    val DEFAULT_CF_DOMAINS = listOf(
        "noskomnadzor.co.uk",
        "cakeisalie.co.uk",
        "fixtelega.co.uk",
        "pclead.co.uk",
        "pomogite.co.uk",
        "havegreatday.co.uk",
        "notelega.co.uk",
        "ebally.co.uk",
        "nebally.co.uk",
        "sadnews.co.uk",
        "stopblocking.co.uk",
        "nothingthere.co.uk",
        "onedaychamp.co.uk",
        "kartoshka.co.uk",
        "sorokodin.co.uk",
        "sorokdva.co.uk",
        "pyatdesyatodin.co.uk",
        "pyatdesyatdva.co.uk",
        "lovetrue.co.uk",
        "offshor.co.uk"
    )

    val PRESET_DOMAINS = listOf(
        "google.com" to "Google",
        "icloud.com" to "Apple",
        "cloudflare.com" to "Cloudflare",
        "microsoft.com" to "Microsoft",
        "yandex.ru" to "Яндекс"
    )

    private val secureRandom = SecureRandom()

    private fun String.toHex(): String =
        trim().toByteArray(Charsets.US_ASCII).joinToString("") { "%02x".format(it) }

    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    suspend fun migrateLegacySettings(context: Context) {
        val prefs = getPrefs(context)
        if (prefs.getBoolean("migrated_legacy", false)) return
        val old = context.applicationContext.legacySettings.data.first()
        val edit = prefs.edit()
        if (!prefs.contains(KEY_PORT)) {
            old[stringPreferencesKey("port")]?.toIntOrNull()?.takeIf { it in 1..65535 }
                ?.let { edit.putInt(KEY_PORT, it) }
        }
        if (!prefs.contains(KEY_SECRET)) {
            old[stringPreferencesKey("secret_key")]?.takeIf { it.matches(Regex("[0-9a-fA-F]{32}")) }
                ?.let { edit.putString(KEY_SECRET, "dd" + it) }
        }
        if (!prefs.contains(KEY_CF_FALLBACK)) {
            old[booleanPreferencesKey("cfproxy_enabled")]?.let { edit.putBoolean(KEY_CF_FALLBACK, it) }
        }
        if (!prefs.contains(KEY_AUTO_START)) {
            old[booleanPreferencesKey("auto_start_on_boot")]?.let { edit.putBoolean(KEY_AUTO_START, it) }
        }
        edit.putBoolean("migrated_legacy", true).apply()
    }

    fun getPort(context: Context): Int {
        return getPrefs(context).getInt(KEY_PORT, DEFAULT_PORT)
    }

    fun setPort(context: Context, port: Int) {
        getPrefs(context).edit().putInt(KEY_PORT, port).apply()
    }

    fun getDomain(context: Context): String {
        return getPrefs(context).getString(KEY_DOMAIN, DEFAULT_DOMAIN) ?: DEFAULT_DOMAIN
    }

    fun setDomain(context: Context, domain: String) {
        getPrefs(context).edit().putString(KEY_DOMAIN, domain).apply()
    }

    fun getSecret(context: Context): String {
        val saved = getPrefs(context).getString(KEY_SECRET, null)
        if (!saved.isNullOrBlank() && saved != "ee8401a20ac9071e9c89793b2493d70875676f6f676c652e636f6d") {
            return saved
        }
        val domain = getDomain(context)
        val defaultSecret = generateRandomSecretForDomain(domain)
        setSecret(context, defaultSecret)
        return defaultSecret
    }

    fun setSecret(context: Context, secret: String) {
        getPrefs(context).edit().putString(KEY_SECRET, secret).apply()
    }

    fun isCloudflareFallback(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_CF_FALLBACK, true)
    }

    fun setCloudflareFallback(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_CF_FALLBACK, enabled).apply()
    }

    fun isAutoStartEnabled(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_AUTO_START, false)
    }

    fun setAutoStartEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_AUTO_START, enabled).apply()
    }

    fun getDynamicDomains(context: Context): List<String> {
        val raw = getPrefs(context).getString(KEY_DYNAMIC_DOMAINS, null)
        if (raw.isNullOrBlank()) {
            return DEFAULT_CF_DOMAINS
        }
        val list = raw.split(",").map { it.trim().lowercase() }.filter { it.isNotBlank() }
        return if (list.size >= 3) list else DEFAULT_CF_DOMAINS
    }

    fun setDynamicDomains(context: Context, domains: List<String>) {
        val joined = domains.joinToString(",")
        getPrefs(context).edit()
            .putString(KEY_DYNAMIC_DOMAINS, joined)
            .putLong(KEY_LAST_DOMAIN_UPDATE, System.currentTimeMillis())
            .apply()
    }

    fun getLastDomainUpdate(context: Context): Long {
        return getPrefs(context).getLong(KEY_LAST_DOMAIN_UPDATE, 0L)
    }

    /**
     * Decodes Caesar-shifted CF proxy domain from Flowseal format:
     * e.g. "virkgj.com" -> "pclead.co.uk"
     */
    fun decodeCfDomain(s: String): String {
        val trimmed = s.trim().lowercase()
        if (!trimmed.endsWith(".com")) return trimmed
        val prefix = trimmed.substring(0, trimmed.length - 4)
        val n = prefix.count { it in 'a'..'z' }
        val decoded = buildString {
            for (c in prefix) {
                if (c in 'a'..'z') {
                    val shifted = (c.code - 'a'.code - n) % 26
                    val normalized = if (shifted < 0) shifted + 26 else shifted
                    append(('a'.code + normalized).toChar())
                } else {
                    append(c)
                }
            }
        }
        return "$decoded.co.uk"
    }

    /**
     * Downloads and updates latest Cloudflare gateway mirrors from GitHub.
     */
    suspend fun fetchAndRefreshDomains(context: Context): Result<Int> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        var conn: java.net.HttpURLConnection? = null
        try {
            val url = java.net.URL("$CFPROXY_DOMAINS_URL?cache_bust=${System.currentTimeMillis()}")
            conn = url.openConnection() as java.net.HttpURLConnection
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.requestMethod = "GET"
            conn.setRequestProperty("User-Agent", "TG-WS-Proxy-Android")

            if (conn.responseCode != 200) {
                return@withContext Result.failure(Exception("HTTP error ${conn.responseCode}"))
            }

            val text = conn.inputStream.bufferedReader().use { it.readText() }
            val rawLines = text.lines().map { it.trim() }.filter { it.isNotBlank() && !it.startsWith("#") }
            val decodedDomains = rawLines.map { decodeCfDomain(it) }.filter { isValidDomain(it) }.distinct()

            if (decodedDomains.size >= 3) {
                setDynamicDomains(context, decodedDomains)
                Result.success(decodedDomains.size)
            } else {
                Result.failure(Exception("Получено недостаточно валидных доменов (${decodedDomains.size})"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            conn?.disconnect()
        }
    }

    private fun isValidDomain(domain: String): Boolean {
        if (domain.length < 4 || domain.length > 253) return false
        val parts = domain.split(".")
        if (parts.size < 2) return false
        return parts.all { it.isNotBlank() && it.all { ch -> ch.isLetterOrDigit() || ch == '-' } }
    }

    fun resetToDefaults(context: Context) {
        setPort(context, DEFAULT_PORT)
        setDomain(context, DEFAULT_DOMAIN)
        setSecret(context, generateRandomSecretForDomain(DEFAULT_DOMAIN))
        setCloudflareFallback(context, true)
        setAutoStartEnabled(context, false)
        setDynamicDomains(context, DEFAULT_CF_DOMAINS)
    }

    /**
     * Generates a deterministic MTProto Fake TLS secret using canonical key:
     * Format: 'ee' + canonical key + domain in hex (ASCII).
     */
    fun getSecretForDomain(domain: String): String {
        return "ee$CANONICAL_KEY_HEX${domain.toHex()}"
    }

    /**
     * Generates a completely new random MTProto Fake TLS secret when requested:
     */
    fun generateRandomSecretForDomain(domain: String): String {
        val randomBytes = ByteArray(16)
        secureRandom.nextBytes(randomBytes)
        val randomHex = randomBytes.joinToString("") { "%02x".format(it) }
        return "ee$randomHex${domain.toHex()}"
    }

    /**
     * Alias for compatibility
     */
    fun generateSecretForDomain(domain: String): String {
        return generateRandomSecretForDomain(domain)
    }

    /**
     * Checks if secret format matches the current domain.
     */
    fun isDomainMatchingSecret(secret: String, domain: String): Boolean {
        return secret.lowercase().endsWith(domain.toHex().lowercase())
    }
}
