package org.flowseal.tgwsproxy.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

object LogFormatter {

    private val goLogPrefixRegex = Regex("""^\d{4}/\d{2}/\d{2}\s+(\d{2}:\d{2}:\d{2})\s+(.*)$""")
    private val localSocketRegex = Regex("""\[127\.0\.0\.1:\d+\]\s*""")
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    private val readyOnRegex = Regex("""(?:Ready on|Запуск ядра:)\s*([^\s]+)""")
    private val sniRegex = Regex("""SNI:\s*([^\s)]+)""")
    private val digitsRegex = Regex("""(\d+)""")
    private val connectedDcRegex = Regex("""Connected DC(\d+)""")
    private val viaDomainRegex = Regex("""via\s+([^\s]+)""")
    private val cfWorkerRegex = Regex("""CF Worker\s+([^\s]+)\s+for DC(\d+)""")

    private var lastStartupTime = 0L
    private val lastChatLogTime = ConcurrentHashMap<String, Long>()
    private val lastMediaLogTime = ConcurrentHashMap<String, Long>()

    fun reset() {
        lastStartupTime = 0L
        lastChatLogTime.clear()
        lastMediaLogTime.clear()
    }

    fun format(rawLine: String): String? {
        val trimmed = rawLine.trim()
        if (trimmed.isEmpty()) return null

        // 1. Filter out raw stats spam (metrics are displayed on dashboard cards)
        if (trimmed.startsWith("[Stats]") || (trimmed.contains("Active:") && trimmed.contains("Total:"))) {
            return null
        }

        // 2. Filter out ASCII banners, decorative dividers, and low-value technical lines
        if (trimmed.startsWith("===") || trimmed.startsWith("TG WS Proxy (Go Mobile Core)")) {
            return null
        }

        // 3. Filter out connection closure noise (normal TCP lifecycle, aggregated into stats)
        if (trimmed.contains("Session closed:") || trimmed.contains(": сессия закрыта")) {
            return null
        }

        // 4. Filter out raw socket listening and telegram links (already provided by UI)
        if (trimmed.contains("Listening on") || trimmed.contains("Telegram link:")) {
            return null
        }

        // 5. Extract timestamp (always use local device time for consistency)
        val timeStr = timeFormat.format(Date())
        var content = trimmed

        val match = goLogPrefixRegex.find(trimmed)
        if (match != null) {
            content = match.groupValues[2].trim()
        }

        // Clean local ephemeral port prefixes like [127.0.0.1:54321]
        content = localSocketRegex.replace(content, "")

        // 6. Translate and enrich into high-value messages without spam or emojis
        val formatted = when {
            // Already formatted with tags
            content.startsWith("[Инфо]") || content.startsWith("[Внимание]") ||
            content.startsWith("[Ошибка]") || content.startsWith("[Статус]") ||
            content.startsWith("[Предупреждение]") -> {
                content
            }

            // Core startup & readiness (deduplicated: max once per 5 seconds)
            content.contains("Ready on") || content.startsWith("Запуск ядра:") -> {
                val now = System.currentTimeMillis()
                if (now - lastStartupTime < 5000L) {
                    return null
                }
                lastStartupTime = now
                val addrMatch = readyOnRegex.find(content)
                val sniMatch = sniRegex.find(content)
                val addr = addrMatch?.groupValues?.get(1) ?: "127.0.0.1:1443"
                val sni = sniMatch?.groupValues?.get(1) ?: "google.com"
                "[Инфо] Прокси запущен на $addr (маскировка: $sni)"
            }

            content.contains("CF gateway mirrors") || content.contains("Dynamic CF gateway domains") -> {
                val countMatch = digitsRegex.find(content)
                val count = countMatch?.groupValues?.get(1) ?: "20"
                "[Инфо] Загружено $count резервных зеркал Cloudflare"
            }

            // Successful Telegram chat connections (rate-limited to 1 per 30s per DC/domain)
            content.contains("Connected DC") && content.contains("(chat)") -> {
                val dcMatch = connectedDcRegex.find(content)
                val domainMatch = viaDomainRegex.find(content)
                val dc = dcMatch?.groupValues?.get(1) ?: "2"
                val domain = domainMatch?.groupValues?.get(1) ?: "шлюз"
                val key = "$dc:$domain"
                val now = System.currentTimeMillis()
                val last = lastChatLogTime[key] ?: 0L
                if (now - last < 30_000L) {
                    return null
                }
                lastChatLogTime[key] = now
                "[Инфо] DC$dc (сообщения) подключен к $domain"
            }

            // Successful Telegram media connections (rate-limited to 1 per 60s per DC/domain)
            content.contains("Connected DC") && content.contains("(media)") -> {
                val dcMatch = connectedDcRegex.find(content)
                val domainMatch = viaDomainRegex.find(content)
                val dc = dcMatch?.groupValues?.get(1) ?: "4"
                val domain = domainMatch?.groupValues?.get(1) ?: "шлюз"
                val key = "$dc:$domain"
                val now = System.currentTimeMillis()
                val last = lastMediaLogTime[key] ?: 0L
                if (now - last < 60_000L) {
                    return null
                }
                lastMediaLogTime[key] = now
                "[Инфо] DC$dc (медиа) подключен к $domain"
            }

            content.contains("Connected via CF Worker") -> {
                val workerMatch = cfWorkerRegex.find(content)
                val worker = workerMatch?.groupValues?.get(1) ?: ""
                val dc = workerMatch?.groupValues?.get(2) ?: ""
                val key = "$dc:$worker"
                val now = System.currentTimeMillis()
                val last = lastChatLogTime[key] ?: 0L
                if (now - last < 30_000L) {
                    return null
                }
                lastChatLogTime[key] = now
                "[Инфо] DC$dc подключен через Cloudflare Worker $worker"
            }

            // Warnings & Errors
            content.contains("Fake TLS verify failed") || content.contains("secret mismatch") -> {
                "[Внимание] Несовпадение ключа Fake TLS (клиент Telegram использует старый ключ)"
            }

            content.contains("Bad handshake") -> {
                "[Предупреждение] Ошибка MTProto рукопожатия от клиента"
            }

            content.contains("unreachable") || content.contains("No upstream gateways reachable") -> {
                val errReason = content.substringAfter("unreachable:", "").trim()
                if (errReason.isNotEmpty()) {
                    "[Ошибка] Серверы Telegram недоступны: $errReason"
                } else {
                    "[Ошибка] Серверы Telegram недоступны (проверьте интернет или обновите зеркала)"
                }
            }

            content.contains("Server shutdown cleanly") || content.startsWith("Остановка ядра") -> {
                "[Инфо] Служба остановлена"
            }

            content.contains("Ошибка запуска") -> {
                "[Ошибка] $content"
            }

            else -> {
                val cleaned = content.replace("[Proxy]", "").trim()
                if (cleaned.isEmpty()) return null
                "[Инфо] $cleaned"
            }
        }

        return "[$timeStr] $formatted"
    }
}
