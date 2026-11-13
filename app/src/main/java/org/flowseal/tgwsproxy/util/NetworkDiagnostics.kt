package org.flowseal.tgwsproxy.util

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

data class DcPingResult(
    val dcId: Int,
    val title: String,
    val subtitle: String,
    val host: String,
    val rttMs: Long?,
    val error: String? = null
)

object NetworkDiagnostics {

    suspend fun runDiagnostics(context: Context): List<DcPingResult> = withContext(Dispatchers.IO) {
        val dynamicDomains = SettingsManager.getDynamicDomains(context)
        val fallbackBase = dynamicDomains.firstOrNull() ?: "noskomnadzor.co.uk"

        val targets = listOf(
            Triple(2, "DC2 (Европа / РФ)", "Личные сообщения, группы, боты") to "kws2.$fallbackBase",
            Triple(4, "DC4 (Европа)", "Медиафайлы, каналы, истории") to "kws4.$fallbackBase",
            Triple(1, "DC1 (США)", "Альтернативные сессии и аккаунты") to "kws1.$fallbackBase",
            Triple(5, "DC5 (Сингапур / Азия)", "Азиатский регион Telegram") to "kws5.$fallbackBase",
            Triple(0, "Cloudflare Резерв", "Резервный шлюз обхода блокировок") to fallbackBase
        )

        val deferreds = targets.map { (meta, host) ->
            async {
                val rtt = measureTcpRtt(host, 443, 3000)
                DcPingResult(
                    dcId = meta.first,
                    title = meta.second,
                    subtitle = meta.third,
                    host = host,
                    rttMs = rtt,
                    error = if (rtt == null) "Таймаут или блокировка" else null
                )
            }
        }

        deferreds.awaitAll()
    }

    private fun measureTcpRtt(host: String, port: Int, timeoutMs: Int): Long? {
        return try {
            val start = System.currentTimeMillis()
            Socket().use { socket ->
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(host, port), timeoutMs)
            }
            System.currentTimeMillis() - start
        } catch (_: java.io.IOException) {
            null
        } catch (_: SecurityException) {
            null
        }
    }
}
