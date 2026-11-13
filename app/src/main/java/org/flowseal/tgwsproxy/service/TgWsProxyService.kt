package org.flowseal.tgwsproxy.service

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.wifi.WifiManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.flowseal.tgwsproxy.R
import org.flowseal.tgwsproxy.TgWsApplication
import org.flowseal.tgwsproxy.core.NativeProxyRunner
import org.flowseal.tgwsproxy.receiver.ProxyActionReceiver
import org.flowseal.tgwsproxy.ui.MainActivity
import org.flowseal.tgwsproxy.util.LogFormatter
import org.flowseal.tgwsproxy.util.SettingsManager

data class ProxyStats(
    val active: Int = 0,
    val total: Int = 0,
    val upMb: Double = 0.0,
    val downMb: Double = 0.0
)

class TgWsProxyService : Service() {

    private lateinit var runner: NativeProxyRunner
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    companion object {
        const val NOTIFICATION_ID = 1001

        const val ACTION_START = "org.flowseal.tgwsproxy.START"
        const val ACTION_STOP = "org.flowseal.tgwsproxy.STOP"

        const val EXTRA_PORT = "EXTRA_PORT"
        const val EXTRA_SECRET = "EXTRA_SECRET"
        const val EXTRA_DOMAIN = "EXTRA_DOMAIN"
        const val EXTRA_CF_WORKER = "EXTRA_CF_WORKER"

        private val _isRunning = MutableStateFlow(false)
        val isRunning = _isRunning.asStateFlow()

        private val _logFlow = MutableSharedFlow<String>(replay = 50)
        val logFlow = _logFlow.asSharedFlow()

        private val _statsFlow = MutableStateFlow(ProxyStats())
        val statsFlow = _statsFlow.asStateFlow()

        private val _secretMismatchFlow = MutableSharedFlow<Unit>(replay = 0, extraBufferCapacity = 1)
        val secretMismatchFlow = _secretMismatchFlow.asSharedFlow()

        private val statsRegex = Regex("""\[Stats\]\s*Active:\s*(\d+)\s*\|\s*Total:\s*(\d+).*?\|\s*Up:\s*([\d.]+)\s*MB\s*\|\s*Down:\s*([\d.]+)\s*MB""")

        var currentPort: Int = 1443
        var currentSecret: String = ""
        var currentDomain: String = ""
    }

    private var isStoppingExplicitly = false
    private var verifyFailCount = 0
    private var lastVerifyFailTime = 0L
    private var restartAttempts = 0
    private var lastRestartTime = 0L
    private var lastStatsLogTime = 0L
    private var lastLoggedUpMb = 0.0
    private var lastLoggedDownMb = 0.0
    private val serviceScope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Main + kotlinx.coroutines.SupervisorJob())
    private val timeFormat = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())

    override fun onCreate() {
        super.onCreate()
        runner = NativeProxyRunner(this)
        runner.setExitListener {
            if (_isRunning.value && !isStoppingExplicitly) {
                val now = System.currentTimeMillis()
                if (now - lastRestartTime > 60000) {
                    restartAttempts = 0
                }
                lastRestartTime = now
                restartAttempts++
                if (restartAttempts <= 5) {
                    LogFormatter.format("[Внимание] Ядро завершило работу (попытка $restartAttempts/5). Автоперезапуск...")?.let {
                        _logFlow.tryEmit(it)
                    }
                    serviceScope.launch {
                        kotlinx.coroutines.delay(1000)
                        if (_isRunning.value && !isStoppingExplicitly) {
                            val dynamicDomains = SettingsManager.getDynamicDomains(this@TgWsProxyService).joinToString(",")
                            val fallbackEnabled = SettingsManager.isCloudflareFallback(this@TgWsProxyService)
                            val effectiveDomains = if (fallbackEnabled) dynamicDomains else ""
                            runner.start(currentPort, currentSecret, currentDomain, cfDomains = effectiveDomains)
                        }
                    }
                    return@setExitListener
                } else {
                    LogFormatter.format("[Ошибка] Превышен лимит перезапусков ядра.")?.let {
                        _logFlow.tryEmit(it)
                    }
                }
            }
            stopProxy()
            stopSelf()
        }
        runner.setLogListener { line ->
            val match = statsRegex.find(line)
            if (match != null) {
                val active = match.groupValues[1].toIntOrNull() ?: 0
                val total = match.groupValues[2].toIntOrNull() ?: 0
                val upMb = match.groupValues[3].toDoubleOrNull() ?: 0.0
                val downMb = match.groupValues[4].toDoubleOrNull() ?: 0.0
                val newStats = ProxyStats(active, total, upMb, downMb)
                _statsFlow.value = newStats
                updateNotification(newStats)

                // High-value periodic traffic heartbeat every 60s if data moved
                val now = System.currentTimeMillis()
                if ((upMb > lastLoggedUpMb || downMb > lastLoggedDownMb) && now - lastStatsLogTime > 60000L) {
                    lastStatsLogTime = now
                    lastLoggedUpMb = upMb
                    lastLoggedDownMb = downMb
                    val timeStr = timeFormat.format(java.util.Date(now))
                    _logFlow.tryEmit("[$timeStr] [Статус] Трафик: ↑ %.2f MB, ↓ %.2f MB (активно соединений: %d)".format(upMb, downMb, active))
                }
                return@setLogListener // Suppress raw [Stats] noise
            }

            if (line.contains("Fake TLS verify failed")) {
                val now = System.currentTimeMillis()
                if (now - lastVerifyFailTime > 5000) {
                    verifyFailCount = 0
                }
                lastVerifyFailTime = now
                verifyFailCount++
                if (verifyFailCount == 2) {
                    _secretMismatchFlow.tryEmit(Unit)
                }
            }

            val formatted = LogFormatter.format(line)
            if (formatted != null) {
                _logFlow.tryEmit(formatted)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopProxy()
                stopSelf()
            }
            ACTION_START, null -> {
                if (runner.isActive()) return START_STICKY
                stopProxy()

                val port = intent?.getIntExtra(EXTRA_PORT, 1443) ?: SettingsManager.getPort(this)
                val secret = if (intent == null) SettingsManager.getSecret(this)
                    else intent.getStringExtra(EXTRA_SECRET) ?: ""
                val domain = if (intent == null) SettingsManager.getDomain(this)
                    else intent.getStringExtra(EXTRA_DOMAIN) ?: "google.com"
                val cfWorker = intent?.getStringExtra(EXTRA_CF_WORKER) ?: ""

                currentPort = port
                currentSecret = secret
                currentDomain = domain

                startProxy(port, secret, domain, cfWorker)
            }
        }
        return START_STICKY
    }

    private fun startProxy(port: Int, secret: String, domain: String, cfWorker: String) {
        try {
            LogFormatter.reset()
            isStoppingExplicitly = false
            acquireLocks()

            val notification = buildNotification(port)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                var type = ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                }
                startForeground(NOTIFICATION_ID, notification, type)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }

            val dynamicDomains = SettingsManager.getDynamicDomains(this).joinToString(",")
            val fallbackEnabled = SettingsManager.isCloudflareFallback(this)
            val effectiveDomains = if (fallbackEnabled) dynamicDomains else ""

            if (runner.start(port, secret, domain, cfWorker, cfDomains = effectiveDomains)) {
                _isRunning.value = true
                checkAndUpdateDomainsInBackground()
                return
            }
        } catch (e: Exception) {
            LogFormatter.format("Ошибка запуска: ${e.message}")?.let { _logFlow.tryEmit(it) }
        }
        stopProxy()
        stopSelf()
    }

    private fun checkAndUpdateDomainsInBackground() {
        val lastUpdate = SettingsManager.getLastDomainUpdate(this)
        val now = System.currentTimeMillis()
        if (now - lastUpdate > 24 * 60 * 60 * 1000L) {
            serviceScope.launch(kotlinx.coroutines.Dispatchers.IO) {
                val res = SettingsManager.fetchAndRefreshDomains(this@TgWsProxyService)
                res.onSuccess { count ->
                    LogFormatter.format("Зеркала Cloudflare обновлены: $count активных доменов")?.let { _logFlow.tryEmit(it) }
                }
            }
        }
    }

    private fun stopProxy() {
        isStoppingExplicitly = true
        runner.stop()
        releaseLocks()
        LogFormatter.reset()
        _isRunning.value = false
        _statsFlow.value = ProxyStats()
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private var lastNotifUpdateTime = 0L

    private fun updateNotification(stats: ProxyStats) {
        if (!_isRunning.value) return
        val now = System.currentTimeMillis()
        if (now - lastNotifUpdateTime < 1500L) {
            return
        }
        lastNotifUpdateTime = now
        try {
            val notification = buildNotification(currentPort, stats)
            val manager = NotificationManagerCompat.from(this)
            manager.notify(NOTIFICATION_ID, notification)
        } catch (e: SecurityException) {
            // Notifications may be disabled by the user on Android 13+
            android.util.Log.d("TgWsProxyService", "Notification permission not granted: ${e.message}")
        } catch (e: RuntimeException) {
            android.util.Log.w("TgWsProxyService", "Failed to update notification: ${e.message}")
        }
    }

    private fun buildNotification(port: Int, stats: ProxyStats? = null): Notification {
        val openAppIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openAppPendingIntent = PendingIntent.getActivity(
            this, 0, openAppIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, ProxyActionReceiver::class.java).apply {
            action = ProxyActionReceiver.ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getBroadcast(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Connect Intent
        val tgUri = Uri.parse("tg://proxy?server=127.0.0.1&port=$port&secret=$currentSecret")
        val connectIntent = Intent(Intent.ACTION_VIEW, tgUri).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        val connectPendingIntent = PendingIntent.getActivity(
            this, 2, connectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val currentStats = stats ?: _statsFlow.value
        val hasTraffic = currentStats.total > 0 || currentStats.upMb > 0 || currentStats.downMb > 0

        val contentText = if (hasTraffic) {
            String.format(
                java.util.Locale.getDefault(),
                "↑ %.2f MB   ↓ %.2f MB  •  %d %s",
                currentStats.upMb,
                currentStats.downMb,
                currentStats.active,
                if (currentStats.active == 1) "соед." else "соед."
            )
        } else {
            "Ожидание трафика • 127.0.0.1:$port"
        }

        val bigText = buildString {
            append("Шлюз: 127.0.0.1:$port")
            if (currentDomain.isNotBlank()) {
                append(" (маскировка: $currentDomain)")
            }
            append("\n")
            append(String.format(java.util.Locale.getDefault(), "Трафик: ↑ %.2f MB   ↓ %.2f MB\n", currentStats.upMb, currentStats.downMb))
            append("Соединения: ${currentStats.active} активных (всего: ${currentStats.total})")
        }

        return NotificationCompat.Builder(this, TgWsApplication.NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setColor(ContextCompat.getColor(this, R.color.primary))
            .setContentTitle("TG WS Proxy • Активен")
            .setContentText(contentText)
            .setSubText("127.0.0.1:$port")
            .setStyle(NotificationCompat.BigTextStyle().bigText(bigText))
            .setContentIntent(openAppPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .addAction(R.drawable.ic_telegram, getString(R.string.action_connect), connectPendingIntent)
            .addAction(R.drawable.ic_stop, getString(R.string.action_stop), stopPendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    @Suppress("DEPRECATION")
    private fun acquireLocks() {
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "TgWsProxy::ServiceWakeLock"
        )
        wakeLock?.apply {
            setReferenceCounted(false)
            acquire(12 * 60 * 60 * 1000L) // 12 hours max
        }

        val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        wifiLock = wifiManager.createWifiLock(
            WifiManager.WIFI_MODE_FULL_HIGH_PERF,
            "TgWsProxy::ServiceWifiLock"
        )
        wifiLock?.apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseLocks() {
        try {
            if (wakeLock?.isHeld == true) wakeLock?.release()
        } catch (e: RuntimeException) {
            android.util.Log.w("TgWsProxyService", "WakeLock release error: ${e.message}")
        }
        try {
            if (wifiLock?.isHeld == true) wifiLock?.release()
        } catch (e: RuntimeException) {
            android.util.Log.w("TgWsProxyService", "WifiLock release error: ${e.message}")
        }
    }

    override fun onDestroy() {
        stopProxy()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
