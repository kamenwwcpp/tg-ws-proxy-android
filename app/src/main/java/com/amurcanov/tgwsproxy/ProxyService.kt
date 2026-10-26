package com.amurcanov.tgwsproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.time.Duration.Companion.milliseconds
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.Executors

class ProxyService : Service() {

    private class PortBusyException : Exception()

    private data class ProxyConfig(
        val bindIp: String,
        val port: Int,
        val ips: String,
        val poolSize: Int,
        val cfEnabled: Boolean,
        val cfPriority: Boolean,
        val cfDomain: String,
        val secretKey: String,
    )

    private var statsJob: Job? = null
    private var screenReceiver: BroadcastReceiver? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var restartJob: Job? = null
    private var lastNotificationContent: String = ""
    private var lastNotificationAtMs: Long = 0L
    private var notificationStartedAtMs: Long = 0L

    // Всё состояние ниже трогается только с main-потока.
    private var startInProgress = false
    private var stopInProgress = false
    private var pendingStart: ProxyConfig? = null
    private var lastConfig: ProxyConfig? = null

    private val serviceScope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    companion object {
        const val ACTION_START = "com.amurcanov.tgwsproxy.START"
        const val ACTION_STOP = "com.amurcanov.tgwsproxy.STOP"
        const val ACTION_RESTART = "com.amurcanov.tgwsproxy.RESTART"
        const val EXTRA_BIND_IP = "EXTRA_BIND_IP"
        const val EXTRA_PORT = "EXTRA_PORT"
        const val EXTRA_IPS = "EXTRA_IPS"
        const val EXTRA_POOL_SIZE = "EXTRA_POOL_SIZE"
        const val EXTRA_CFPROXY_ENABLED = "EXTRA_CFPROXY_ENABLED"
        const val EXTRA_CFPROXY_PRIORITY = "EXTRA_CFPROXY_PRIORITY"
        const val EXTRA_CFPROXY_DOMAIN = "EXTRA_CFPROXY_DOMAIN"
        const val EXTRA_SECRET_KEY = "EXTRA_SECRET_KEY"

        private const val NOTIFICATION_ID = 101
        private const val CHANNEL_ID = "TG_WS_Proxy_Service_v4"
        private const val TAG = "ProxyService"

        // Stats/notification update interval (only while the screen is on)
        private const val STATS_UPDATE_MS = 5_000L
        private const val NOTIFICATION_MIN_UPDATE_MS = 5_000L
        private const val NATIVE_STOP_WAIT_MS = 3_000L

        // Нативное состояние процессное и не потокобезопасно между Start/Stop:
        // параллельные вызовы давали -1 на втором StartProxy (и авто-стоп рабочего
        // прокси) или StopProxy раньше StartProxy (осиротевший прокси на порту).
        private val nativeDispatcher = Executors.newSingleThreadExecutor { r ->
            Thread(r, "ProxyNative").apply { isDaemon = true }
        }.asCoroutineDispatcher()
        private val nativeScope = CoroutineScope(SupervisorJob() + nativeDispatcher)

        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning
        private val _isVerifiedRunning = MutableStateFlow(false)
        val isVerifiedRunning: StateFlow<Boolean> = _isVerifiedRunning

        // Монотонный счётчик смен состояния: UI сбрасывает «Подключение…», даже если
        // старт провалился и isRunning так и не менялся.
        private val _stateEpoch = MutableStateFlow(0)
        val stateEpoch: StateFlow<Int> = _stateEpoch
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                // Контракт startForegroundService: startForeground обязан прозвучать
                // на каждый вызов, даже если старт отложен/не нужен.
                if (!startForegroundSafe(getString(R.string.notification_starting))) {
                    stopSelf()
                    return START_NOT_STICKY
                }
                LogManager.clearLogs()
                startProxy(
                    ProxyConfig(
                        bindIp = intent.getStringExtra(EXTRA_BIND_IP) ?: "127.0.0.1",
                        port = intent.getIntExtra(EXTRA_PORT, 1443),
                        ips = intent.getStringExtra(EXTRA_IPS) ?: "",
                        poolSize = intent.getIntExtra(EXTRA_POOL_SIZE, 4),
                        cfEnabled = intent.getBooleanExtra(EXTRA_CFPROXY_ENABLED, true),
                        cfPriority = intent.getBooleanExtra(EXTRA_CFPROXY_PRIORITY, true),
                        cfDomain = intent.getStringExtra(EXTRA_CFPROXY_DOMAIN) ?: "",
                        secretKey = intent.getStringExtra(EXTRA_SECRET_KEY) ?: "",
                    )
                )
            }
            ACTION_STOP -> {
                stopProxy()
            }
            ACTION_RESTART -> {
                restartProxy()
            }
            null -> {
                // Service restarted by system after being killed
                val cfg = lastConfig
                if (cfg != null) {
                    Log.w(TAG, "Service restarted by system, re-starting proxy")
                    startProxy(cfg)
                } else {
                    stopSelf()
                }
            }
        }
        // START_REDELIVER_INTENT: if the system kills the service, it will restart it
        // and re-deliver the last intent, so we don't lose the config.
        return START_REDELIVER_INTENT
    }

    private fun startForegroundSafe(content: String): Boolean {
        return try {
            val notification = createNotification(content)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            true
        } catch (e: Exception) {
            // Android 12+: ForegroundServiceStartNotAllowedException при рестарте из фона.
            Log.e(TAG, "startForeground failed", e)
            false
        }
    }

    private fun isPortAvailable(bindIp: String, port: Int): Boolean {
        return try {
            ServerSocket().use { socket ->
                socket.reuseAddress = true
                socket.bind(InetSocketAddress(InetAddress.getByName(bindIp), port))
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun startProxy(cfg: ProxyConfig) {
        if (_isRunning.value || startInProgress) return
        if (stopInProgress) {
            // Стоп ещё идёт: стартуем сразу после него, а не теряем запрос.
            pendingStart = cfg
            return
        }
        startInProgress = true
        _isVerifiedRunning.value = false
        lastConfig = cfg

        notificationStartedAtMs = System.currentTimeMillis()
        lastNotificationContent = getString(R.string.notification_starting)
        lastNotificationAtMs = notificationStartedAtMs
        if (!startForegroundSafe(lastNotificationContent)) {
            startInProgress = false
            updateRunningState(false)
            stopSelf()
            return
        }

        // Без WakeLock: FGS сохраняет сеть в Doze, а входящий пакет сам будит CPU.
        // Постоянный PARTIAL_WAKE_LOCK не давал процессору засыпать вообще.
        registerScreenReceiver()
        registerNetworkCallback()
        if ((getSystemService(POWER_SERVICE) as PowerManager).isInteractive) {
            startStatsUpdates()
        }

        serviceScope.launch {
            val result: Result<Int> = withContext(nativeDispatcher) {
                if (!isPortAvailable(cfg.bindIp, cfg.port)) {
                    return@withContext Result.failure(PortBusyException())
                }
                runCatching {
                    NativeProxy.setPoolSize(cfg.poolSize)
                    NativeProxy.setCfProxyCacheDir(cacheDir.absolutePath)
                    NativeProxy.setCfProxyConfig(cfg.cfEnabled, cfg.cfPriority, cfg.cfDomain)
                    NativeProxy.startProxy(cfg.bindIp, cfg.port, cfg.ips, cfg.secretKey, 1)
                }
            }
            startInProgress = false
            if (stopInProgress) return@launch

            val code = result.getOrNull()
            val error = result.exceptionOrNull()
            when {
                code == 0 -> {
                    updateRunningState(true)
                    _isVerifiedRunning.value = true
                    updateNotification(getString(R.string.notification_running), force = true)
                    Log.i(TAG, "Proxy ready: listening on port ${cfg.port}")
                }
                error is PortBusyException -> {
                    val str = getString(R.string.port_is_not_available, cfg.port)
                    Toast.makeText(this@ProxyService, str, Toast.LENGTH_SHORT).show()
                    updateNotification(str, force = true)
                    stopProxy()
                }
                error != null -> {
                    Log.e(TAG, "Failed to start proxy via JNA", error)
                    updateNotification(getString(R.string.notification_error, error.message ?: ""), force = true)
                    delay(3000.milliseconds)
                    stopProxy()
                }
                else -> {
                    Log.e(TAG, "StartProxy returned error code: $code")
                    updateNotification(getString(R.string.notification_start_error_code, code ?: -1), force = true)
                    delay(3000.milliseconds)
                    stopProxy()
                }
            }
        }
    }

    private fun startStatsUpdates() {
        if (statsJob?.isActive == true) return
        statsJob = serviceScope.launch {
            while (isActive) {
                delay(STATS_UPDATE_MS.milliseconds)
                if (_isRunning.value && !stopInProgress) {
                    try {
                        val rawStats = withContext(Dispatchers.IO) { NativeProxy.getStats() } ?: continue
                        val upRaw = extractStat(rawStats, "up=")
                        val downRaw = extractStat(rawStats, "down=")
                        val activeConns = extractStat(rawStats, "active=")

                        val totalBytes = parseHumanBytes(upRaw) + parseHumanBytes(downRaw)
                        val active = activeConns.toIntOrNull() ?: 0
                        val text = getString(R.string.notification_traffic, formatBytes(totalBytes), active)
                        updateNotification(text)
                    } catch (e: Exception) {
                        Log.w(TAG, "Stats update failed", e)
                    }
                }
            }
        }
    }

    private fun stopStatsUpdates() {
        statsJob?.cancel()
        statsJob = null
    }

    // Уведомление при выключенном экране никто не видит — не дёргаем JNI и
    // NotificationManager впустую.
    private fun registerScreenReceiver() {
        if (screenReceiver != null) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                when (intent.action) {
                    Intent.ACTION_SCREEN_ON -> if (!stopInProgress && (_isRunning.value || startInProgress)) startStatsUpdates()
                    Intent.ACTION_SCREEN_OFF -> stopStatsUpdates()
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        screenReceiver = receiver
    }

    private fun unregisterScreenReceiver() {
        screenReceiver?.let {
            try {
                unregisterReceiver(it)
            } catch (_: IllegalArgumentException) {
            }
        }
        screenReceiver = null
    }

    // Wi-Fi <-> LTE: сокеты пула от старой сети молча мертвы, а cooldown'ы
    // посчитаны для другого маршрута — без сброса TG минуту получал дохлые коннекты.
    private fun registerNetworkCallback() {
        if (networkCallback != null || Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return
        val cm = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            @Volatile
            private var current: Network? = null

            override fun onAvailable(network: Network) {
                val prev = current
                current = network
                // Первый onAvailable прилетает сразу при регистрации — это не смена.
                if (prev != null && prev != network) {
                    nativeScope.launch {
                        try {
                            NativeProxy.networkChanged()
                        } catch (e: Throwable) {
                            Log.w(TAG, "NetworkChanged failed", e)
                        }
                    }
                }
            }
        }
        try {
            cm.registerDefaultNetworkCallback(callback)
            networkCallback = callback
        } catch (e: Exception) {
            Log.w(TAG, "registerDefaultNetworkCallback failed", e)
        }
    }

    private fun unregisterNetworkCallback() {
        val cb = networkCallback ?: return
        networkCallback = null
        try {
            (getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager)?.unregisterNetworkCallback(cb)
        } catch (_: Exception) {
        }
    }

    private fun updateNotification(content: String, force: Boolean = false) {
        val now = System.currentTimeMillis()
        if (!force) {
            if (content == lastNotificationContent) return
            if (lastNotificationAtMs != 0L && now - lastNotificationAtMs < NOTIFICATION_MIN_UPDATE_MS) return
        }

        lastNotificationContent = content
        lastNotificationAtMs = now
        try {
            val manager = getSystemService(NOTIFICATION_SERVICE) as? NotificationManager
            manager?.notify(NOTIFICATION_ID, createNotification(content))
        } catch (e: Exception) {
            Log.w(TAG, "Failed to update notification", e)
        }
    }

    private fun restartProxy() {
        if (restartJob?.isActive == true || stopInProgress || startInProgress) return
        val cfg = lastConfig
        if (cfg == null) {
            Log.w(TAG, "Restart requested without saved proxy configuration")
            return
        }

        restartJob = serviceScope.launch {
            Log.i(TAG, "Restarting proxy from notification")
            updateNotification(getString(R.string.notification_restarting), force = true)

            requestNativeStop("restart")
            updateRunningState(false)
            delay(350.milliseconds)
            startProxy(cfg)
        }
    }

    private fun extractStat(stats: String, key: String): String {
        val idx = stats.indexOf(key)
        if (idx == -1) return "0B"
        val start = idx + key.length
        val end = stats.indexOf(" ", start)
        return if (end == -1) stats.substring(start) else stats.substring(start, end)
    }

    private fun parseHumanBytes(s: String): Double {
        val num = s.replace(Regex("[^0-9.]"), "").toDoubleOrNull() ?: 0.0
        return when {
            s.endsWith("TB") -> num * 1024.0 * 1024 * 1024 * 1024
            s.endsWith("GB") -> num * 1024.0 * 1024 * 1024
            s.endsWith("MB") -> num * 1024.0 * 1024
            s.endsWith("KB") -> num * 1024.0
            else -> num
        }
    }

    private fun formatBytes(bytes: Double): String {
        if (bytes < 1024) return "%.0fB".format(bytes)
        if (bytes < 1024 * 1024) return "%.1fKB".format(bytes / 1024)
        if (bytes < 1024 * 1024 * 1024) return "%.1fMB".format(bytes / (1024 * 1024))
        return "%.2fGB".format(bytes / (1024 * 1024 * 1024))
    }

    private fun stopProxy() {
        if (stopInProgress) return
        stopInProgress = true
        pendingStart = null
        restartJob?.cancel()
        restartJob = null
        stopStatsUpdates()
        unregisterScreenReceiver()
        unregisterNetworkCallback()
        serviceScope.launch {
            updateNotification(getString(R.string.notification_stopping), force = true)
            // nativeScope последовательный: стоп гарантированно после идущего старта.
            requestNativeStop("stop")
            updateRunningState(false)
            stopInProgress = false

            val pending = pendingStart
            pendingStart = null
            if (pending != null) {
                startProxy(pending)
                return@launch
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
            stopSelf()
        }
    }

    private suspend fun requestNativeStop(reason: String): Boolean {
        val job = nativeScope.async {
            try {
                NativeProxy.stopProxy()
            } catch (e: Throwable) {
                Log.w(TAG, "StopProxy failed during $reason", e)
            }
        }
        // await, а не withContext: блокирующий JNI-вызов нельзя прервать, но ждать
        // его дольше таймаута UI не обязан.
        val finished = withTimeoutOrNull(NATIVE_STOP_WAIT_MS.milliseconds) {
            job.await()
            true
        } ?: false

        if (!finished) {
            Log.w(TAG, "Native stop is still running after ${NATIVE_STOP_WAIT_MS}ms during $reason")
        }
        return finished
    }

    /**
     * Called when the user swipes the app from recents.
     * Without this, the service would be killed on many OEM Androids.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        if (_isRunning.value) {
            Log.w(TAG, "onTaskRemoved: proxy is running, service stays alive")
            // The service continues because stopWithTask=false in manifest
        }
    }

    private fun updateRunningState(isRunning: Boolean) {
        _isRunning.value = isRunning
        if (!isRunning) {
            _isVerifiedRunning.value = false
        }
        _stateEpoch.value += 1
        ProxyTileService.requestSync(this)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_description)
                setShowBadge(false)
                setSound(null, null)
                enableVibration(false)
                enableLights(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
            val manager = getSystemService(NOTIFICATION_SERVICE) as? NotificationManager
            manager?.createNotificationChannel(serviceChannel)
        }
    }

    private fun createNotification(content: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPendingIntent = PendingIntent.getActivity(
            this, 1, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, ProxyService::class.java).apply {
            action = ACTION_STOP
        }
        val restartIntent = Intent(this, ProxyService::class.java).apply {
            action = ACTION_RESTART
        }
        val restartPendingIntent = PendingIntent.getService(
            this, 2, restartIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Telegram WS Proxy")
            .setContentText(content)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(openPendingIntent) // Tap notification → open app
            .addAction(android.R.drawable.ic_popup_sync, getString(R.string.notification_restart), restartPendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, getString(R.string.notification_disconnect), stopPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setWhen(notificationStartedAtMs.takeIf { it > 0L } ?: System.currentTimeMillis())
            .setShowWhen(false)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    override fun onDestroy() {
        restartJob?.cancel()
        restartJob = null
        stopStatsUpdates()
        unregisterScreenReceiver()
        unregisterNetworkCallback()
        // Сервис уничтожен не через stopProxy (система/FGS-лимит) — гасим ядро,
        // иначе оно держит порт и следующий старт падает с «порт занят».
        if (!stopInProgress && (_isRunning.value || startInProgress)) {
            nativeScope.launch {
                try {
                    NativeProxy.stopProxy()
                } catch (_: Throwable) {
                }
            }
        }
        if (_isRunning.value) {
            updateRunningState(false)
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }
}
