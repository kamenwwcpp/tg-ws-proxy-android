package com.amurcanov.tgwsproxy

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Автоподъём прокси, если прошивка выгрузила процесс (идея форка Alexingin).
 *
 * Приложение помнит, что пользователь включил прокси, и проверяет, жив ли он:
 *  - точным будильником раз в 15 минут — он срабатывает и в Doze и даёт право
 *    запустить foreground-сервис из фона на Android 12+;
 *  - при открытии шторки с плиткой и при открытии приложения.
 * Если пользователь сам выключил прокси, ничего не поднимается.
 */
object KeepAlive {
    private const val TAG = "TgWsProxy"
    private const val PREFS = "keep_alive"
    private const val KEY_DESIRED = "desired_running"
    private const val KEY_LAST_REVIVE = "last_revive_at"
    private const val KEY_ASKED_BATTERY = "asked_battery_exemption"
    private const val CHECK_INTERVAL_MS = 15L * 60 * 1000
    private const val REVIVE_MIN_GAP_MS = 20_000L
    private const val REQUEST_CODE = 7101
    const val ACTION_CHECK = "com.amurcanov.tgwsproxy.KEEP_ALIVE_CHECK"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun isDesired(context: Context): Boolean = prefs(context).getBoolean(KEY_DESIRED, false)

    /** Прокси успешно запущен — пользователь хочет, чтобы он работал. */
    fun onProxyStarted(context: Context) {
        prefs(context).edit().putBoolean(KEY_DESIRED, true).apply()
        schedule(context)
    }

    /** Пользователь сам выключил прокси — поднимать больше не нужно. */
    fun onUserStopped(context: Context) {
        prefs(context).edit().putBoolean(KEY_DESIRED, false).apply()
        cancel(context)
    }

    private fun pendingIntent(context: Context): PendingIntent {
        val intent = Intent(context, KeepAliveReceiver::class.java).setAction(ACTION_CHECK)
        return PendingIntent.getBroadcast(
            context,
            REQUEST_CODE,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    fun schedule(context: Context) {
        val am = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        val at = SystemClock.elapsedRealtime() + CHECK_INTERVAL_MS
        val pi = pendingIntent(context)
        try {
            val exactAllowed = Build.VERSION.SDK_INT < Build.VERSION_CODES.S || am.canScheduleExactAlarms()
            when {
                exactAllowed && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ->
                    am.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ->
                    am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
                else -> am.set(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
            }
        } catch (e: Exception) {
            Log.w(TAG, "[WARN] KeepAlive: не удалось поставить будильник: ${e.message}")
        }
    }

    fun cancel(context: Context) {
        val am = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        runCatching { am.cancel(pendingIntent(context)) }
    }

    /** Поднять прокси, если он должен работать, но не работает. */
    suspend fun reviveIfNeeded(context: Context, reason: String): Boolean {
        val app = context.applicationContext
        if (!isDesired(app)) return false
        if (ProxyService.isRunning.value) return false
        val p = prefs(app)
        // Не чаще раза в 20 секунд: шторка и приложение могут дёрнуть подряд.
        val now = System.currentTimeMillis()
        if (now - p.getLong(KEY_LAST_REVIVE, 0L) < REVIVE_MIN_GAP_MS) return false
        p.edit().putLong(KEY_LAST_REVIVE, now).apply()

        Log.w(TAG, "[WARN] Прокси должен работать, но был остановлен системой — перезапуск ($reason)")
        return try {
            withContext(Dispatchers.Main) {
                ProxyController.startFromSavedSettings(
                    app,
                    showInvalidPortToast = false,
                    autoReviveReason = reason
                )
            }
        } catch (e: Exception) {
            // Android 12+ может запретить запуск foreground-сервиса из фона,
            // если приложению не разрешена работа в фоне.
            Log.w(TAG, "[WARN] Не удалось перезапустить прокси ($reason): ${e.javaClass.simpleName}: ${e.message}")
            false
        }
    }

    /** Один раз попросить разрешение на работу в фоне (после первого запуска прокси). */
    fun shouldAskBatteryOnce(context: Context): Boolean {
        if (isIgnoringBatteryOptimizations(context)) return false
        val p = prefs(context)
        if (p.getBoolean(KEY_ASKED_BATTERY, false)) return false
        p.edit().putBoolean(KEY_ASKED_BATTERY, true).apply()
        return true
    }

    /**
     * Системный диалог «Разрешить приложению работать в фоне?». Касается только
     * этого приложения, общая экономия батареи телефона не меняется.
     */
    @android.annotation.SuppressLint("BatteryLife")
    fun openBatterySettings(context: Context) {
        val intents = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                add(
                    Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                        .setData(Uri.parse("package:${context.packageName}"))
                )
            }
            add(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                    .setData(Uri.parse("package:${context.packageName}"))
            )
        }
        for (i in intents) {
            try {
                context.startActivity(i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                return
            } catch (_: Exception) {
            }
        }
    }

    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return true
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return true
        return pm.isIgnoringBatteryOptimizations(context.packageName)
    }
}

/** Срабатывает по будильнику KeepAlive, даже если процесс был выгружен. */
class KeepAliveReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != KeepAlive.ACTION_CHECK) return
        val pending = goAsync()
        val app = context.applicationContext
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                if (KeepAlive.isDesired(app)) {
                    KeepAlive.reviveIfNeeded(app, "будильник")
                    KeepAlive.schedule(app)
                }
            } catch (e: Exception) {
                Log.w("TgWsProxy", "[WARN] KeepAlive: ${e.message}")
            } finally {
                pending.finish()
            }
        }
    }
}
