package org.flowseal.tgwsproxy.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import org.flowseal.tgwsproxy.service.TgWsProxyService
import org.flowseal.tgwsproxy.util.SettingsManager

class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        Log.i(TAG, "Received broadcast action: $action")

        if (action == Intent.ACTION_BOOT_COMPLETED ||
            action == Intent.ACTION_MY_PACKAGE_REPLACED ||
            action == "android.intent.action.QUICKBOOT_POWERON" ||
            action == "com.htc.intent.action.QUICKBOOT_POWERON"
        ) {
            if (SettingsManager.isAutoStartEnabled(context)) {
                Log.i(TAG, "Auto-start is enabled, launching TgWsProxyService...")
                val serviceIntent = Intent(context, TgWsProxyService::class.java).apply {
                    this.action = TgWsProxyService.ACTION_START
                }
                try {
                    ContextCompat.startForegroundService(context, serviceIntent)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to start service on boot", e)
                }
            } else {
                Log.d(TAG, "Auto-start is disabled in settings, skipping.")
            }
        }
    }
}
