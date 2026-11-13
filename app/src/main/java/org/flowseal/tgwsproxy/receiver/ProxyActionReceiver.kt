package org.flowseal.tgwsproxy.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.flowseal.tgwsproxy.service.TgWsProxyService

class ProxyActionReceiver : BroadcastReceiver() {

    companion object {
        const val ACTION_STOP = "org.flowseal.tgwsproxy.ACTION_STOP"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_STOP) {
            val stopIntent = Intent(context, TgWsProxyService::class.java).apply {
                action = TgWsProxyService.ACTION_STOP
            }
            context.startService(stopIntent)
        }
    }
}
