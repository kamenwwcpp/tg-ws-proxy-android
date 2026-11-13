package org.flowseal.tgwsproxy.service

import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi
import org.flowseal.tgwsproxy.util.SettingsManager

@RequiresApi(Build.VERSION_CODES.N)
class TgWsProxyTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTileState()
    }

    override fun onClick() {
        super.onClick()
        val isRunning = TgWsProxyService.isRunning.value
        val intent = Intent(this, TgWsProxyService::class.java).apply {
            if (isRunning) {
                action = TgWsProxyService.ACTION_STOP
            } else {
                action = TgWsProxyService.ACTION_START
                putExtra(TgWsProxyService.EXTRA_PORT, SettingsManager.getPort(this@TgWsProxyTileService))
                putExtra(TgWsProxyService.EXTRA_SECRET, SettingsManager.getSecret(this@TgWsProxyTileService))
                putExtra(TgWsProxyService.EXTRA_DOMAIN, SettingsManager.getDomain(this@TgWsProxyTileService))
            }
        }

        if (isRunning) {
            startService(intent)
        } else {
            androidx.core.content.ContextCompat.startForegroundService(this, intent)
        }

        updateTileState(!isRunning)
    }

    private fun updateTileState(forcedRunning: Boolean? = null) {
        val tile = qsTile ?: return
        val running = forcedRunning ?: TgWsProxyService.isRunning.value
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = if (running) "TG Proxy: ВКЛ" else "TG Proxy: ВЫКЛ"
        tile.updateTile()
    }
}
