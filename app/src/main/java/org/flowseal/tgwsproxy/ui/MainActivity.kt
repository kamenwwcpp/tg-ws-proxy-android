package org.flowseal.tgwsproxy.ui

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import org.flowseal.tgwsproxy.checkForUpdate
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.flowseal.tgwsproxy.R
import org.flowseal.tgwsproxy.databinding.ActivityMainBinding
import org.flowseal.tgwsproxy.databinding.BottomSheetSettingsBinding
import org.flowseal.tgwsproxy.service.TgWsProxyService
import org.flowseal.tgwsproxy.util.SettingsManager

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val logBuffer = StringBuilder()

    private val requestNotificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
        if (!isGranted) {
            Toast.makeText(this, "Уведомления необходимы для стабильной работы службы", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        checkPermissions()
        requestBatteryOptimizationExemption()
        lifecycleScope.launch {
            try {
                SettingsManager.migrateLegacySettings(this@MainActivity)
            } catch (e: java.io.IOException) {
                android.util.Log.w("TgWsProxy", "Legacy settings could not be read", e)
            }
            setupListeners()
            observeState()
            updateSettingsSummary()
            val release = checkForUpdate() ?: return@launch
            if (isFinishing || isDestroyed) return@launch
            MaterialAlertDialogBuilder(this@MainActivity)
                .setTitle(R.string.update_available)
                .setMessage(getString(R.string.update_message, release.version))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.update_download) { _, _ ->
                    try {
                        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(release.url)))
                    } catch (_: ActivityNotFoundException) {
                        Toast.makeText(this@MainActivity, R.string.update_open_failed, Toast.LENGTH_SHORT).show()
                    }
                }
                .show()
        }
    }

    private fun requestBatteryOptimizationExemption() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                try {
                    val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                        data = Uri.parse("package:$packageName")
                    }
                    startActivity(intent)
                } catch (e: ActivityNotFoundException) {
                    android.util.Log.w("MainActivity", "Battery optimization intent not supported on this device", e)
                } catch (e: SecurityException) {
                    android.util.Log.w("MainActivity", "Battery optimization permission denied", e)
                }
            }
        }
    }

    private fun openBackgroundOptimizationSettings() {
        val intents = mutableListOf<Intent>()

        // 1. Unrestricted Background Data usage (Android 7.0+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            intents.add(
                Intent(Settings.ACTION_IGNORE_BACKGROUND_DATA_RESTRICTIONS_SETTINGS).apply {
                    data = Uri.parse("package:$packageName")
                }
            )
        }

        // 2. Battery optimization ignore request
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            intents.add(
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
            )
        }

        // 3. Fallback to App Details Settings
        intents.add(
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.parse("package:$packageName")
            }
        )

        var launched = false
        for (intent in intents) {
            try {
                startActivity(intent)
                launched = true
                break
            } catch (_: ActivityNotFoundException) {
                // Try next candidate intent
            } catch (e: SecurityException) {
                android.util.Log.w("MainActivity", "Settings activity security exception", e)
            }
        }

        if (launched) {
            Toast.makeText(
                this,
                "Для Infinix/Tecno/Xiaomi: разрешите «Работу в фоне» и «Неограниченный трафик»",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun checkPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                requestNotificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun setupListeners() {
        binding.btnToggleProxy.setOnClickListener {
            if (TgWsProxyService.isRunning.value) {
                stopProxyService()
            } else {
                startProxyService()
            }
        }

        binding.btnConnectTelegram.setOnClickListener {
            connectToTelegram()
        }

        binding.btnQuickSettings.setOnClickListener {
            showSmartSettingsDialog()
        }

        binding.btnOpenSmartSettings.setOnClickListener {
            showSmartSettingsDialog()
        }

        binding.btnCopyLogs.setOnClickListener {
            try {
                val fullText = if (logBuffer.isNotEmpty()) logBuffer.toString() else binding.tvLogs.text.toString()
                val safeText = if (fullText.length > 40000) fullText.takeLast(40000) else fullText
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("TG Proxy Logs", safeText))
                Toast.makeText(this, "Логи скопированы в буфер", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(this, "Ошибка копирования логов: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnClearLogs.setOnClickListener {
            logBuffer.clear()
            val time = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())
            binding.tvLogs.text = "[$time] ℹ️ Журнал очищен.\n"
        }

        binding.btnCheckPing.setOnClickListener {
            runGatewayDiagnostics()
        }
    }

    private fun runGatewayDiagnostics() {
        updateUiRunningState(TgWsProxyService.isRunning.value)
        binding.btnCheckPing.isEnabled = false
        binding.tvDc2Ping.text = "..."
        binding.tvDc4Ping.text = "..."
        binding.tvDc1Ping.text = "..."
        binding.tvCfPing.text = "..."

        val inactiveColor = ContextCompat.getColor(this, R.color.text_secondary)
        binding.tvDc2Ping.setTextColor(inactiveColor)
        binding.tvDc4Ping.setTextColor(inactiveColor)
        binding.tvDc1Ping.setTextColor(inactiveColor)
        binding.tvCfPing.setTextColor(inactiveColor)

        lifecycleScope.launch {
            val results = org.flowseal.tgwsproxy.util.NetworkDiagnostics.runDiagnostics(this@MainActivity)
            results.forEach { res ->
                val text = if (res.rttMs != null) "${res.rttMs} мс" else "Ошибка"
                val color = when {
                    res.rttMs == null -> android.graphics.Color.parseColor("#E53935")
                    res.rttMs < 100 -> android.graphics.Color.parseColor("#4CAF50")
                    res.rttMs < 250 -> android.graphics.Color.parseColor("#8BC34A")
                    else -> android.graphics.Color.parseColor("#FF9800")
                }
                when (res.dcId) {
                    2 -> {
                        binding.tvDc2Ping.text = text
                        binding.tvDc2Ping.setTextColor(color)
                        binding.dotDc2.setBackgroundColor(color)
                    }
                    4 -> {
                        binding.tvDc4Ping.text = text
                        binding.tvDc4Ping.setTextColor(color)
                        binding.dotDc4.setBackgroundColor(color)
                    }
                    1 -> {
                        binding.tvDc1Ping.text = text
                        binding.tvDc1Ping.setTextColor(color)
                        binding.dotDc1.setBackgroundColor(color)
                    }
                    0 -> {
                        binding.tvCfPing.text = text
                        binding.tvCfPing.setTextColor(color)
                        binding.dotCf.setBackgroundColor(color)
                    }
                }
            }
            binding.btnCheckPing.isEnabled = true
        }
    }

    private fun startProxyService() {
        val port = SettingsManager.getPort(this)
        val secret = SettingsManager.getSecret(this)
        val domain = SettingsManager.getDomain(this)

        val intent = Intent(this, TgWsProxyService::class.java).apply {
            action = TgWsProxyService.ACTION_START
            putExtra(TgWsProxyService.EXTRA_PORT, port)
            putExtra(TgWsProxyService.EXTRA_SECRET, secret)
            putExtra(TgWsProxyService.EXTRA_DOMAIN, domain)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopProxyService() {
        val intent = Intent(this, TgWsProxyService::class.java).apply {
            action = TgWsProxyService.ACTION_STOP
        }
        startService(intent)
    }

    private fun connectToTelegram() {
        val port = SettingsManager.getPort(this)
        val secret = SettingsManager.getSecret(this)

        if (!TgWsProxyService.isRunning.value) {
            startProxyService()
        }

        val uri = Uri.parse("tg://proxy?server=127.0.0.1&port=$port&secret=$secret")
        val intent = Intent(Intent.ACTION_VIEW, uri).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }

        try {
            startActivity(intent)
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, "Telegram не найден на этом устройстве", Toast.LENGTH_LONG).show()
        } catch (e: SecurityException) {
            Toast.makeText(this, "Не удалось открыть Telegram: доступ ограничен", Toast.LENGTH_LONG).show()
        }
    }

    private fun observeState() {
        lifecycleScope.launch {
            TgWsProxyService.isRunning.collectLatest { running ->
                updateUiRunningState(running)
            }
        }

        lifecycleScope.launch {
            TgWsProxyService.statsFlow.collectLatest { stats ->
                binding.tvStatsMetrics.text =
                    "Активно: ${stats.active} | Входящий: %.2f MB | Исходящий: %.2f MB".format(
                        stats.downMb,
                        stats.upMb
                    )
            }
        }

        lifecycleScope.launch {
            TgWsProxyService.logFlow.collect { logLine ->
                logBuffer.append(logLine).append("\n")
                if (logBuffer.length > 40000) {
                    logBuffer.delete(0, 10000)
                }
                binding.tvLogs.text = logBuffer.toString()
                binding.scrollLogs.post {
                    binding.scrollLogs.fullScroll(android.view.View.FOCUS_DOWN)
                }
            }
        }

        lifecycleScope.launch {
            TgWsProxyService.secretMismatchFlow.collectLatest {
                Snackbar.make(
                    binding.root,
                    "Ключ в Telegram устарел! Обновите прокси в Telegram.",
                    Snackbar.LENGTH_INDEFINITE
                ).setAction("Обновить") {
                    connectToTelegram()
                }.show()
            }
        }
    }

    private fun updateUiRunningState(running: Boolean) {
        val port = SettingsManager.getPort(this)

        if (running) {
            binding.viewStatusDot.setBackgroundColor(ContextCompat.getColor(this, R.color.status_active))
            binding.tvStatusTitle.text = getString(R.string.status_running, port.toString())
            binding.btnToggleProxy.text = getString(R.string.btn_stop)
            binding.btnToggleProxy.setIconResource(R.drawable.ic_stop)
            binding.btnToggleProxy.backgroundTintList = ContextCompat.getColorStateList(this, R.color.status_inactive)

            binding.dotLocalProxy.setBackgroundColor(android.graphics.Color.parseColor("#4CAF50"))
            binding.tvLocalProxyStatus.text = "Активен"
            binding.tvLocalProxyStatus.setTextColor(android.graphics.Color.parseColor("#4CAF50"))
            binding.tvDiagnosticHint.text = "Прокси активен на 127.0.0.1:$port. Трафик Telegram защищён и направлен через веб-шлюзы."
            binding.tvDiagnosticHint.setTextColor(android.graphics.Color.parseColor("#8BC34A"))
        } else {
            binding.viewStatusDot.setBackgroundColor(ContextCompat.getColor(this, R.color.status_inactive))
            binding.tvStatusTitle.text = getString(R.string.status_stopped)
            binding.btnToggleProxy.text = getString(R.string.btn_start)
            binding.btnToggleProxy.setIconResource(R.drawable.ic_play)
            binding.btnToggleProxy.backgroundTintList = ContextCompat.getColorStateList(this, R.color.primary)

            binding.dotLocalProxy.setBackgroundColor(ContextCompat.getColor(this, R.color.status_inactive))
            binding.tvLocalProxyStatus.text = "Остановлен"
            binding.tvLocalProxyStatus.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
            binding.tvDiagnosticHint.text = "Шлюзы на связи. Для работы Telegram запустите прокси кнопкой выше."
            binding.tvDiagnosticHint.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
        }
        binding.tvLocalProxyTitle.text = "Локальный мост (127.0.0.1:$port)"
    }

    private fun updateSettingsSummary() {
        val currentDomain = SettingsManager.getDomain(this)
        val preset = SettingsManager.PRESET_DOMAINS.find { it.first == currentDomain }
        val presetName = preset?.second ?: "Пользовательский"
        val port = SettingsManager.getPort(this)
        val cfStatus = if (SettingsManager.isCloudflareFallback(this)) "включен" else "выключен"

        binding.tvSettingsSummaryDomain.text = "Маскировка (SNI): $currentDomain ($presetName)"
        binding.tvSettingsSummaryPort.text = "Порт: $port • Cloudflare Fallback: $cfStatus"
        binding.tvLocalProxyTitle.text = "Локальный мост (127.0.0.1:$port)"
    }

    private fun showSmartSettingsDialog() {
        val dialog = BottomSheetDialog(this)
        val sheetBinding = BottomSheetSettingsBinding.inflate(layoutInflater)
        dialog.setContentView(sheetBinding.root)

        val currentDomain = SettingsManager.getDomain(this)
        sheetBinding.etDomain.setText(currentDomain)
        sheetBinding.etSecret.setText(SettingsManager.getSecret(this))
        sheetBinding.etPort.setText(SettingsManager.getPort(this).toString())
        sheetBinding.switchCloudflare.isChecked = SettingsManager.isCloudflareFallback(this)
        sheetBinding.switchAutoStart.isChecked = SettingsManager.isAutoStartEnabled(this)

        fun updateDomainsLabel() {
            val domains = SettingsManager.getDynamicDomains(this)
            val lastUpdate = SettingsManager.getLastDomainUpdate(this)
            val updateText = if (lastUpdate > 0) {
                java.text.SimpleDateFormat("dd.MM HH:mm", java.util.Locale.getDefault()).format(java.util.Date(lastUpdate))
            } else "по умолчанию"
            sheetBinding.tvDynamicDomainsStatus.text = "Активно зеркал: ${domains.size} • $updateText"
        }
        updateDomainsLabel()

        sheetBinding.btnRefreshDomains.setOnClickListener {
            sheetBinding.btnRefreshDomains.isEnabled = false
            sheetBinding.tvDynamicDomainsStatus.text = "Обновление с GitHub..."
            lifecycleScope.launch {
                val res = SettingsManager.fetchAndRefreshDomains(this@MainActivity)
                sheetBinding.btnRefreshDomains.isEnabled = true
                res.onSuccess { count ->
                    updateDomainsLabel()
                    Toast.makeText(this@MainActivity, "Зеркала обновлены ($count доменов)", Toast.LENGTH_SHORT).show()
                    if (TgWsProxyService.isRunning.value) {
                        stopProxyService()
                        binding.root.postDelayed({ startProxyService() }, 300)
                    }
                }.onFailure { err ->
                    sheetBinding.tvDynamicDomainsStatus.text = "Ошибка: ${err.message}"
                    Toast.makeText(this@MainActivity, "Не удалось обновить зеркала", Toast.LENGTH_SHORT).show()
                }
            }
        }

        sheetBinding.btnBackgroundSettings.setOnClickListener {
            openBackgroundOptimizationSettings()
        }

        when (currentDomain) {
            "google.com" -> sheetBinding.chipGoogle.isChecked = true
            "icloud.com" -> sheetBinding.chipApple.isChecked = true
            "cloudflare.com" -> sheetBinding.chipCloudflare.isChecked = true
            "microsoft.com" -> sheetBinding.chipMicrosoft.isChecked = true
            "yandex.ru" -> sheetBinding.chipYandex.isChecked = true
        }

        fun applyPreset(domain: String) {
            sheetBinding.etDomain.setText(domain)
            val newSecret = SettingsManager.generateSecretForDomain(domain)
            sheetBinding.etSecret.setText(newSecret)
        }

        sheetBinding.chipGoogle.setOnClickListener { applyPreset("google.com") }
        sheetBinding.chipApple.setOnClickListener { applyPreset("icloud.com") }
        sheetBinding.chipCloudflare.setOnClickListener { applyPreset("cloudflare.com") }
        sheetBinding.chipMicrosoft.setOnClickListener { applyPreset("microsoft.com") }
        sheetBinding.chipYandex.setOnClickListener { applyPreset("yandex.ru") }

        sheetBinding.btnGenerateSecret.setOnClickListener {
            val domain = sheetBinding.etDomain.text.toString().trim().ifBlank { "google.com" }
            val newSecret = SettingsManager.generateRandomSecretForDomain(domain)
            sheetBinding.etSecret.setText(newSecret)
            Toast.makeText(this, "Сгенерирован новый Fake TLS ключ", Toast.LENGTH_SHORT).show()
        }

        sheetBinding.btnCopySecret.setOnClickListener {
            val secret = sheetBinding.etSecret.text.toString()
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("TG Proxy Secret", secret))
            Toast.makeText(this, "Секрет скопирован в буфер", Toast.LENGTH_SHORT).show()
        }

        sheetBinding.btnResetDefaults.setOnClickListener {
            SettingsManager.resetToDefaults(this)
            sheetBinding.etDomain.setText(SettingsManager.DEFAULT_DOMAIN)
            sheetBinding.etSecret.setText(SettingsManager.getSecret(this))
            sheetBinding.etPort.setText(SettingsManager.DEFAULT_PORT.toString())
            sheetBinding.switchCloudflare.isChecked = true
            sheetBinding.switchAutoStart.isChecked = false
            sheetBinding.chipGoogle.isChecked = true
            updateDomainsLabel()
            Toast.makeText(this, "Настройки сброшены к рекомендованным", Toast.LENGTH_SHORT).show()
        }

        sheetBinding.btnSaveSettings.setOnClickListener {
            val port = sheetBinding.etPort.text.toString().toIntOrNull() ?: 1443
            val domain = sheetBinding.etDomain.text.toString().trim().ifBlank { "google.com" }
            var secret = sheetBinding.etSecret.text.toString().trim()
            if (secret.isBlank()) {
                secret = SettingsManager.generateSecretForDomain(domain)
            }

            SettingsManager.setPort(this, port)
            SettingsManager.setDomain(this, domain)
            SettingsManager.setSecret(this, secret)
            SettingsManager.setCloudflareFallback(this, sheetBinding.switchCloudflare.isChecked)
            SettingsManager.setAutoStartEnabled(this, sheetBinding.switchAutoStart.isChecked)

            updateSettingsSummary()

            if (TgWsProxyService.isRunning.value) {
                stopProxyService()
                binding.root.postDelayed({ startProxyService() }, 300)
            }

            dialog.dismiss()
            Snackbar.make(binding.root, "Настройки сохранены. Обновите ключ в Telegram!", Snackbar.LENGTH_LONG)
                .setAction("Обновить") { connectToTelegram() }
                .show()
        }

        dialog.show()
    }
}
