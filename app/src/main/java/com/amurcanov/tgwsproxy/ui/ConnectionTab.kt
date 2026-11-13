package com.amurcanov.tgwsproxy.ui

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.amurcanov.tgwsproxy.BuildConfig
import com.amurcanov.tgwsproxy.ProxyController
import com.amurcanov.tgwsproxy.ProxyService
import com.amurcanov.tgwsproxy.SettingsStore
import com.amurcanov.tgwsproxy.R
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

@Composable
fun ConnectionTab(settingsStore: SettingsStore) {
    val context = LocalContext.current
    val isRunning by ProxyService.isRunning.collectAsStateWithLifecycle()
    val isVerifiedRunning by ProxyService.isVerifiedRunning.collectAsStateWithLifecycle()
    val stateEpoch by ProxyService.stateEpoch.collectAsStateWithLifecycle()

    val isReady by settingsStore.isReady.collectAsStateWithLifecycle(initialValue = false)

    // Settings
    val savedPort by settingsStore.port.collectAsStateWithLifecycle(initialValue = "1443")
    val savedBindIp by settingsStore.bindIp.collectAsStateWithLifecycle(initialValue = "127.0.0.1")
    val savedCfEnabled by settingsStore.cfproxyEnabled.collectAsStateWithLifecycle(initialValue = true)
    val savedPoolSize by settingsStore.poolSize.collectAsStateWithLifecycle(initialValue = 4)
    val savedSecretKey by settingsStore.secretKey.collectAsStateWithLifecycle(initialValue = "LOADING")

    val scope = rememberCoroutineScope()
    val currentVersion = remember { "v${BuildConfig.VERSION_NAME.removePrefix("v")}" }

    if (!isReady || savedSecretKey == "LOADING") {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(24.dp),
                strokeWidth = 2.dp
            )
        }
        return
    }

    // Auto-generate secret if empty
    LaunchedEffect(savedSecretKey) {
        if (savedSecretKey == "") {
            val bytes = ByteArray(16)
            java.security.SecureRandom().nextBytes(bytes)
            val generated = bytes.joinToString("") { "%02x".format(it) }
            scope.launch { settingsStore.saveSecretKey(generated) }
        }
    }

    var isStarting by remember { mutableStateOf(false) }
    val statusText = when {
        isVerifiedRunning -> stringResource(R.string.status_connected)
        isStarting || isRunning -> stringResource(R.string.status_connecting)
        else -> stringResource(R.string.status_disconnected)
    }

    // stateEpoch: провалившийся старт не меняет isRunning, и без него кнопка
    // залипала в «Подключение…».
    LaunchedEffect(isRunning, isVerifiedRunning, stateEpoch) {
        if (isVerifiedRunning || !isRunning) {
            isStarting = false
        }
    }

    val port = savedPort.toIntOrNull() ?: 1443
    val secretForUrl = remember(savedSecretKey) {
        val raw = savedSecretKey.trim()
        if (raw.isNotEmpty() && raw != "LOADING") raw else "00000000000000000000000000000000"
    }
    val bindIp = savedBindIp.trim().takeIf { it.isNotEmpty() } ?: "127.0.0.1"
    val proxyUrl = "https://t.me/proxy?server=$bindIp&port=$port&secret=dd$secretForUrl"
    
    val primary = Color(0xFF2AABEE)
    val secondary = Color(0xFFABB8C5)
    val card = CardDefaults.cardColors(
        containerColor = Color(0xFF17212B),
        contentColor = Color.White
    )
    val clipboard = LocalClipboardManager.current
    val canApply = savedSecretKey.length == 32
    val hostForLink = if (bindIp == "0.0.0.0" || bindIp == "::") "127.0.0.1" else bindIp
    val link = Uri.parse(proxyUrl).buildUpon().clearQuery()
        .appendQueryParameter("server", hostForLink)
        .appendQueryParameter("port", port.toString())
        .appendQueryParameter("secret", "dd" + secretForUrl)
        .build().toString()

    Column(
        modifier = Modifier.fillMaxSize()
            .background(Color(0xFF0E1621))
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Image(painterResource(R.drawable.ic_go_dashboard_logo), null, Modifier.size(44.dp))
            Column {
                Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleLarge, color = Color.White)
                Text("Go · " + currentVersion, color = secondary, style = MaterialTheme.typography.bodySmall)
            }
        }

        Card(colors = card, modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    val dot = if (isVerifiedRunning) Color(0xFF00E676) else if (isStarting) primary else Color(0xFFFF5252)
                    Box(Modifier.size(9.dp).background(dot, CircleShape))
                    Text(statusText, style = MaterialTheme.typography.titleMedium)
                }
                Text("$hostForLink:$port", color = secondary)
            }
        }

        Button(
            onClick = {
                if (isRunning || isStarting) {
                    ProxyController.stop(context)
                } else {
                    isStarting = true
                    scope.launch {
                        try {
                            if (!ProxyController.startFromSavedSettings(context, showInvalidPortToast = true)) {
                                isStarting = false
                            }
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            isStarting = false
                            android.util.Log.w("TgWsProxy", "Unable to start proxy", e)
                        }
                    }
                }
            },
            enabled = !isStarting,
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isRunning) Color(0xFFB32636) else primary,
                contentColor = if (isRunning) Color.White else Color(0xFF0E1621)
            ),
            modifier = Modifier.fillMaxWidth().heightIn(min = 54.dp)
        ) {
            Text(stringResource(if (isRunning) R.string.dashboard_stop else R.string.dashboard_start))
        }

        OutlinedButton(
            onClick = { applyToTelegramPackages(context, link) },
            enabled = canApply,
            colors = ButtonDefaults.outlinedButtonColors(contentColor = primary),
            modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)
        ) {
            Text(stringResource(R.string.apply_in_telegram))
        }

        Card(colors = card, modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.settings), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.pool_short, savedPoolSize) + " · " +
                    stringResource(if (savedCfEnabled) R.string.dashboard_cf_on else R.string.dashboard_cf_off),
                    color = secondary)
                OutlinedButton(
                    enabled = canApply,
                    onClick = { clipboard.setText(AnnotatedString(link)) },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = primary)
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.copy))
                }
            }
        }
    }
}

private val telegramPackages = listOf(
    "org.telegram.messenger",
    "com.radolyn.ayugram",
    "com.exteragram.messenger",
    "org.telegram.plus",
    "ir.ilmili.telegraph",
    "org.telegram.BifToGram",
    "tw.nekomimi.nekogram",
    "xyz.nextalone.nagram",
    "uz.unnarsx.cherrygram",
    "org.telegram.mdgram",
    "org.forkclient.messenger.beta",
    "app.nicegram",
    "top.qwq2333.nullgram",
    "com.iMe.android",
    "ru.dahl.messenger",
    "com.scriptsaz.litegram",
    "org.thunderdog.challegram"
)

private fun applyToTelegramPackages(context: Context, url: String) {
    val pm = context.packageManager
    val availablePackages = telegramPackages.filter {
        try {
            pm.getPackageInfo(it, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    if (availablePackages.isEmpty()) {
        Toast.makeText(context, "Клиенты не найдены", Toast.LENGTH_SHORT).show()
        return
    }

    val targetedIntents = availablePackages.map { pkg ->
        Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
            setPackage(pkg)
        }
    }

    if (targetedIntents.size == 1) {
        val intent = targetedIntents.first().apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            context.startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(context, "Ошибка при открытии клиента", Toast.LENGTH_SHORT).show()
        }
    } else {
        val chooserIntent = Intent.createChooser(targetedIntents.first(), "Выберите клиент")
        chooserIntent.putExtra(Intent.EXTRA_INITIAL_INTENTS, targetedIntents.drop(1).toTypedArray())
        chooserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            context.startActivity(chooserIntent)
        } catch (e: Exception) {
            Toast.makeText(context, "Ошибка при выборе клиента", Toast.LENGTH_SHORT).show()
        }
    }
}
