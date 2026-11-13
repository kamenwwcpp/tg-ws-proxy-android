package org.flowseal.tgwsproxy.core

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

class NativeProxyRunner(private val context: Context) {

    @Volatile private var process: Process? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private var logListener: ((String) -> Unit)? = null
    private var exitListener: (() -> Unit)? = null

    companion object {
        private const val TAG = "NativeProxyRunner"
        private const val LIB_NAME = "libtgproxy.so"
    }

    fun setLogListener(listener: ((String) -> Unit)?) {
        this.logListener = listener
    }

    fun setExitListener(listener: (() -> Unit)?) {
        exitListener = listener
    }

    fun start(
        port: Int = 1443,
        secret: String = "",
        domain: String = "google.com",
        cfWorker: String = "",
        cfDomains: String = "",
        disableFakeTls: Boolean = false
    ): Boolean {
        if (isActive()) {
            Log.w(TAG, "Proxy is already running")
            return true
        }

        val nativeLibDir = context.applicationInfo.nativeLibraryDir
        val libFile = File(nativeLibDir, LIB_NAME)

        if (!libFile.exists()) {
            val errMsg = "Native binary not found at: ${libFile.absolutePath}"
            Log.e(TAG, errMsg)
            logListener?.invoke("ОШИБКА: $errMsg")
            return false
        }

        val cmd = mutableListOf<String>().apply {
            add(libFile.absolutePath)
            add("-listen")
            add("127.0.0.1:$port")
            if (secret.isNotBlank()) {
                add("-secret")
                add(secret)
            }
            if (domain.isNotBlank()) {
                add("-domain")
                add(domain)
            }
            if (cfWorker.isNotBlank()) {
                add("-cf-worker")
                add(cfWorker)
            }
            if (cfDomains.isNotBlank()) {
                add("-cf-domains")
                add(cfDomains)
            }
            if (disableFakeTls || secret.startsWith("dd")) {
                add("-no-faketls")
            }
            if (!org.flowseal.tgwsproxy.util.SettingsManager.isCloudflareFallback(context)) add("-no-cf")
            add("-stats-interval")
            add("5")
        }

        try {
            Log.i(TAG, "Starting native proxy")
            logListener?.invoke("Запуск ядра: 127.0.0.1:$port (Fake TLS SNI: $domain)")

            val pb = ProcessBuilder(cmd)
            pb.redirectErrorStream(true)
            val startedProcess = pb.start()
            process = startedProcess

            Thread {
                try {
                    BufferedReader(InputStreamReader(startedProcess.inputStream)).use { reader ->
                        while (process === startedProcess) {
                            val line = reader.readLine() ?: break
                            if (process !== startedProcess) break
                            Log.d(TAG, line)
                            logListener?.invoke(line)
                        }
                    }
                } catch (e: Exception) {
                    if (process === startedProcess) {
                        Log.e(TAG, "Log stream read exception", e)
                    }
                }
            }.start()

            Thread {
                val exitCode = startedProcess.waitFor()
                mainHandler.post {
                    if (process === startedProcess) {
                        process = null
                        Log.w(TAG, "Native proxy exited with code $exitCode")
                        exitListener?.invoke()
                    }
                }
            }.start()

            return true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to launch native proxy process", e)
            stop()
            logListener?.invoke("Ошибка запуска: ${e.message}")
            return false
        }
    }

    fun stop() {
        val stoppedProcess = process ?: return
        process = null

        Log.i(TAG, "Stopping native proxy process")
        logListener?.invoke("Остановка ядра...")

        try {
            stoppedProcess.destroy()
            stoppedProcess.waitFor()
        } catch (e: Exception) {
            Log.e(TAG, "Error waiting for process destruction", e)
        }
    }

    fun isActive(): Boolean {
        val currentProcess = process ?: return false
        return try {
            currentProcess.exitValue()
            false
        } catch (_: IllegalThreadStateException) {
            true
        }
    }
}
