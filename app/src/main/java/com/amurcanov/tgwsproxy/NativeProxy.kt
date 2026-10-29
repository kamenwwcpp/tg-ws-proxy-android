package com.amurcanov.tgwsproxy

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer

interface ProxyLibrary : Library {
    companion object {
        val INSTANCE = Native.load("tgwsproxy", ProxyLibrary::class.java) as ProxyLibrary
    }

    fun StartProxy(host: String, port: Int, dcIps: String, secret: String, verbose: Int): Int
    fun StopProxy(): Int
    fun NetworkChanged(): Int
    fun SetNetworkState(available: Int, kind: Int): Int
    fun SetPoolSize(size: Int)
    fun SetBufferSizeKb(kb: Int)
    fun SetCfProxyCacheDir(cacheDir: String)
    fun SetCfProxyConfig(enabled: Int, priority: Int, userDomain: String)
    fun SetCfWorkerDomains(domains: String)
    fun SetFakeTlsDomain(domain: String)
    fun SetDisableSecure(v: Int)
    fun SetForceTestDc(v: Int)
    fun SetProxyProtocol(v: Int)
    fun GetSecretWithPrefix(): Pointer?
    fun GetStats(): Pointer?
    fun FreeString(p: Pointer)
}

object NativeProxy {
    fun startProxy(host: String, port: Int, dcIps: String, secret: String, verbose: Int): Int {
        return ProxyLibrary.INSTANCE.StartProxy(host, port, dcIps, secret, verbose)
    }

    fun stopProxy(): Int {
        return ProxyLibrary.INSTANCE.StopProxy()
    }

    fun networkChanged(): Int {
        return ProxyLibrary.INSTANCE.NetworkChanged()
    }

    fun setNetworkState(available: Boolean, kind: Int): Int {
        return ProxyLibrary.INSTANCE.SetNetworkState(if (available) 1 else 0, kind)
    }

    fun setPoolSize(size: Int) {
        ProxyLibrary.INSTANCE.SetPoolSize(size)
    }

    fun setBufferSizeKb(kb: Int) {
        ProxyLibrary.INSTANCE.SetBufferSizeKb(kb)
    }

    fun setCfProxyCacheDir(cacheDir: String) {
        ProxyLibrary.INSTANCE.SetCfProxyCacheDir(cacheDir)
    }

    fun setCfProxyConfig(enabled: Boolean, priority: Boolean, userDomain: String) {
        ProxyLibrary.INSTANCE.SetCfProxyConfig(
            if (enabled) 1 else 0,
            if (priority) 1 else 0,
            userDomain
        )
    }

    fun setCfWorkerDomains(domains: String) {
        ProxyLibrary.INSTANCE.SetCfWorkerDomains(domains)
    }

    fun setFakeTlsDomain(domain: String) {
        ProxyLibrary.INSTANCE.SetFakeTlsDomain(domain)
    }

    fun setDisableSecure(v: Boolean) {
        ProxyLibrary.INSTANCE.SetDisableSecure(if (v) 1 else 0)
    }

    fun setForceTestDc(v: Boolean) {
        ProxyLibrary.INSTANCE.SetForceTestDc(if (v) 1 else 0)
    }

    fun setProxyProtocol(v: Boolean) {
        ProxyLibrary.INSTANCE.SetProxyProtocol(if (v) 1 else 0)
    }

    /** Returns the full secret with correct prefix (dd or ee+domain_hex) */
    fun getSecretWithPrefix(): String? {
        val ptr = ProxyLibrary.INSTANCE.GetSecretWithPrefix() ?: return null
        val res = ptr.getString(0)
        ProxyLibrary.INSTANCE.FreeString(ptr)
        return res
    }

    fun getStats(): String? {
        val ptr = ProxyLibrary.INSTANCE.GetStats() ?: return null
        val res = ptr.getString(0)
        ProxyLibrary.INSTANCE.FreeString(ptr)
        return res
    }
}
