package org.amnezia.vpn.protocol.wireguard

import android.net.VpnService.Builder
import android.os.PowerManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.amnezia.awg.GoBackend
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.VpnException
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.util.LibraryLoader.loadSharedLibrary
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.asSequence
import org.amnezia.vpn.util.net.InetEndpoint
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.parseInetAddress
import org.amnezia.vpn.util.optStringOrNull
import org.json.JSONObject
import kotlin.math.max

private const val TAG = "Wireguard"
private const val WATCHDOG_CHECK_INTERVAL_MS = 30_000L
private const val WAKE_LOCK_TAG = "amnezia:wireguard-tunnel"

// WireGuard core defaults, used when the tunnel does not report its own timings.
private const val DEFAULT_REJECT_AFTER_TIME_SEC = 180L
private const val DEFAULT_KEEPALIVE_TIMEOUT_SEC = 10L
private const val DEFAULT_REKEY_TIMEOUT_SEC = 5L
private const val DEFAULT_REKEY_AFTER_TIME_SEC = 120L

private val GO_DURATION = Regex("""(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)""")

/**
 * Parses a Go duration string ("3m0s", "5s", "1h30m0s") into seconds.
 */
internal fun parseGoDurationSeconds(value: String?): Long? {
    if (value.isNullOrBlank()) return null
    var seconds = 0.0
    var found = false
    for (match in GO_DURATION.findAll(value)) {
        val amount = match.groupValues[1].toDouble()
        seconds += when (match.groupValues[2]) {
            "ns" -> amount / 1_000_000_000
            "us", "µs" -> amount / 1_000_000
            "ms" -> amount / 1_000
            "s" -> amount
            "m" -> amount * 60
            "h" -> amount * 3600
            else -> 0.0
        }
        found = true
    }
    return if (found) seconds.toLong() else null
}

/**
 * The peer session is stale when the core stops expecting a fresh handshake.
 *
 * Mirrors keyRefreshTimeoutReceiving() of the amneziawg-go core and never drops below the rekey
 * interval, so a healthy tunnel, which rekeys on its own, is not recreated.
 */
internal fun staleTunnelThresholdSec(
    rejectAfterTimeSec: Long?,
    keepaliveTimeoutSec: Long?,
    rekeyTimeoutSec: Long?,
    rekeyAfterTimeSec: Long?
): Long {
    val rejectAfterTime = rejectAfterTimeSec ?: DEFAULT_REJECT_AFTER_TIME_SEC
    val keepaliveTimeout = keepaliveTimeoutSec ?: DEFAULT_KEEPALIVE_TIMEOUT_SEC
    val rekeyTimeout = rekeyTimeoutSec ?: DEFAULT_REKEY_TIMEOUT_SEC
    val rekeyAfterTime = rekeyAfterTimeSec ?: DEFAULT_REKEY_AFTER_TIME_SEC
    return max(max(0L, rejectAfterTime - keepaliveTimeout - rekeyTimeout), rekeyAfterTime + keepaliveTimeout)
}

open class Wireguard : Protocol() {

    private var tunnelHandle: Int = -1
    private var config: WireguardConfig? = null // save config for reconnect
    protected open val ifName: String = "amn0"
    private lateinit var scope: CoroutineScope
    private var statusJob: Job? = null
    private var watchdogJob: Job? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override val statistics: Statistics
        get() {
            if (tunnelHandle == -1) return Statistics.EMPTY_STATISTICS
            val config = GoBackend.awgGetConfig(tunnelHandle) ?: return Statistics.EMPTY_STATISTICS
            return Statistics.build {
                var optsCount = 0
                config.splitToSequence("\n").forEach { line ->
                    with(line) {
                        when {
                            startsWith("rx_bytes=") -> setRxBytes(substring(9).toLong()).also { ++optsCount }
                            startsWith("tx_bytes=") -> setTxBytes(substring(9).toLong()).also { ++optsCount }
                            else -> {}
                        }
                    }
                    if (optsCount == 2) return@forEach
                }
            }
        }

    override fun internalInit() {
        if (!isInitialized) loadSharedLibrary(context, "wg-go")
        if (this::scope.isInitialized) {
            scope.cancel()
        }
        scope = CoroutineScope(Dispatchers.IO)
    }

    override suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        val wireguardConfig = parseConfig(config)
        start(wireguardConfig, vpnBuilder, protect)
        this.config = wireguardConfig
    }

    protected open fun parseConfig(config: JSONObject): WireguardConfig {
        val configData = config.getJSONObject("wireguard_config_data")
        return WireguardConfig.build {
            configWireguard(config, configData)
            configSplitTunneling(config)
            configAppSplitTunneling(config)
        }
    }

    protected fun WireguardConfig.Builder.configWireguard(config: JSONObject, configData: JSONObject) {
        configData.getString("client_ip").split(",").map { address ->
            InetNetwork.parse(address.trim())
        }.forEach(::addAddress)

        config.optStringOrNull("dns1")?.let { dns ->
            addDnsServer(parseInetAddress(dns.trim()))
        }

        config.optStringOrNull("dns2")?.let { dns ->
            addDnsServer(parseInetAddress(dns.trim()))
        }

        val defRoutes = hashSetOf(
            InetNetwork("0.0.0.0", 0),
            InetNetwork("::", 0)
        )
        val routes = hashSetOf<InetNetwork>()
        configData.getJSONArray("allowed_ips").asSequence<String>().map { route ->
            InetNetwork.parse(route.trim())
        }.forEach(routes::add)
        // if the allowed IPs list contains at least one non-default route, disable global split tunneling
        if (routes.any { it !in defRoutes }) disableSplitTunneling()
        addRoutes(routes)

        configData.optStringOrNull("mtu")?.let { setMtu(it.toInt()) }

        val host = configData.getString("hostName").let { parseInetAddress(it.trim()) }
        val port = configData.getInt("port")
        setEndpoint(InetEndpoint(host, port))

        if (configData.optBoolean("isObfuscationEnabled")) {
            setUseProtocolExtension(true)
            configExtensionParameters(configData)
        }

        configData.optStringOrNull("persistent_keep_alive")?.let { setPersistentKeepalive(it) }
        configData.getString("client_priv_key").let { setPrivateKeyHex(it.base64ToHex()) }
        configData.getString("server_pub_key").let { setPublicKeyHex(it.base64ToHex()) }
        configData.optStringOrNull("psk_key")?.let { setPreSharedKeyHex(it.base64ToHex()) }
    }

    protected fun WireguardConfig.Builder.configExtensionParameters(configData: JSONObject) {
        configData.optStringOrNull("Jc")?.let { setJc(it.toInt()) }
        configData.optStringOrNull("Jmin")?.let { setJmin(it.toInt()) }
        configData.optStringOrNull("Jmax")?.let { setJmax(it.toInt()) }
        configData.optStringOrNull("S1")?.let { setS1(it.toInt()) }
        configData.optStringOrNull("S2")?.let { setS2(it.toInt()) }
        configData.optStringOrNull("S3")?.let { setS3(it.toInt()) }
        configData.optStringOrNull("S4")?.let { setS4(it.toInt()) }
        configData.optStringOrNull("H1")?.trim()?.let { if (it.isNotEmpty()) setH1(it) }
        configData.optStringOrNull("H2")?.trim()?.let { if (it.isNotEmpty()) setH2(it) }
        configData.optStringOrNull("H3")?.trim()?.let { if (it.isNotEmpty()) setH3(it) }
        configData.optStringOrNull("H4")?.trim()?.let { if (it.isNotEmpty()) setH4(it) }
        configData.optStringOrNull("I1")?.let { setI1(it) }
        configData.optStringOrNull("I2")?.let { setI2(it) }
        configData.optStringOrNull("I3")?.let { setI3(it) }
        configData.optStringOrNull("I4")?.let { setI4(it) }
        configData.optStringOrNull("I5")?.let { setI5(it) }
        configData.optStringOrNull("HeaderProtectionKey")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setHeaderProtectionKey(it.base64ToHex()) }
        configData.optStringOrNull("ContentPaddingAddition")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setContentPaddingAddition(it) }
        configData.optStringOrNull("RekeyAfterTime")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRekeyAfterTime(it) }
        configData.optStringOrNull("RekeyTimeout")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRekeyTimeout(it) }
        configData.optStringOrNull("RejectAfterTime")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRejectAfterTime(it) }
        configData.optStringOrNull("KeepaliveTimeout")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setKeepaliveTimeout(it) }
        configData.optStringOrNull("MaxHandshakeAttempts")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setMaxHandshakeAttempts(it) }
        configData.optStringOrNull("RandomTrailers")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRandomTrailers(it) }
        configData.optStringOrNull("DisableCookies")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setDisableCookies(it) }
    }

    private fun start(
        config: WireguardConfig,
        vpnBuilder: Builder,
        protect: (Int) -> Boolean,
        stopExistingVpn: Boolean = false
    ) {
        if (!stopExistingVpn && tunnelHandle != -1) {
            Log.w(TAG, "Tunnel already up")
            return
        }

        buildVpnInterface(config, vpnBuilder)

        vpnBuilder.establish().use { tunFd ->
            if (stopExistingVpn && tunnelHandle != -1) {
                turnOffVpn()
            }
            if (tunFd == null) {
                throw VpnStartException("Create VPN interface: permission not granted or revoked")
            }
            Log.i(TAG, "awg-go backend ${GoBackend.awgVersion()}")
            tunnelHandle = GoBackend.awgTurnOn(ifName, tunFd.detachFd(), config.toWgUserspaceString())
        }

        if (tunnelHandle < 0) {
            tunnelHandle = -1
            throw VpnStartException("Wireguard tunnel creation error")
        }

        if (!protect(GoBackend.awgGetSocketV4(tunnelHandle)) || !protect(GoBackend.awgGetSocketV6(tunnelHandle))) {
            GoBackend.awgTurnOff(tunnelHandle)
            tunnelHandle = -1
            throw VpnStartException("Protect VPN interface: permission not granted or revoked")
        }
        launchStatusJob()
        acquireWakeLock()
        launchWatchdog()
    }

    private fun launchStatusJob() {
        Log.d(TAG, "Launch status job")
        statusJob = scope.launch {
            while (true) {
                val lastHandshake = getLastHandshake()
                Log.v(TAG, "lastHandshake=$lastHandshake")
                if (lastHandshake == 0L) {
                    delay(1000)
                    continue
                }
                if (lastHandshake == -2L || lastHandshake > 0L) state.value = CONNECTED
                else if (lastHandshake == -1L) state.value = DISCONNECTED
                statusJob = null
                break
            }
        }
    }

    private fun getLastHandshake(): Long {
        if (tunnelHandle == -1) {
            Log.e(TAG, "Trying to get config of a non-existent tunnel")
            return -1
        }
        val config = GoBackend.awgGetConfig(tunnelHandle)
        if (config == null) {
            Log.e(TAG, "Failed to get tunnel config")
            return -2
        }
        val lastHandshake = config.lines().find { it.startsWith("last_handshake_time_sec=") }?.substring(24)?.toLong()
        if (lastHandshake == null) {
            Log.e(TAG, "Failed to get last_handshake_time_sec")
            return -2
        }
        return lastHandshake
    }

    /**
     * Recreates the tunnel when the peer session went stale.
     *
     * While the device is asleep the core timers do not run, so no keepalive is sent and the peer
     * session expires. Once the device wakes up, the core retries the handshake and clears the
     * cached source address on every attempt, but the mobile operator may have moved the tunnel to
     * a different NAT port, in which case the handshake never reaches the server and the core
     * gives up ("Handshake did not complete after N attempts, giving up"). The peer is then left
     * without a keypair and drops every packet, so the tunnel stays dead until it is recreated.
     * Recreating it opens a new socket, which restores the session.
     */
    private fun launchWatchdog() {
        stopWatchdog()
        watchdogJob = scope.launch {
            while (true) {
                delay(WATCHDOG_CHECK_INTERVAL_MS)
                try {
                    recreateStaleTunnel()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e(TAG, "Tunnel watchdog failed: ${e.message}")
                }
            }
        }
    }

    private fun stopWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = null
    }

    private fun recreateStaleTunnel() {
        if (!isTunnelStale()) return
        Log.w(TAG, "Tunnel handshake is stale, recreating the tunnel")
        onTunnelStale()
    }

    private fun isTunnelStale(): Boolean {
        val handshake = getLastHandshake()
        if (handshake <= 0) return false
        val ageSec = System.currentTimeMillis() / 1000 - handshake
        return ageSec > currentStaleThresholdSec()
    }

    private fun currentStaleThresholdSec(): Long {
        val config = if (tunnelHandle == -1) null else GoBackend.awgGetConfig(tunnelHandle)
        return staleTunnelThresholdSec(
            parseGoDurationSeconds(configValue(config, "reject_after_time")),
            parseGoDurationSeconds(configValue(config, "keepalive_timeout")),
            parseGoDurationSeconds(configValue(config, "rekey_timeout")),
            parseGoDurationSeconds(configValue(config, "rekey_after_time"))
        )
    }

    private fun configValue(config: String?, key: String): String? =
        config?.lines()?.firstOrNull { it.startsWith("$key=") }?.substringAfter('=')

    /**
     * Keeps the CPU awake while the tunnel is up, so the core timers keep sending keepalives and
     * can re-handshake on their own after the device wakes up.
     */
    private fun acquireWakeLock() {
        if (wakeLock != null) return
        val powerManager = context.getSystemService(PowerManager::class.java) ?: return
        wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKE_LOCK_TAG).apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { lock -> if (lock.isHeld) lock.release() }
        wakeLock = null
    }

    private fun turnOffVpn() {
        stopWatchdog()
        releaseWakeLock()
        statusJob?.cancel()
        statusJob = null
        val handleToClose = tunnelHandle
        tunnelHandle = -1
        GoBackend.awgTurnOff(handleToClose)
    }

    override fun stopVpn() {
        if (tunnelHandle == -1) {
            Log.w(TAG, "Tunnel already down")
            return
        }
        turnOffVpn()
        state.value = DISCONNECTED
    }

    override fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean) {
        val config = this.config ?: throw VpnException("Reconnect config is empty")
        start(config, vpnBuilder, protect, true)
    }
}
