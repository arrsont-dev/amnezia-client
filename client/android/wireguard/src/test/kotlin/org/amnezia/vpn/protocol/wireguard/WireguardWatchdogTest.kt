package org.amnezia.vpn.protocol.wireguard

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class WireguardWatchdogTest {

    @Test
    fun parsesGoDurations() {
        assertEquals(180L, parseGoDurationSeconds("3m0s")!!)
        assertEquals(5L, parseGoDurationSeconds("5s")!!)
        assertEquals(90L, parseGoDurationSeconds("1m30s")!!)
        assertEquals(5400L, parseGoDurationSeconds("1h30m0s")!!)
        assertEquals(0L, parseGoDurationSeconds("250ms")!!)
    }

    @Test
    fun ignoresUnparsableDurations() {
        assertNull(parseGoDurationSeconds(null))
        assertNull(parseGoDurationSeconds(""))
        assertNull(parseGoDurationSeconds("never"))
    }

    @Test
    fun usesCoreDefaultsWhenTimingsAreMissing() {
        assertEquals(165L, staleTunnelThresholdSec(null, null, null, null))
    }

    @Test
    fun mirrorsCoreHandshakeExpectation() {
        // reject_after_time - keepalive_timeout - rekey_timeout
        assertEquals(165L, staleTunnelThresholdSec(180L, 10L, 5L, 120L))
    }

    @Test
    fun neverRecreatesAHealthyTunnel() {
        // the threshold has to stay above the rekey interval, otherwise the watchdog
        // would recreate a healthy tunnel
        assertEquals(130L, staleTunnelThresholdSec(60L, 10L, 5L, 120L))
    }
}
