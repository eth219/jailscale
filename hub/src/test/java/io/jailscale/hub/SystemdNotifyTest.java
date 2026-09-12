package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Readiness reporting is opt-in (ARCHITECTURE.md §13), so the thing worth pinning is that a hub
 * nobody asked stays silent: every default deployment runs this code, and the only correct amount
 * of work for it to do there is none.
 */
class SystemdNotifyTest {

    @Test
    void aHubNobodyAskedSaysNothing() {
        assertFalse(SystemdNotify.asked(null), "no NOTIFY_SOCKET is the ordinary case");
        assertFalse(SystemdNotify.asked(""), "an empty NOTIFY_SOCKET is a unit that does not want one");
        assertFalse(SystemdNotify.asked("   "));
    }

    @Test
    void aSocketToAnswerIsAnswered() {
        assertTrue(SystemdNotify.asked("/run/systemd/notify"));
        assertTrue(SystemdNotify.asked("@abstract-socket"), "systemd also hands out abstract sockets");
    }

    @Test
    void readyIsSafeToCallWhenNothingIsListening() {
        // The surefire JVM has no NOTIFY_SOCKET, so this is the path every hub takes: it must
        // return, and it must not throw, whatever the host does or does not have installed.
        SystemdNotify.ready();
    }
}
