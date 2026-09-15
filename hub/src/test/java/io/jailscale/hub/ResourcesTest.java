package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Uptime counts from when the hub was constructed, not from whenever this class happened to be
 * initialised. The live hub reported 0s of uptime ninety seconds after a restart, because the
 * first request for its page was what initialised {@link Resources}.
 */
class ResourcesTest {

    @Test
    void uptimeIsMeasuredFromTheMarkedStart() {
        Resources.markStarted(System.currentTimeMillis() - 5_000);
        long up = Resources.uptimeMillis();
        assertTrue(up >= 5_000 && up < 6_000, "uptime " + up + " ms, expected about 5 s");
    }
}
