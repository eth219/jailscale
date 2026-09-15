package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.hub.dns.DnsQuery;
import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * ARCHITECTURE.md §13.5: the nodes as witnesses. A standby that has lost its primary asks its
 * nodes for a proof the primary answers and a node cannot forge; none means the primary is dead
 * and the standby promotes itself, one means a partition and it does not. Epochs then settle
 * which of two primaries stands down when they meet.
 */
@Timeout(120)
class AutoPromoteTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub a;
    private Hub b;
    private Daemon alice;
    private ServerSocket app;
    private int portA;
    private int portB;
    private HubConfig cfgA;
    private HubConfig cfgB;

    @BeforeEach
    void quick() {
        Hub.promoteAfterMs = 1500;
        Hub.witnessWindowMs = 1500;
        Hub.autoPromoteIntervalMs = 0;
    }

    @AfterEach
    void stop() throws Exception {
        Hub.promoteAfterMs = 30_000;
        Hub.witnessWindowMs = 10_000;
        Hub.autoPromoteIntervalMs = 10 * 60_000;
        for (AutoCloseable c : new AutoCloseable[] {alice, b, a, app}) {
            if (c != null) {
                c.close();
            }
        }
    }

    private static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return s.getLocalPort();
        }
    }

    private interface Check {
        boolean ok() throws Exception;
    }

    private static void waitFor(String what, Check c) throws Exception {
        long deadline = System.currentTimeMillis() + 30_000;
        while (System.currentTimeMillis() < deadline) {
            if (c.ok()) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError(what);
    }

    /** Primary A with alice on it, standby B with alice's relay connection: the witness is in place. */
    private void pair() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("ap");
        portA = freePort();
        portB = freePort();
        // Both units name the other (§13.5): the role file, not the flag, says which is which.
        cfgA = HubConfig.withCert(URI.create("https://hub.test:" + portA), root.resolve("a"), "127.0.0.1", portA,
            CERT, KEY, false, HubConfig.POLICY_MEMBERS, true, "hub.test").withAdvertise("203.0.113.1");
        a = new Hub(cfgA);
        a.relayEndpointOverride = "127.0.0.1:" + portA;
        a.start();
        app = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        alice = new Daemon(NodeConfig.in(root.resolve("alice")));
        alice.start();
        Path aliceSock = root.resolve("alice/jailscale.sock");
        JsonObject inv = Ipc.call(root.resolve("a/jailhub.sock"), JsonObject.builder().put("cmd", "invite-create").put("user", "alice").build());
        JsonObject up = Ipc.call(aliceSock, JsonObject.builder().put("cmd", "up").put("invite", inv.string("url")).put("addr", "127.0.0.1")
            .put("caFile", CERT.toString()).build());
        assertTrue(up.optBool("ok", false), up.toString());
        assertTrue(Ipc.call(aliceSock, JsonObject.builder().put("cmd", "open").put("port", app.getLocalPort()).put("name", "web").build()).optBool("ok", false));

        cfgB = HubConfig.withCert(URI.create("https://hub.test:" + portB), root.resolve("b"), "127.0.0.1", portB,
            null, null, false, HubConfig.POLICY_MEMBERS, true, "hub.test")
            .withPeer(URI.create("https://hub.test:" + portA), CERT, "127.0.0.1").withAdvertise("203.0.113.2");
        Files.createDirectories(root.resolve("b"));
        Files.copy(root.resolve("a/hub.key"), root.resolve("b/hub.key"), StandardCopyOption.REPLACE_EXISTING);
        b = new Hub(cfgB);
        b.relayEndpointOverride = "127.0.0.1:" + portB;
        b.start();
        waitFor("standby never synced", () -> b.peerClient().isSynced());
        waitFor("alice never opened a relay connection to the standby", () -> alice.connectedRelays().contains("127.0.0.1:" + portB));
        assertEquals("standby", b.role());
        assertEquals(1, a.epoch());
        assertEquals(0, b.epoch());
        assertTrue(b.autoPromote(), "registration is by invite here, so automatic promotion is on by default");
    }

    @Test
    void aDeadPrimaryIsReplacedWithoutAPerson() throws Exception {
        pair();
        a.close();
        a = null;
        waitFor("the standby never promoted itself", () -> "primary".equals(b.role()));
        assertEquals(1, b.epoch(), "one promotion: epoch 0 to 1");
        assertEquals(List.of("203.0.113.2"), DnsQuery.a("127.0.0.1", b.dnsPort(), "hub.test", 2000), "and the apex is now the promoted host");

        // The old primary comes back, its role file still saying primary at epoch 1, now naming B
        // as its peer: two primaries meet, epochs tie at 1, and the lower address wins, which is
        // 203.0.113.1... so A would stay primary. Push B one epoch ahead first, as a second
        // failover in the field would have, and watch A stand down.
        b.roleFile().promote(); // epoch 2 (test shortcut; a real second promotion does the same)
        a = new Hub(cfgA.withPeer(URI.create("https://hub.test:" + portB), CERT, "127.0.0.1"));
        a.relayEndpointOverride = "127.0.0.1:" + portA;
        a.start();
        assertEquals("primary", a.role(), "it starts as what its role file says");
        waitFor("the returning primary never stood down", () -> "standby".equals(a.role()));
        assertEquals(2, a.epoch(), "its epoch follows the one it stood down before");
        waitFor("the demoted hub never synced from the new primary", () -> a.peerClient() != null && a.peerClient().isSynced());
        assertTrue(a.store().node(alice.machineKey()) != null);
        assertEquals("primary", b.role());
    }

    @Test
    void aPartitionIsNotADeathWhenANodeCanStillReachThePrimary() throws Exception {
        pair();
        // Cut only the hub-to-hub channel. alice still reaches A on her control connection, so
        // B's probe comes back with A's proof, and B stays what it is however long this lasts.
        b.peerClient().suspend(true);
        waitFor("the channel did not drop", () -> !b.peerClient().isConnected());
        Thread.sleep(Hub.promoteAfterMs + Hub.witnessWindowMs + 2500);
        assertEquals("standby", b.role(), "a reachable primary is not replaced");
        assertEquals("primary", a.role());
        assertEquals(1, a.epoch());
        b.peerClient().suspend(false);
        waitFor("the channel never came back", () -> b.peerClient().isSynced());
    }

    @Test
    void withNoWitnessTheDecisionStaysAPersons() throws Exception {
        pair();
        alice.close();
        alice = null;
        waitFor("alice's relay connection did not go", () -> b.registry().size() == 0);
        a.close();
        a = null;
        Thread.sleep(Hub.promoteAfterMs + Hub.witnessWindowMs + 2500);
        assertEquals("standby", b.role(), "nobody to ask, so nobody promotes");
        assertFalse(b.peerClient().isConnected());
    }
}
