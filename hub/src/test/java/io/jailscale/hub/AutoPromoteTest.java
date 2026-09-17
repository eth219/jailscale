package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.hub.dns.DnsQuery;
import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

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

    /**
     * §13.5's timings, shortened so a test does not sit out forty seconds. On the two configs and
     * not on a static: that is #61, and the reason is this class -- three fields set in a
     * {@code @BeforeEach} and put back in an {@code @AfterEach}, correct only for as long as
     * surefire runs one test at a time, and silently wrong for every later test in the JVM if the
     * restore were ever missed.
     */
    private static final HubConfig.Tuning QUICK =
        HubConfig.Tuning.defaults().promoteAfterMs(1500).witnessWindowMs(1500).autoPromoteIntervalMs(0);

    @AfterEach
    void stop() throws Exception {
        for (AutoCloseable c : new AutoCloseable[] {alice, b, a, app}) {
            if (c != null) {
                c.close();
            }
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
        pair(QUICK);
    }

    /** As above, with B's timings given: one test needs an interval nothing can have elapsed against. */
    private void pair(HubConfig.Tuning tuningB) throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("ap");
        portA = TestPorts.reserve();
        // Both units name the other (§13.5): the role file, not the flag, says which is which.
        cfgA = HubConfig.withCert(URI.create("https://hub.test:" + portA), root.resolve("a"), "127.0.0.1", portA,
            CERT, KEY, false, HubConfig.POLICY_MEMBERS, true, "hub.test").withAdvertise("203.0.113.1").withTuning(QUICK);
        a = new Hub(cfgA);
        a.relayEndpointOverride = "127.0.0.1:" + portA;
        a.start();
        app = TestPorts.listen(8);
        alice = new Daemon(NodeConfig.in(root.resolve("alice")));
        alice.start();
        Path aliceSock = root.resolve("alice/jailscale.sock");
        JsonObject inv = Ipc.call(root.resolve("a/jailhub.sock"), JsonObject.builder().put("cmd", "invite-create").put("user", "alice").build());
        JsonObject up = Ipc.call(aliceSock, JsonObject.builder().put("cmd", "up").put("invite", inv.string("url")).put("addr", "127.0.0.1")
            .put("caFile", CERT.toString()).build());
        assertTrue(up.optBool("ok", false), up.toString());
        assertTrue(Ipc.call(aliceSock, JsonObject.builder().put("cmd", "open").put("port", app.getLocalPort()).put("name", "web").build()).optBool("ok", false));

        // Drawn here and not beside portA: TestPorts keeps two of its own callers apart, but a hub
        // binds its DNS pair, /metrics and the plain-HTTP front on port 0, and those draws know
        // nothing of its register. Reserved before A starts, B's number is one of the numbers A
        // could be handed.
        portB = TestPorts.reserve();
        cfgB = HubConfig.withCert(URI.create("https://hub.test:" + portB), root.resolve("b"), "127.0.0.1", portB,
            null, null, false, HubConfig.POLICY_MEMBERS, true, "hub.test")
            .withPeer(URI.create("https://hub.test:" + portA), CERT, "127.0.0.1").withAdvertise("203.0.113.2")
            .withTuning(tuningB);
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
    void theFirstPromotionIsNotHeldBackByAnIntervalNothingHasElapsedAgainst() throws Exception {
        // The rest of this class runs with no interval at all, so the term this asserts is dead in
        // every other test. An interval longer than the monotonic clock has been running is what
        // the default ten minutes looks like to a host that booted nine minutes ago -- the
        // mass-reboot case -- and a hub that has never promoted has no reading to compare against
        // it. Read as a reading, the zero it holds instead blocks the promotion entirely.
        //
        // Given to B at construction rather than set on it afterwards: its configuration is a
        // record, and B has never promoted either way, which is the condition under test.
        //
        // Long.MAX_VALUE and not `Clock.millis() + 60_000`: set before the pair is built, a minute
        // is spent by A starting, alice joining, B starting and two waits that each allow thirty
        // seconds, so on a slow enough runner the interval would have elapsed by the time it
        // mattered and the test would pass while asserting nothing.
        pair(QUICK.autoPromoteIntervalMs(Long.MAX_VALUE));
        a.close();
        a = null;
        waitFor("the standby never promoted itself", () -> "primary".equals(b.role()));
        assertEquals(1, b.epoch(), "one promotion: epoch 0 to 1");
    }

    @Test
    void aNameARelayIsStillServingIsProbedRatherThanCalledNotOpen() throws Exception {
        // §11.3 answers `link not open` for a name nothing here serves, and leaves that verdict out
        // of what `jailscale verify` exits on -- so the test for it has to be "is this node serving
        // the name", not "is the hub it joined connected". A relay serves these names while the
        // primary is away (§13.4), which is exactly the window §11.4 says names change hands in:
        // an all-clear there would be the check silent when it matters most.
        pair();
        Path aliceSock = root.resolve("alice/jailscale.sock");
        a.close();
        a = null;
        waitFor("alice never lost the primary", () -> !alice.isHubConnected());
        assertTrue(alice.connectedRelays().contains("127.0.0.1:" + portB), "the relay is what is still serving");

        JsonObject verified = Ipc.call(aliceSock, JsonObject.builder().put("cmd", "verify").build());
        assertTrue(verified.optBool("ok", false), verified.toString());
        for (Object o : verified.array("results")) {
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> row = (java.util.Map<String, Object>) o;
            assertNotEquals("link not open", row.get("verdict"),
                "a name a relay is serving is not a name nothing serves: " + verified);
        }
        assertEquals(1, verified.integer("checked"), "and it counts as looked at: " + verified);
    }

    @Test
    void whatTheStandingDownPrimaryServedAloneIsReportedAndKept() throws Exception {
        // §13.5: both hubs serve through a partition, so the one that turns out to have the lower
        // epoch may have served joins and claims nobody else saw. Those do not merge when the link
        // heals -- the winner's state replaces this host's entire -- so what it must not do is
        // vanish without a word.
        pair();
        a.close();
        a = null;
        waitFor("the standby never promoted itself", () -> "primary".equals(b.role()));

        // While A is away from B, it serves someone B will never hear about. Written into A's state
        // directory directly, which is what A having served it amounts to by the time it restarts.
        try (Store served = new Store(root.resolve("a"))) {
            served.registerNode("mkey:bob", "bob", "desktop", "linux");
            served.claimName("bobapp", "bob", "mkey:bob", "127.0.0.1:8080");
        }

        b.roleFile().promote(); // as a second failover in the field would, so B outranks A on return
        a = new Hub(cfgA.withPeer(URI.create("https://hub.test:" + portB), CERT, "127.0.0.1"));
        a.relayEndpointOverride = "127.0.0.1:" + portA;
        a.start();
        assertTrue(a.store().node("mkey:bob") != null, "A starts holding what it served");
        waitFor("the returning primary never stood down", () -> "standby".equals(a.role()));
        waitFor("the demoted hub never synced", () -> a.peerClient() != null && a.peerClient().isSynced());

        // Gone from the live state, which is the design: there is no lineage to merge along.
        assertTrue(a.store().node("mkey:bob") == null, "bob does not exist on the primary's state");
        assertFalse(a.store().names().stream().anyMatch(n -> n.name().equals("bobapp")), "nor does the name");

        // But kept where an operator can read it, and it is a snapshot a Store opens.
        Path kept = root.resolve("a/state.superseded.snapshot");
        assertTrue(Files.exists(kept), "the superseded state should be kept at " + kept);
        Path recovered = TestDirs.newRoot("recovered");
        Files.copy(kept, recovered.resolve("state.snapshot"));
        try (Store back = new Store(recovered)) {
            assertTrue(back.node("mkey:bob") != null, "bob should be readable from the kept copy");
            assertTrue(back.names().stream().anyMatch(n -> n.name().equals("bobapp")), "and so should the name");
        }
        // And alice, who both hubs knew about, came through the hand-off untouched.
        assertTrue(a.store().node(alice.machineKey()) != null);
    }

    @Test
    void aPartitionIsNotADeathWhenANodeCanStillReachThePrimary() throws Exception {
        pair();
        // Cut only the hub-to-hub channel. alice still reaches A on her control connection, so
        // B's probe comes back with A's proof, and B stays what it is however long this lasts.
        b.peerClient().suspend(true);
        waitFor("the channel did not drop", () -> !b.peerClient().isConnected());
        Thread.sleep(QUICK.promoteAfterMs() + QUICK.witnessWindowMs() + 2500);
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
        Thread.sleep(QUICK.promoteAfterMs() + QUICK.witnessWindowMs() + 2500);
        assertEquals("standby", b.role(), "nobody to ask, so nobody promotes");
        assertFalse(b.peerClient().isConnected());
    }
}
