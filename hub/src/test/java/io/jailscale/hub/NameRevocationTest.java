package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * ARCHITECTURE.md §11.4: when a name moves to another node, the node that lost it is told. The point is
 * that being offline is the common case -- a node is often offline precisely because that is when
 * someone else took the name -- so the notice has to survive until it reconnects.
 */
@Timeout(120)
class NameRevocationTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private int port;
    private final List<Daemon> daemons = new ArrayList<>();
    private ServerSocket localApp;

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("rv");
            port = TestPorts.reserve();
        HubConfig cfg = HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test");
        hub = new Hub(cfg);
        hub.start();
        localApp = TestPorts.listen(8);
    }

    @AfterEach
    void stop() throws Exception {
        for (Daemon d : daemons) {
            d.close();
        }
        localApp.close();
        hub.close();
    }

    private Daemon node(String home) throws IOException {
        Daemon d = new Daemon(NodeConfig.in(root.resolve(home)));
        d.start();
        daemons.add(d);
        return d;
    }

    private JsonObject cli(String home, JsonObject.Builder req) throws IOException {
        return Ipc.call(root.resolve(home).resolve("jailscale.sock"), req.build());
    }

    private JsonObject ok(JsonObject r) {
        assertTrue(r.optBool("ok", false), r.toString());
        return r;
    }

    /** The first machine of a user: nobody is called alice yet, so the name is hers to take. */
    private void join(String home) throws Exception {
        ok(cli(home, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString())));
    }

    /**
     * Another machine of the same user. Joining as an existing user takes a credential that names
     * them (§10): alice issues an invite for herself, and the machine redeeming it is hers. Asking
     * to be alice without one is how someone else would become her.
     */
    private void joinSameUser(String home, String invite) throws Exception {
        ok(cli(home, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("invite", invite).put("caFile", CERT.toString())));
    }

    private String selfInvite(String home) throws Exception {
        return ok(cli(home, JsonObject.builder().put("cmd", "invite").put("self", true))).string("url");
    }

    private List<Object> revoked(String home) throws IOException {
        return ok(cli(home, JsonObject.builder().put("cmd", "status"))).array("revoked");
    }

    @Test
    void theNodeThatLosesANameIsToldWhileItIsConnected() throws Exception {
        node("a");
        join("a");
        ok(cli("a", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "shared")));
        assertEquals(0, revoked("a").size());

        // A second node of the same user opens the same name: the newest opener wins (§8.2).
        String invite = selfInvite("a");
        // Asking to be alice without a credential is refused, and the refusal says what to do.
        node("c");
        JsonObject asAlice = cli("c", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString()));
        assertTrue(!asAlice.optBool("ok", false), asAlice.toString());
        assertTrue(asAlice.toString().contains("user-taken") && asAlice.toString().contains("invite --self"), asAlice.toString());
        node("b");
        joinSameUser("b", invite);
        ok(cli("b", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "shared")));

        waitFor(() -> revoked("a").size() == 1);
        Map<String, Object> row = row(revoked("a").get(0));
        assertEquals("shared", row.get("name"));
        assertEquals("reassigned", row.get("reason"));

        // It is gone from the losing node's own list, so a reconnect will not silently reopen it.
        assertEquals(0, ok(cli("a", JsonObject.builder().put("cmd", "ls"))).array("links").size());
        // and the node that took it is unaffected
        assertEquals(0, revoked("b").size());
    }

    @Test
    void aNoticeWaitsForANodeThatWasOfflineWhenItLostTheName() throws Exception {
        Daemon a = node("a");
        join("a");
        ok(cli("a", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "shared")));

        String invite = selfInvite("a");
        // Alice goes away. This is the case that matters: nobody can be told anything right now.
        a.close();
        daemons.remove(a);
        waitFor(() -> hub.links().byName("shared") == null);

        node("b");
        joinSameUser("b", invite);
        ok(cli("b", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "shared")));
        // Nothing could be sent, so the hub is holding it.
        assertEquals(1, hub.store().noticeCount());

        // Alice comes back with the same machine key and is told on arrival.
        node("a");
        waitFor(() -> revoked("a").size() == 1);
        assertEquals("reassigned", row(revoked("a").get(0)).get("reason"));
        // Delivered once, then forgotten.
        waitFor(() -> hub.store().noticeCount() == 0);
    }

    @Test
    void anOperatorReleaseTakesTheNameDownAndSaysSo() throws Exception {
        node("a");
        join("a");
        ok(cli("a", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "bye")));
        assertTrue(hub.links().byName("bye") != null);

        hub.store().releaseName("bye");
        hub.links().releasedByOperator("bye", false);

        // The live link goes down, not just the claim: before this the name kept serving.
        assertEquals(null, hub.links().byName("bye"));
        waitFor(() -> revoked("a").size() == 1);
        assertEquals("released", row(revoked("a").get(0)).get("reason"));
    }

    @Test
    void openingTheNameAgainAnswersTheWarning() throws Exception {
        node("a");
        join("a");
        ok(cli("a", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "mine")));
        hub.store().releaseName("mine");
        hub.links().releasedByOperator("mine", false);
        waitFor(() -> revoked("a").size() == 1);

        ok(cli("a", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "mine")));
        assertEquals(0, revoked("a").size(), "deliberately reopening the name is the answer to the warning");
    }

    @Test
    void aNodeThatNeverComesBackDoesNotGrowTheStateWithoutBound() throws Exception {
        for (int i = 0; i < Store.MAX_NOTICES_PER_NODE + 5; i++) {
            hub.store().addNotice("mkeyabsent", "l_" + i, "n" + i, "reassigned");
        }
        assertEquals(Store.MAX_NOTICES_PER_NODE, hub.store().notices("mkeyabsent").size());
        // The oldest are the ones dropped.
        assertEquals("n5", hub.store().notices("mkeyabsent").get(0).name());
        assertFalse(hub.store().notices("mkeyabsent").stream().anyMatch(r -> r.name().equals("n0")));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> row(Object o) {
        return (Map<String, Object>) o;
    }

    private interface Check {
        boolean ok() throws Exception;
    }

    private static void waitFor(Check c) throws Exception {
        long deadline = System.currentTimeMillis() + 20_000;
        while (System.currentTimeMillis() < deadline) {
            if (c.ok()) {
                return;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("condition not met in time");
    }
}
