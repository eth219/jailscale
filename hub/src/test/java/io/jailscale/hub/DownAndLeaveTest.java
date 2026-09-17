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
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * {@code jailscale down} and {@code jailscale leave}: the two commands that take a node off its
 * hub, and the only two in the CLI that no test reached at any layer. They look alike from the
 * outside -- both end with the node not connected -- and they differ in everything that matters
 * afterwards, which is why each is worth pinning.
 *
 * <p>{@code down} is a pause: the registration, the node id and the links all survive, so
 * {@code up} brings the same node back. {@code leave} is the forgetting: it drops the hub, the
 * identity and every link this node had there.
 */
@Timeout(90)
class DownAndLeaveTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private Daemon node;
    private int port;
    private ServerSocket localApp;

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("jd");
        java.net.ServerSocket portSocket = TestPorts.listen(1024);
        port = portSocket.getLocalPort();
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.listenOn(portSocket);
        hub.start();
        localApp = TestPorts.listen(8);
        node = new Daemon(NodeConfig.in(root.resolve("alice")));
        node.start();
    }

    @AfterEach
    void stop() throws Exception {
        node.close();
        localApp.close();
        hub.close();
    }

    private JsonObject cli(JsonObject.Builder req) throws IOException {
        JsonObject r = Ipc.call(root.resolve("alice").resolve("jailscale.sock"), req.build());
        assertTrue(r.optBool("ok", false), r.toString());
        return r;
    }

    private JsonObject status() throws IOException {
        return cli(JsonObject.builder().put("cmd", "status"));
    }

    /** Joins the hub (registration is open here) and publishes the local app as "web". */
    private long joinAndOpen() throws Exception {
        cli(JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString()));
        waitFor(() -> node.hasCert(hub.tls().keyId()));
        cli(JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "web"));
        JsonObject s = status();
        assertTrue(s.bool("connected"));
        assertTrue(s.bool("registered"));
        assertEquals("alice", s.string("user"));
        assertEquals("hub.test", s.string("hub"));
        assertEquals(1, s.array("links").size());
        return s.lng("nodeId");
    }

    /**
     * A pause, not a departure. Someone typing this wants their machine off the air for a while --
     * the node id, the hub key it has pinned and the links it publishes all have to be there when
     * they type {@code up} again, or the name they handed out comes back as a different one.
     */
    @Test
    void downClosesTheConnectionAndKeepsEverythingElse() throws Exception {
        long nodeId = joinAndOpen();
        assertEquals(1, hub.registry().size());

        cli(JsonObject.builder().put("cmd", "down"));

        JsonObject s = status();
        assertFalse(s.bool("connected"), "down leaves nothing connected");
        assertTrue(s.bool("registered"), "but the node is still a member of this hub");
        assertEquals(nodeId, s.lng("nodeId"));
        assertEquals("alice", s.string("user"));
        assertEquals("hub.test", s.string("hub"));
        assertEquals(1, s.array("links").size(), "the link is kept, to be republished on the way back up");
        waitFor(() -> hub.registry().size() == 0);
        assertEquals(1, hub.store().nodes().size(), "the hub still knows the node, it is just offline");

        // And back: the same identity, not a new one.
        cli(JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString()));
        waitFor(() -> node.hasCert(hub.tls().keyId()));
        JsonObject back = status();
        assertTrue(back.bool("connected"));
        assertEquals(nodeId, back.lng("nodeId"), "up after down must not hand out a second node id");
        assertEquals(1, hub.store().nodes().size());
    }

    /**
     * The forgetting. Everything that ties this machine to that hub goes, including the links --
     * the names belonged to the hub, and keeping rows that point at a hub the node no longer has a
     * key for would only produce a table of links that cannot be reopened.
     *
     * <p>What it deliberately does not do is tell the hub. The record there is the admin's to
     * remove ({@code jailhub node remove}), and a node that has left cannot be the one to ask:
     * anyone who could send the message could send it for somebody else's machine.
     */
    @Test
    void leaveForgetsTheHubLocallyAndLeavesTheRecordToTheAdmin() throws Exception {
        joinAndOpen();
        String machineKey = status().string("machineKey");

        cli(JsonObject.builder().put("cmd", "leave"));

        JsonObject s = status();
        assertFalse(s.bool("connected"));
        assertFalse(s.bool("registered"));
        assertFalse(s.has("nodeId"), "the node id is dropped, not kept at its old value");
        assertFalse(s.has("user"));
        assertFalse(s.has("hub"));
        assertFalse(s.has("hubKey"), "the pinned hub key goes too, or a later up would trust the old one");
        assertEquals(0, s.array("links").size());
        assertEquals(machineKey, s.string("machineKey"), "the machine key is this node's own, and survives");
        waitFor(() -> hub.registry().size() == 0);

        assertEquals(1, hub.store().nodes().size(),
            "leave is local: the hub's record is removed by an admin with `jailhub node remove`");
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
