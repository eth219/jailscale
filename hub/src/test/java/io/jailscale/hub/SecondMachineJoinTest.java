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
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * Adding a second machine to a user that already exists (ARCHITECTURE.md §10): the hub refuses a
 * node that picks the name itself and accepts one carrying an invite that names it, and — the part
 * that was wrong — {@code up} says which of those two just happened.
 */
@Timeout(120)
class SecondMachineJoinTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private int port;
    private final List<Daemon> daemons = new ArrayList<>();

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("2nd");
        java.net.ServerSocket portSocket = TestPorts.listen(1024);
        port = portSocket.getLocalPort();
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.listenOn(portSocket);
        hub.start();
    }

    @AfterEach
    void stop() throws Exception {
        List<AutoCloseable> all = new ArrayList<>(daemons);
        all.add(hub);
        TestCloseables.closeAll(all.toArray(new AutoCloseable[0]));
    }

    private Daemon node(String name) throws IOException {
        Daemon d = new Daemon(NodeConfig.in(root.resolve(name)));
        d.start();
        daemons.add(d);
        return d;
    }

    private JsonObject cli(String name, JsonObject.Builder req) throws IOException {
        return Ipc.call(root.resolve(name).resolve("jailscale.sock"), req.build());
    }

    private JsonObject.Builder up(String user) {
        return JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", user).put("caFile", CERT.toString());
    }

    /**
     * The second `up` is the one under test. A rejection used to be kept on the link and handed to
     * whoever asked next, so `up --invite` reported "user-taken" for an invite the hub had just
     * accepted: the node was joined, and the person at the keyboard had been told it had failed.
     */
    @Test
    void aRejectedJoinIsNotStillTheAnswerToTheNextOne() throws Exception {
        node("alice");
        assertTrue(cli("alice", up("alice")).optBool("ok", false));

        node("bob");
        JsonObject refused = cli("bob", up("alice"));
        assertFalse(refused.optBool("ok", false), "bob should not get alice's name by asking: " + refused);
        assertTrue(refused.optString("error", "").contains("user-taken"), refused.toString());

        // What the hub's own message tells bob to do next.
        JsonObject self = cli("alice", JsonObject.builder().put("cmd", "invite").put("self", true));
        assertTrue(self.optBool("ok", false), self.toString());

        JsonObject joined = cli("bob", JsonObject.builder().put("cmd", "up").put("invite", self.string("url"))
            .put("addr", "127.0.0.1").put("caFile", CERT.toString()));
        assertTrue(joined.optBool("ok", false), "the invite was accepted; up said otherwise: " + joined);
        assertEquals("approved", joined.string("status"));
        assertEquals("alice", joined.string("user"));

        // And the hub agrees: two machines, one user.
        assertEquals(2, hub.store().nodes().size());
    }
}
