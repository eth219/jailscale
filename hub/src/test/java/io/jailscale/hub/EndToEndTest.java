package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * M1 completion criterion (DESIGN.md §14): a node invited by another node joins with nothing but
 * {@code jailscale up --invite}, plus code invites, knock + admin approval, and hub key
 * rotation without dropping nodes. Everything runs in-process over loopback TLS with the test
 * certificate; the CLI is exercised through the same IPC the real binary uses.
 */
@Timeout(90)
class EndToEndTest {

    private Path root;
    private Hub hub;
    private int port;
    private final List<Daemon> daemons = new ArrayList<>();

    @BeforeEach
    void startHub() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        // AF_UNIX paths are limited to ~100 bytes on macOS; keep the tree short.
        root = TestDirs.newRoot("js");
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        Path cert = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
        Path key = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();
        HubConfig cfg = HubConfig.withCert(URI.create("https://localhost:" + port), root.resolve("hub"), "127.0.0.1", port,
            cert, key, false, HubConfig.POLICY_MEMBERS, true, "localhost");
        hub = new Hub(cfg);
        hub.start();
    }

    @AfterEach
    void stop() throws Exception {
        for (Daemon d : daemons) {
            d.close();
        }
        hub.close();
    }

    private Daemon node(String name) throws IOException {
        Daemon d = new Daemon(NodeConfig.in(root.resolve(name)));
        d.start();
        daemons.add(d);
        return d;
    }

    private JsonObject cli(String name, JsonObject req) throws IOException {
        return Ipc.call(root.resolve(name).resolve("jailscale.sock"), req);
    }

    private JsonObject up(String name, JsonObject.Builder args) throws IOException {
        JsonObject r = cli(name, args.put("cmd", "up")
            .put("caFile", Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath().toString()).build());
        assertTrue(r.optBool("ok", false), r.toString());
        return r;
    }

    private JsonObject admin(JsonObject req) throws IOException {
        JsonObject r = Ipc.call(hub.stateDir().resolve("jailhub.sock"), req);
        assertTrue(r.optBool("ok", false), r.toString());
        return r;
    }

    @Test
    void inviteFlowsAndKeyRotation() throws Exception {
        // Bootstrap: the hub printed a first invite; fetch one the same way (admin=true).
        Invites.Created boot = hub.invites().create(null, 1, 3600, "test", true);

        // 1. alice joins with the bootstrap invite and becomes admin.
        node("alice");
        JsonObject a = up("alice", JsonObject.builder().put("invite", boot.url()).put("user", "alice"));
        assertEquals("approved", a.string("status"));
        assertEquals("alice", a.string("user"));
        assertTrue(hub.store().isAdmin("alice"));
        assertEquals(1, hub.registry().size());

        // 2. alice invites bob from her node; bob joins with only the link.
        JsonObject inv = cli("alice", JsonObject.builder().put("cmd", "invite").put("user", "bob").put("uses", 2).build());
        assertTrue(inv.optBool("ok", false), inv.toString());
        node("bob");
        JsonObject b = up("bob", JsonObject.builder().put("invite", inv.string("url")));
        assertEquals("approved", b.string("status"));
        assertEquals("bob", b.string("user"));

        // 3. the short code of the same invite (second use) works with --hub + --code.
        node("carol");
        JsonObject c = up("carol", JsonObject.builder().put("hub", "localhost").put("port", port)
            .put("code", inv.string("code").toLowerCase()));
        assertEquals("approved", c.string("status"));
        assertEquals("bob", c.string("user")); // the invite pinned the name

        // 4. the invite is now spent.
        node("dave");
        JsonObject spent = cli("dave", JsonObject.builder().put("cmd", "up").put("invite", inv.string("url"))
            .put("caFile", Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath().toString()).build());
        assertFalse(spent.optBool("ok", false));
        assertTrue(spent.string("error").contains("invite-invalid"), spent.toString());

        // 5. dave knocks instead and waits; the admin approves via jailhub IPC; dave is pushed the result.
        daemons.get(3).close();
        daemons.remove(3);
        Files.walk(root.resolve("dave")).sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        node("dave");
        JsonObject knock = up("dave", JsonObject.builder().put("hub", "localhost").put("port", port).put("user", "dave"));
        assertEquals("pending", knock.string("status"));
        String daveKey = knock.string("machineKey");
        assertEquals(1, admin(JsonObject.builder().put("cmd", "node-list").build()).array("pending").size());
        admin(JsonObject.builder().put("cmd", "node-approve").put("mkey", daveKey).build());
        waitFor(() -> cli("dave", JsonObject.builder().put("cmd", "status").build()).optBool("registered", false));
        assertEquals("dave", cli("dave", JsonObject.builder().put("cmd", "status").build()).string("user"));
        assertEquals(4, hub.store().nodes().size());

        // 5b. an auth-key registers a headless node with no browser and no name prompt.
        JsonObject ak = admin(JsonObject.builder().put("cmd", "authkey-create").put("tag", "ci").put("uses", 1).build());
        node("ci");
        JsonObject ciUp = up("ci", JsonObject.builder().put("hub", "localhost").put("port", port).put("authKey", ak.string("key")));
        assertEquals("approved", ciUp.string("status"));
        assertEquals("tag:ci", ciUp.string("user"));
        assertEquals(5, hub.store().nodes().size());

        // 6. netcheck round trip.
        JsonObject nc = cli("alice", JsonObject.builder().put("cmd", "netcheck").build());
        assertTrue(nc.optBool("ok", false));
        assertTrue(nc.lng("rttMicros") < 5_000_000);

        // 7. hub key rotation: announce, activate, force reconnects; every node pins the new key.
        String oldKey = hub.keys().publicText();
        admin(JsonObject.builder().put("cmd", "key-rotate").put("grace", 1).build());
        waitFor(() -> "true".equals(String.valueOf(cli("alice", JsonObject.builder().put("cmd", "status").build()).has("hubKey"))));
        Thread.sleep(1100);
        hub.promoteRotationIfDue();
        String newKey = hub.keys().publicText();
        assertNotEquals(oldKey, newKey);
        hub.registry().closeAll("shutdown");
        for (String n : new String[] {"alice", "bob", "carol", "dave", "ci"}) {
            waitFor(() -> {
                JsonObject st = cli(n, JsonObject.builder().put("cmd", "status").build());
                return st.optBool("connected", false) && newKey.equals(st.optString("hubKey", null));
            });
        }
        assertEquals(5, hub.registry().size());

        // 8. revocation pushes a goodbye and the node stops reconnecting.
        admin(JsonObject.builder().put("cmd", "node-remove").put("mkey", daveKey).build());
        waitFor(() -> !cli("dave", JsonObject.builder().put("cmd", "status").build()).optBool("connected", true));
        assertNotNull(cli("dave", JsonObject.builder().put("cmd", "status").build()).optString("lastError", null));
        assertEquals(4, hub.store().nodes().size());
    }

    @Test
    void wrongHubKeyIsAHardFailure() throws Exception {
        node("eve");
        JsonObject r = cli("eve", JsonObject.builder().put("cmd", "up").put("hub", "localhost").put("port", port)
            .put("hubKey", io.jailscale.crypto.KeyText.format(io.jailscale.crypto.KeyText.HUB,
                io.jailscale.crypto.X25519.generate().publicKey())).put("tlsInsecure", true).build());
        assertFalse(r.optBool("ok", false));
        assertTrue(r.string("error").contains("hub key mismatch"), r.toString());
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
            Thread.sleep(100);
        }
        throw new AssertionError("condition not met in time");
    }
}
