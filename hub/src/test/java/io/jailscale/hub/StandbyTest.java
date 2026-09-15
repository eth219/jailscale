package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * ARCHITECTURE.md §13.1 end to end: a second hub given the primary's {@code hub.key} follows it --
 * certificate, keys, state and every event after -- turns nodes away while it is a standby, and
 * after {@code jailhub promote} is a primary the same nodes can join with the key they pinned.
 */
@Timeout(120)
class StandbyTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub primary;
    private Hub standby;
    private Daemon alice;
    private Daemon bob;
    private ServerSocket app;

    @AfterEach
    void stop() throws Exception {
        for (AutoCloseable c : new AutoCloseable[] {alice, bob, standby, primary, app}) {
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

    private static JsonObject status(String host, int port) throws Exception {
        try (SSLSocket s = Tls.connect(Tls.clientContext(CERT, false), host, "127.0.0.1", port, true, 10_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", host, "/v1/status", null, null);
            HttpResponse r = Http.readResponse(s.getInputStream(), 65536);
            assertEquals(200, r.status());
            return Json.parseObject(r.bodyText());
        }
    }

    private static String page(String host, int port) throws Exception {
        try (SSLSocket s = Tls.connect(Tls.clientContext(CERT, false), host, "127.0.0.1", port, true, 10_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", host, "/", null, null);
            return Http.readResponse(s.getInputStream(), 1 << 20).bodyText();
        }
    }

    private interface Check {
        boolean ok() throws Exception;
    }

    private static void waitFor(String what, Check c) throws Exception {
        long deadline = System.currentTimeMillis() + 20_000;
        while (System.currentTimeMillis() < deadline) {
            if (c.ok()) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError(what);
    }

    @Test
    void aStandbyFollowsThePrimaryTurnsNodesAwayAndServesThemOncePromoted() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("sb");
        int portA = freePort();
        int portB = freePort();
        primary = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + portA), root.resolve("a"), "127.0.0.1", portA,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        primary.start();

        // A member with a name, before the standby exists: the snapshot has to carry it.
        app = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        alice = new Daemon(NodeConfig.in(root.resolve("alice")));
        alice.start();
        Path aliceSock = root.resolve("alice/jailscale.sock");
        JsonObject up = Ipc.call(aliceSock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", portA).put("user", "alice").put("caFile", CERT.toString()).build());
        assertTrue(up.optBool("ok", false), up.toString());
        JsonObject open = Ipc.call(aliceSock, JsonObject.builder().put("cmd", "open").put("port", app.getLocalPort()).put("name", "web").build());
        assertTrue(open.optBool("ok", false), open.toString());

        // The standby gets no certificate files of its own: the wildcard, its key and the state
        // all have to come over the channel. What it is given is hub.key, which is the whole
        // provisioning act. Without it, starting is refused with the file named. Its base URL is
        // the primary's own name, as deployed: that is the name it serves once promoted.
        HubConfig sbConfig = HubConfig.withCert(URI.create("https://hub.test:" + portB), root.resolve("b"), "127.0.0.1", portB,
            null, null, false, HubConfig.POLICY_MEMBERS, true, "hub.test")
            .withPeer(URI.create("https://hub.test:" + portA), CERT, "127.0.0.1");
        IOException noKey = org.junit.jupiter.api.Assertions.assertThrows(IOException.class, () -> new Hub(sbConfig));
        assertTrue(noKey.getMessage().contains("hub.key"), noKey.getMessage());
        Files.createDirectories(root.resolve("b"));
        Files.copy(root.resolve("a/hub.key"), root.resolve("b/hub.key"), StandardCopyOption.REPLACE_EXISTING);
        standby = new Hub(sbConfig);
        standby.start(); // returns once the primary's certificate has arrived

        assertEquals(primary.tls().keyId(), standby.tls().keyId(), "the standby signs with the primary's certificate");
        assertTrue(Files.exists(root.resolve("b/tls/wildcard.pem")), "the certificate is on disk for a restart after promotion");
        assertTrue(Files.exists(root.resolve("b/tls/wildcard.key")));
        assertEquals(primary.keys().publicText(), standby.keys().publicText());
        waitFor("the snapshot never reached the standby", () -> standby.peerClient().isSynced());
        assertNotNull(standby.store().node(alice.machineKey()), "the member registered before the standby existed");
        assertEquals("alice", standby.store().nameOwner("web"));
        assertEquals("open", standby.store().setting(Store.SETTING_REGISTRATION, "invite"), "settings follow the primary, not the standby's flags");

        // Every event after the snapshot, in order.
        JsonObject inv = Ipc.call(root.resolve("a/jailhub.sock"), JsonObject.builder().put("cmd", "invite-create").put("user", "carol").build());
        assertTrue(inv.optBool("ok", false), inv.toString());
        Ipc.call(root.resolve("a/jailhub.sock"), JsonObject.builder().put("cmd", "admin-add").put("user", "alice").build());
        waitFor("the invite never reached the standby", () -> standby.store().invites().size() == primary.store().invites().size());
        waitFor("the admin never reached the standby", () -> standby.store().isAdmin("alice"));

        // Both sides say what they are, to a person and to a monitor.
        JsonObject sbStatus = status("hub.test", portB);
        assertEquals("standby", sbStatus.string("role"));
        assertEquals("hub.test", sbStatus.string("primary"));
        assertTrue(sbStatus.bool("inSync"));
        JsonObject prStatus = status("hub.test", portA);
        assertEquals("primary", prStatus.string("role"));
        assertFalse(prStatus.has("primary"));
        assertTrue(prStatus.object("availability").object("peers").has("127.0.0.1"), "a standby with the primary's own name is known by its address: " + prStatus);
        assertTrue(sbStatus.object("availability").object("peers").has("hub.test"), sbStatus.toString());
        assertTrue(sbStatus.object("availability").object("process").has("24h"), sbStatus.toString());
        String prPage = page("hub.test", portA);
        assertTrue(prPage.contains("standby <code>127.0.0.1</code> in sync"), prPage);
        assertTrue(prPage.contains("Seen from here"), prPage);
        assertTrue(page("hub.test", portB).contains("standby of <code>hub.test</code>, in sync"));
        JsonObject ipcStatus = Ipc.call(root.resolve("a/jailhub.sock"), JsonObject.builder().put("cmd", "status").build());
        assertEquals(1, ipcStatus.array("standbys").size(), ipcStatus.toString());

        // A node that reaches the standby is told what it is and keeps trying, rather than being
        // registered on a hub that cannot keep a registration.
        bob = new Daemon(NodeConfig.in(root.resolve("bob")));
        bob.start();
        Path bobSock = root.resolve("bob/jailscale.sock");
        Thread bobUp = Thread.ofVirtual().start(() -> {
            try {
                Ipc.call(bobSock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
                    .put("port", portB).put("user", "bob").put("caFile", CERT.toString()).build());
            } catch (IOException ignored) {
                // the answer is read from status below
            }
        });
        waitFor("the standby did not turn the node away by name",
            () -> Ipc.call(bobSock, JsonObject.builder().put("cmd", "status").build()).toString().contains("standby"));
        assertEquals(0, standby.registry().size());

        // Promotion: the standby stops following and takes nodes; the channel to it closes.
        JsonObject promoted = Ipc.call(root.resolve("b/jailhub.sock"), JsonObject.builder().put("cmd", "promote").build());
        assertTrue(promoted.optBool("ok", false), promoted.toString());
        assertEquals("primary", promoted.string("role"));
        assertEquals("primary", status("hub.test", portB).string("role"));
        waitFor("the primary still counts the promoted hub as a standby", () -> primary.peers().count() == 0);
        JsonObject again = Ipc.call(root.resolve("b/jailhub.sock"), JsonObject.builder().put("cmd", "promote").build());
        assertFalse(again.optBool("ok", false), "promoting a primary is an error, not a no-op: " + again);

        // bob's retry lands: registration is open (the primary's setting), and the hub key bob
        // pinned from the standby's /v1/key is the one it still has.
        bobUp.join(60_000);
        waitFor("bob never joined the promoted hub", () -> {
            JsonObject st = Ipc.call(bobSock, JsonObject.builder().put("cmd", "status").build());
            return st.optBool("connected", false) || st.optBool("registered", false);
        });
        assertNotNull(standby.store().node(bob.machineKey()));
        assertEquals("alice", standby.store().nameOwner("web"), "what was replicated is what the promoted hub serves");
        // The old primary's copy did not change: promotion is one way and says so.
        assertEquals("primary", status("hub.test", portA).string("role"));
    }
}
