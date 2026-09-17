package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.hub.dns.DnsQuery;
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
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

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

    private static JsonObject status(String host, int port) throws Exception {
        try (SSLSocket s = Tls.connect(Tls.clientContext(CERT, false), host, "127.0.0.1", port, true, 10_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", host, "/v1/status", null, null);
            HttpResponse r = Http.readResponse(s.getInputStream(), 65536);
            assertEquals(200, r.status());
            return Json.parseObject(r.bodyText());
        }
    }

    /** A visit to a published name through one hub, as a browser would make it. */
    private static HttpResponse visit(String name, int port) throws Exception {
        try (SSLSocket s = Tls.connect(Tls.clientContext(CERT, false), name, "127.0.0.1", port, true, 15_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", name, "/", null, null);
            return Http.readResponse(s.getInputStream(), 65536);
        }
    }

    /** A local app that answers every request with one line. */
    private static void serveApp(ServerSocket app) {
        Thread.ofVirtual().start(() -> {
            while (!app.isClosed()) {
                try {
                    java.net.Socket c = app.accept();
                    Thread.ofVirtual().start(() -> {
                        try (c) {
                            Http.readRequest(c.getInputStream(), 4096);
                            c.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
                                .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
                        } catch (Exception ignored) {
                            // visitor gone
                        }
                    });
                } catch (IOException e) {
                    return;
                }
            }
        });
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
        java.net.ServerSocket portASocket = TestPorts.listen(1024);
        int portA = portASocket.getLocalPort();
        primary = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + portA), root.resolve("a"), "127.0.0.1", portA,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test").withAdvertise("203.0.113.1"));
        primary.listenOn(portASocket);
        // Both hubs share the loopback address here and differ by port, so what a node dials is
        // told apart from what DNS advertises (§13.4); in a deployment they are the same address.
        primary.relayEndpointOverride = "127.0.0.1:" + portA;
        primary.start();
        // §13.3: alone, the primary answers its own name with itself, for the apex and any name under it.
        assertEquals(List.of("203.0.113.1"), DnsQuery.a("127.0.0.1", primary.dnsPort(), "hub.test", 2000));
        assertEquals(List.of("203.0.113.1"), DnsQuery.a("127.0.0.1", primary.dnsPort(), "web.hub.test", 2000));

        // A member with a name, before the standby exists: the snapshot has to carry it.
        app = TestPorts.listen(8);
        serveApp(app);
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
        //
        // Its port is held rather than reserved, so the ordering no longer matters: a bound socket
        // cannot be handed to the primary's own port-0 draws, which is what used to make this
        // fragile (#196).
        java.net.ServerSocket portBSocket = TestPorts.listen(1024);
        int portB = portBSocket.getLocalPort();
        HubConfig sbConfig = HubConfig.withCert(URI.create("https://hub.test:" + portB), root.resolve("b"), "127.0.0.1", portB,
            null, null, false, HubConfig.POLICY_MEMBERS, true, "hub.test")
            .withPeer(URI.create("https://hub.test:" + portA), CERT, "127.0.0.1").withAdvertise("203.0.113.2");
        IOException noKey = org.junit.jupiter.api.Assertions.assertThrows(IOException.class, () -> new Hub(sbConfig));
        assertTrue(noKey.getMessage().contains("hub.key"), noKey.getMessage());
        Files.createDirectories(root.resolve("b"));
        Files.copy(root.resolve("a/hub.key"), root.resolve("b/hub.key"), StandardCopyOption.REPLACE_EXISTING);
        standby = new Hub(sbConfig);
        standby.listenOn(portBSocket);
        standby.relayEndpointOverride = "127.0.0.1:" + portB;
        standby.start(); // returns once the primary's certificate has arrived

        assertEquals(primary.tls().keyId(), standby.tls().keyId(), "the standby signs with the primary's certificate");
        assertTrue(Files.exists(root.resolve("b/tls/wildcard.pem")), "the certificate is on disk for a restart after promotion");
        assertTrue(Files.exists(root.resolve("b/tls/wildcard.key")));
        assertEquals(primary.keys().publicText(), standby.keys().publicText());
        waitFor("the snapshot never reached the standby", () -> standby.peerClient().isSynced());
        // §13.3: the standby answers the primary's challenge values.
        primary.dns().setTxt(List.of("challenge-for-the-ca"));
        waitFor("the challenge value never reached the standby",
            () -> DnsQuery.txt("127.0.0.1", standby.dnsPort(), "_acme-challenge.hub.test", 2000).contains("challenge-for-the-ca"));
        primary.dns().clearTxt();
        waitFor("the cleared challenge never reached the standby",
            () -> DnsQuery.txt("127.0.0.1", standby.dnsPort(), "_acme-challenge.hub.test", 2000).isEmpty());
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
        // §13.4: the standby serves. The primary named it to alice, alice opened a relay connection
        // and reopened her link there, and a visitor who reaches the standby is served by alice --
        // signed by the standby, with the copy of the key it holds.
        waitFor("alice never opened a relay connection to the standby", () -> alice.connectedRelays().contains("127.0.0.1:" + portB));
        waitFor("alice's link never reopened on the standby", () -> standby.links().byName("web") != null);
        HttpResponse viaStandby = visit("web.hub.test", portB);
        assertEquals(200, viaStandby.status());
        assertEquals("hello", viaStandby.bodyText());
        assertEquals(200, visit("web.hub.test", portA).status(), "and the primary still serves it too");
        // And DNS says so: the name resolves to both hosts, the apex to the primary alone, and a
        // name nobody has opened to every host serving, where the "not open" page is.
        waitFor("the primary never learned alice is on the standby",
            () -> new java.util.HashSet<>(DnsQuery.a("127.0.0.1", primary.dnsPort(), "web.hub.test", 2000)).equals(java.util.Set.of("203.0.113.1", "203.0.113.2")));
        assertEquals(java.util.Set.of("203.0.113.1", "203.0.113.2"), new java.util.HashSet<>(DnsQuery.a("127.0.0.1", standby.dnsPort(), "web.hub.test", 2000)));
        assertEquals(List.of("203.0.113.1"), DnsQuery.a("127.0.0.1", standby.dnsPort(), "hub.test", 2000));
        assertEquals(List.of("203.0.113.1"), DnsQuery.a("127.0.0.1", primary.dnsPort(), "hub.test", 2000));
        assertEquals(java.util.Set.of("203.0.113.1", "203.0.113.2"), new java.util.HashSet<>(DnsQuery.a("127.0.0.1", primary.dnsPort(), "nobody.hub.test", 2000)));
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
        // One fetch each, read many times below: re-fetching per assertion is a TLS handshake and a
        // page render apiece, and it also means a failing assertion's message shows a page other
        // than the one that failed.
        String sbPage = page("hub.test", portB);
        // "connected" and not "in sync": a standby acknowledges nothing, so that is the whole of
        // what the primary can say about it. The standby's own page below is where "in sync" is
        // claimed, by the side that knows.
        assertTrue(prPage.contains("standby <code>127.0.0.1</code> connected"), prPage);
        assertTrue(prPage.contains("Seen from here"), prPage);
        assertTrue(sbPage.contains("standby of <code>hub.test</code>, in sync"), sbPage);
        // A pair that is doing its job is not graded as a problem on either side. This is the
        // assertion that makes the two below mean something: without it they would also pass on a
        // page that called every hub degraded.
        assertTrue(prPage.contains("All systems operational"), prPage);
        assertTrue(sbPage.contains("All systems operational"), sbPage);
        // §13.4: a standby answers Goodbye{standby} to every control connection, so its own page
        // must not tell a reader to join here -- while the primary's, which will take the join,
        // must not carry the warning. Both halves, because either alone is satisfied by a page
        // that always says it or never does.
        assertTrue(sbPage.contains("Not on this host, though:"), sbPage);
        assertFalse(prPage.contains("Not on this host, though:"), prPage);
        // And the join itself is gone, not merely warned about: the command names the apex, which
        // resolves to the primary alone and to nothing at all once the primary is down -- which is
        // the state a reader is in when they are looking at the standby's page.
        assertFalse(sbPage.contains("jailscale up --hub"), sbPage);
        assertFalse(sbPage.contains("jailscale up --invite"), sbPage);
        assertTrue(prPage.contains("jailscale up --hub hub.test") || prPage.contains("jailscale up --invite"), prPage);
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
        assertTrue(standby.registry().get(bob.machineKey()) == null, "a control connection is not taken by a standby");

        // §13.4, the point of it all, in the order it happens: the primary goes first. Nobody has
        // told alice anything, so her relay connection to the standby stays, her name is still
        // served through it -- signed by the standby with the copy of the key it holds -- and
        // the standby's DNS now names itself alone for her name and nothing for the apex.
        primary.close();
        primary = null;
        waitFor("the standby still counts the old primary as a peer",
            () -> DnsQuery.a("127.0.0.1", standby.dnsPort(), "web.hub.test", 2000).equals(List.of("203.0.113.2")));
        assertEquals(List.of(), DnsQuery.a("127.0.0.1", standby.dnsPort(), "hub.test", 2000), "no primary, nothing to point the apex at");
        assertEquals(200, visit("web.hub.test", portB).status());
        assertEquals("hello", visit("web.hub.test", portB).bodyText());
        // The standby is serving and its own page says what is wrong anyway: it is following
        // nobody. Four rows down, that was "not connected" in the same grey as the uptime.
        waitFor("the standby's page never said it had lost the primary",
            () -> page("hub.test", portB).contains("Degraded &mdash; not connected to the primary"));

        // Promotion: the standby stops following and takes nodes, and the apex is itself.
        JsonObject promoted = Ipc.call(root.resolve("b/jailhub.sock"), JsonObject.builder().put("cmd", "promote").build());
        assertTrue(promoted.optBool("ok", false), promoted.toString());
        assertEquals("primary", promoted.string("role"));
        assertEquals("primary", status("hub.test", portB).string("role"));
        assertEquals(List.of("203.0.113.2"), DnsQuery.a("127.0.0.1", standby.dnsPort(), "hub.test", 2000));
        // Promoted, and alone: a hub that was given a peer and has none is short one host, which is
        // a different thing from a single-hub deployment that never had one and is not graded.
        String promotedPage = page("hub.test", portB);
        assertTrue(promotedPage.contains("Degraded &mdash; no standby is connected"), promotedPage);
        assertTrue(promotedPage.contains("<b>Warning</b>: primary, no standby connected"), promotedPage);
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
        assertEquals(200, visit("web.hub.test", portB).status(), "and alice's name is still served after the promotion");
    }
}
