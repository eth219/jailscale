package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** ARCHITECTURE.md §8.3: a user domain, certified with the node's own key via http-01 relayed by the hub. */
@Timeout(120)
class UserDomainTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();
    private static final String DOMAIN = "app.example.test";

    private Path root;
    private Hub hub;
    private int port;
    private Daemon node;
    private AcmeFlowTest.MockCa ca;
    private HttpServer app;

    @AfterEach
    void stop() throws Exception {
        if (node != null) {
            node.close();
        }
        if (hub != null) {
            hub.close();
        }
        if (ca != null) {
            ca.close();
        }
        if (app != null) {
            app.stop(0);
        }
    }

    private String get(String sni, String path) throws Exception {
        try (SSLSocket s = Tls.connect(Tls.clientContext(CERT, false), sni, "127.0.0.1", port, true, 10_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", sni, path, new Headers(), null);
            HttpResponse r = Http.readResponse(s.getInputStream(), 1 << 20);
            return r.status() + " " + r.bodyText();
        }
    }

    @Test
    void ownDomainIsIssuedRelayedAndPassedThrough() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("jd");
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test").withHttp("127.0.0.1", 0).withUserDomainCa(CERT));
        hub.start();
        assertTrue(hub.httpPort() > 0);
        ca = new AcmeFlowTest.MockCa(() -> -1);
        ca.httpPort = () -> hub.httpPort();

        app = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 4);
        app.createContext("/", ex -> {
            byte[] b = ("hello from " + ex.getRequestHeaders().getFirst("Host")).getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(b);
            }
        });
        app.start();

        node = new Daemon(NodeConfig.in(root.resolve("node")));
        node.start();
        Path sock = root.resolve("node/jailscale.sock");
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "alice").put("caFile", CERT.toString()).build()).optBool("ok", false));

        // The hub insists on proof: no chain, a chain for another name, a name under the hub itself.
        Message r = node.debugRequest(new Message.LinkOpen("https", null, DOMAIN, null, "127.0.0.1:1", null, null), "LinkOpened");
        assertEquals("domain-unverified", ((Message.LinkOpened) r).reason());
        r = node.debugRequest(new Message.LinkOpen("https", null, DOMAIN, null, "127.0.0.1:1", List.of(Files.readString(CERT)), null), "LinkOpened");
        assertEquals("domain-cert-name-mismatch", ((Message.LinkOpened) r).reason());
        r = node.debugRequest(new Message.LinkOpen("https", null, "x.hub.test", null, "127.0.0.1:1", null, null), "LinkOpened");
        assertEquals("bad-domain", ((Message.LinkOpened) r).reason());

        // The port-80 front answers only registered tokens and redirects the rest.
        try (Socket c = new Socket("127.0.0.1", hub.httpPort())) {
            Http.writeRequest(c.getOutputStream(), "GET", DOMAIN, "/.well-known/acme-challenge/nope", new Headers(), null);
            assertEquals(404, Http.readResponse(c.getInputStream(), 4096).status());
        }
        try (Socket c = new Socket("127.0.0.1", hub.httpPort())) {
            Http.writeRequest(c.getOutputStream(), "GET", DOMAIN, "/some/page", new Headers(), null);
            HttpResponse redir = Http.readResponse(c.getInputStream(), 4096);
            assertEquals(301, redir.status());
            assertEquals("https://" + DOMAIN + "/some/page", redir.headers().get("Location"));
        }

        // jailscale open <port> --domain app.example.test: ACME http-01 through the hub, then passthrough.
        JsonObject open = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", app.getAddress().getPort())
            .put("domain", DOMAIN).put("acmeDirectory", ca.base + "/directory").put("acmeEmail", "alice@example.test").build());
        assertTrue(open.optBool("ok", false), open.toString());
        assertEquals("https://" + DOMAIN + ":" + port, open.string("url"));
        assertEquals(1, ca.orders);
        assertEquals(List.of(DOMAIN), ca.validatedNames);
        assertTrue(Files.exists(root.resolve("node/domains/" + DOMAIN + ".pem")));
        assertTrue(Files.exists(root.resolve("node/domains/" + DOMAIN + ".key")));
        assertEquals("alice", hub.store().domain(DOMAIN).user());

        // A visitor: SNI app.example.test → hub passthrough → node terminates with its own key → local app.
        assertEquals("200 hello from " + DOMAIN, get(DOMAIN, "/"));

        // The chain is public -- every visitor above was handed it -- so presenting one is not a
        // claim. Without a signature from its private key the hub does not move the domain, and a
        // signature that is not over this connection's handshake hash is no better.
        List<String> real = List.of(Files.readString(root.resolve("node/domains/" + DOMAIN + ".pem")));
        r = node.debugRequest(new Message.LinkOpen("https", null, DOMAIN, null, "127.0.0.1:1", real, null), "LinkOpened");
        assertEquals("domain-proof-missing", ((Message.LinkOpened) r).reason());
        r = node.debugRequest(new Message.LinkOpen("https", null, DOMAIN, null, "127.0.0.1:1", real, new byte[64]), "LinkOpened");
        assertEquals("domain-proof-invalid", ((Message.LinkOpened) r).reason());
        assertEquals("alice", hub.store().domain(DOMAIN).user());

        // A relayed http-01 token answers for its own name and nothing else. Answering regardless
        // of Host would validate every domain pointed at this hub, for whichever node asked.
        assertNull(hub.challenges().set("m_test", DOMAIN, "tok-a", "tok-a.thumb"));
        try (Socket c = new Socket("127.0.0.1", hub.httpPort())) {
            Http.writeRequest(c.getOutputStream(), "GET", DOMAIN, "/.well-known/acme-challenge/tok-a", new Headers(), null);
            HttpResponse ok = Http.readResponse(c.getInputStream(), 4096);
            assertEquals(200, ok.status());
            assertEquals("tok-a.thumb", ok.bodyText());
        }
        try (Socket c = new Socket("127.0.0.1", hub.httpPort())) {
            Http.writeRequest(c.getOutputStream(), "GET", "hub.test", "/.well-known/acme-challenge/tok-a", new Headers(), null);
            assertEquals(404, Http.readResponse(c.getInputStream(), 4096).status());
        }
        try (Socket c = new Socket("127.0.0.1", hub.httpPort())) {
            Http.writeRequest(c.getOutputStream(), "GET", "other.example.test", "/.well-known/acme-challenge/tok-a", new Headers(), null);
            assertEquals(404, Http.readResponse(c.getInputStream(), 4096).status());
        }

        // And the hub does not lend its own name out for validation at all.
        Message ownName = node.debugRequest(new Message.ChallengeSet("hub.test", "tok-b", "tok-b.thumb"), "Ack");
        assertEquals("bad-domain", ((Message.Error) ownName).reason());
        ownName = node.debugRequest(new Message.ChallengeSet("x.hub.test", "tok-c", "tok-c.thumb"), "Ack");
        assertEquals("bad-domain", ((Message.Error) ownName).reason());

        // A hub sub-name keeps working next to it, and the hub refuses unknown domains outright.
        JsonObject named = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", app.getAddress().getPort()).put("name", "plain").build());
        assertTrue(named.optBool("ok", false), named.toString());
        assertTrue(get("plain.hub.test", "/").startsWith("200 "));
        boolean refused = false;
        try {
            get("other.example.test", "/");
        } catch (Exception e) {
            refused = true;
        }
        assertTrue(refused);

        // Restart the node: the stored certificate is reused (no new order) and the domain comes
        // back. Waiting for the domain to go before waiting for it to return is what the first loop
        // is for: the record from before the restart stands until the hub notices the node has
        // left, so a wait that only looks for a record can end on that stale one, and then the
        // request below reaches a hub with no connection to the node and fails the handshake. Seen
        // once in about sixty runs on windows-2025, never on a faster machine. Waiting for the
        // record to come back cannot end early the same way: it is the restarted node's own
        // LinkOpen that puts it there, over the session the request needs.
        node.close();
        long deadline = System.currentTimeMillis() + 15_000;
        while (hub.links().byDomain(DOMAIN) != null && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        assertNull(hub.links().byDomain(DOMAIN), "the hub kept the domain after the node left");
        node = new Daemon(NodeConfig.in(root.resolve("node")));
        node.start();
        while (hub.links().byDomain(DOMAIN) == null && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        assertEquals(1, ca.orders);
        assertEquals("200 hello from " + DOMAIN, get(DOMAIN, "/"));
        JsonObject ls = Ipc.call(sock, JsonObject.builder().put("cmd", "ls").build());
        assertTrue(ls.toString().contains("certExpiresAt"), ls.toString());

        // A domain does not change hands on a claim, however well proven: the same rule as a name
        // (§8.2). Alice still holds the key and the certificate, but the record says the domain is
        // bob's, so the hub refuses and the operator has to release it first.
        hub.store().claimDomain(DOMAIN, "bob", "m_bob");
        JsonObject retake = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", app.getAddress().getPort())
            .put("domain", DOMAIN).put("acmeDirectory", ca.base + "/directory").put("acmeEmail", "alice@example.test").build());
        assertTrue(!retake.optBool("ok", false), retake.toString());
        assertEquals("taken", retake.optString("error", null));
        assertEquals("bob", hub.store().domain(DOMAIN).user());
    }
}
