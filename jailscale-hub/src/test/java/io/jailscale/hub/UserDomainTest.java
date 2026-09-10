package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

/** DESIGN.md §9.4: a user domain, certified with the node's own key via http-01 relayed by the hub. */
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
        root = Files.createTempDirectory(Path.of("/tmp"), "jd");
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
        Message r = node.debugRequest(new Message.LinkOpen("https", null, DOMAIN, null, "127.0.0.1:1", null), "LinkOpened");
        assertEquals("domain-unverified", ((Message.LinkOpened) r).reason());
        r = node.debugRequest(new Message.LinkOpen("https", null, DOMAIN, null, "127.0.0.1:1", List.of(Files.readString(CERT))), "LinkOpened");
        assertEquals("domain-cert-name-mismatch", ((Message.LinkOpened) r).reason());
        r = node.debugRequest(new Message.LinkOpen("https", null, "x.hub.test", null, "127.0.0.1:1", null), "LinkOpened");
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

        // Restart the node: the stored certificate is reused (no new order) and the domain comes back.
        node.close();
        node = new Daemon(NodeConfig.in(root.resolve("node")));
        node.start();
        long deadline = System.currentTimeMillis() + 15_000;
        while (hub.links().byDomain(DOMAIN) == null && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        assertEquals(1, ca.orders);
        assertEquals("200 hello from " + DOMAIN, get(DOMAIN, "/"));
        JsonObject ls = Ipc.call(sock, JsonObject.builder().put("cmd", "ls").build());
        assertTrue(ls.toString().contains("certExpiresAt"), ls.toString());
    }
}
