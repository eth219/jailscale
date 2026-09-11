package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** ARCHITECTURE.md §9.3: the visitor gate, and Upgrade/bidirectional passthrough. */
@Timeout(90)
class GateAndUpgradeTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private int port;
    private Daemon alice;
    private Path sock;
    private ServerSocket app;

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("jg");
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.start();
        // Local app: plain GET -> text; "Upgrade: echo" -> 101 then a byte echo until EOF.
        app = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            while (!app.isClosed()) {
                try {
                    Socket c = app.accept();
                    Thread.ofVirtual().start(() -> serve(c));
                } catch (IOException e) {
                    return;
                }
            }
        });
        alice = new Daemon(NodeConfig.in(root.resolve("alice")));
        alice.start();
        sock = root.resolve("alice/jailscale.sock");
        JsonObject up = Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "alice").put("caFile", CERT.toString()).build());
        assertTrue(up.optBool("ok", false), up.toString());
        long deadline = System.currentTimeMillis() + 10_000;
        while (!alice.hasCert(hub.tls().keyId()) && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
    }

    private static void serve(Socket c) {
        try (c) {
            HttpRequest r = Http.readRequest(c.getInputStream(), 4096);
            OutputStream out = c.getOutputStream();
            if ("echo".equalsIgnoreCase(r.headers().get("Upgrade"))) {
                HttpResponse.upgrade("echo").writeTo(out);
                InputStream in = c.getInputStream();
                byte[] buf = new byte[1024];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                    out.flush();
                }
                return;
            }
            HttpResponse.text(200, "page " + r.path() + " cookie=" + r.headers().get("Cookie")).writeTo(out);
        } catch (Exception ignored) {
            // visitor gone
        }
    }

    @AfterEach
    void stop() throws Exception {
        alice.close();
        app.close();
        hub.close();
    }

    private SSLSocket connect(String host) throws Exception {
        return Tls.connect(Tls.clientContext(CERT, false), host, "127.0.0.1", port, true, 10_000);
    }

    private HttpResponse get(String host, String target, Headers headers) throws Exception {
        try (SSLSocket s = connect(host)) {
            Http.writeRequest(s.getOutputStream(), "GET", host, target, headers, null);
            return Http.readResponse(s.getInputStream(), 65536);
        }
    }

    @Test
    void gateRequiresVisitLinkThenCookie() throws Exception {
        JsonObject open = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", app.getLocalPort())
            .put("name", "private").put("gate", true).build());
        assertTrue(open.optBool("ok", false), open.toString());
        String visit = open.string("visitUrl");
        assertTrue(visit.startsWith("https://private.hub.test:" + port + "/?jail="), visit);
        String token = visit.substring(visit.indexOf("jail=") + 5);

        // No token: refused before anything reaches the local app.
        HttpResponse r = get("private.hub.test", "/secret", null);
        assertEquals(403, r.status());

        // Visit link: cookie set, redirected to the clean path (other query params kept).
        HttpResponse redirect = get("private.hub.test", "/deep?a=1&jail=" + token + "&b=2", null);
        assertEquals(302, redirect.status());
        assertEquals("/deep?a=1&b=2", redirect.headers().get("Location"));
        String setCookie = redirect.headers().get("Set-Cookie");
        assertNotNull(setCookie);
        assertTrue(setCookie.startsWith("jail=" + token + ";"), setCookie);
        assertTrue(setCookie.contains("HttpOnly") && setCookie.contains("Secure"), setCookie);

        // With the cookie: passes, and the local app sees the original request including the cookie.
        HttpResponse ok = get("private.hub.test", "/deep?a=1", new Headers().add("Cookie", "other=x; jail=" + token));
        assertEquals(200, ok.status());
        assertEquals("page /deep cookie=other=x; jail=" + token, ok.bodyText());

        // A wrong token is refused; a new link invalidates the old one; --off opens the link.
        assertEquals(403, get("private.hub.test", "/", new Headers().add("Cookie", "jail=nope")).status());
        JsonObject renew = Ipc.call(sock, JsonObject.builder().put("cmd", "gate").put("name", "private").build());
        assertTrue(renew.optBool("ok", false));
        assertEquals(403, get("private.hub.test", "/", new Headers().add("Cookie", "jail=" + token)).status());
        Ipc.call(sock, JsonObject.builder().put("cmd", "gate").put("name", "private").put("off", true).build());
        assertEquals(200, get("private.hub.test", "/", null).status());
    }

    @Test
    void upgradeStreamsPassThroughBothWays() throws Exception {
        JsonObject open = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", app.getLocalPort()).put("name", "wsock").build());
        assertTrue(open.optBool("ok", false), open.toString());
        try (SSLSocket s = connect("wsock.hub.test")) {
            Http.writeRequest(s.getOutputStream(), "GET", "wsock.hub.test", "/socket",
                new Headers().add("Connection", "Upgrade").add("Upgrade", "echo"), null);
            HttpResponse r = Http.readResponse(s.getInputStream(), 4096);
            assertEquals(101, r.status());
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            for (int i = 0; i < 20; i++) {
                byte[] msg = ("frame-" + i + "-" + "x".repeat(i * 300)).getBytes(StandardCharsets.US_ASCII);
                out.write(msg);
                out.flush();
                byte[] back = in.readNBytes(msg.length);
                assertEquals(new String(msg, StandardCharsets.US_ASCII), new String(back, StandardCharsets.US_ASCII));
            }
        }
    }
}
