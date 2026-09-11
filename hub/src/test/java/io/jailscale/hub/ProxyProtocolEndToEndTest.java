package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** ARCHITECTURE.md §8.5 (hub behind a TCP proxy sending PROXY headers) and §9.3 (node prepends one for the local app). */
@Timeout(90)
class ProxyProtocolEndToEndTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private int port;
    private Daemon node;
    private ServerSocket app;
    private ServerSocket proxy;
    private final List<String> firstLines = new CopyOnWriteArrayList<>();

    @AfterEach
    void stop() throws Exception {
        if (node != null) {
            node.close();
        }
        hub.close();
        app.close();
        if (proxy != null) {
            proxy.close();
        }
    }

    private void forward(Socket c) {
        try (c; Socket h = new Socket("127.0.0.1", port)) {
            h.getOutputStream().write(("PROXY TCP4 " + c.getInetAddress().getHostAddress() + " 127.0.0.1 " + c.getPort() + " 443\r\n")
                .getBytes(StandardCharsets.US_ASCII));
            Thread t = Thread.ofVirtual().start(() -> {
                try {
                    c.getInputStream().transferTo(h.getOutputStream());
                    h.shutdownOutput();
                } catch (IOException ignored) {
                    // done
                }
            });
            h.getInputStream().transferTo(c.getOutputStream());
            t.join();
        } catch (IOException | InterruptedException ignored) {
            // done
        }
    }

    /** The local app records the first line of every connection and answers HTTP. */
    private void serveApp(Socket c) {
        try (c) {
            BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream(), StandardCharsets.ISO_8859_1));
            String first = r.readLine();
            firstLines.add(first);
            String line;
            while ((line = r.readLine()) != null && !line.isEmpty()) {
                // headers
            }
            byte[] body = ("seen: " + first).getBytes(StandardCharsets.UTF_8);
            OutputStream out = c.getOutputStream();
            out.write(("HTTP/1.1 200 OK\r\nContent-Length: " + body.length + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write(body);
            out.flush();
        } catch (IOException ignored) {
            // done
        }
    }

    @Test
    void visitorAddressSurvivesTheProxyAndReachesTheApp() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("jp");
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        int rawLo;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            rawLo = s.getLocalPort();
        }
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test")
            .withProxyProtocol(true, List.of()).withPortRange(rawLo, rawLo));
        hub.start();
        app = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            while (!app.isClosed()) {
                try {
                    Socket c = app.accept();
                    Thread.ofVirtual().start(() -> serveApp(c));
                } catch (IOException e) {
                    return;
                }
            }
        });
        // The "proxy": a loopback forwarder that prepends a PROXY v1 line, as nginx stream / HAProxy would.
        proxy = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            while (!proxy.isClosed()) {
                try {
                    Socket c = proxy.accept();
                    Thread.ofVirtual().start(() -> forward(c));
                } catch (IOException e) {
                    return;
                }
            }
        });
        node = new Daemon(NodeConfig.in(root.resolve("node")));
        node.start();
        Path sock = root.resolve("node/jailscale.sock");
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", proxy.getLocalPort()).put("user", "alice").put("caFile", CERT.toString()).build()).optBool("ok", false));
        long deadline = System.currentTimeMillis() + 10_000;
        while (!node.hasCert(hub.tls().keyId()) && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        JsonObject open = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", app.getLocalPort()).put("name", "proxied")
            .put("proxyProtocol", true).build());
        assertTrue(open.optBool("ok", false), open.toString());

        // A visitor arriving through the proxy: PROXY v1 line, then TLS.
        try (Socket raw = new Socket("127.0.0.1", port)) {
            raw.getOutputStream().write("PROXY TCP4 203.0.113.5 10.0.0.1 51234 443\r\n".getBytes(StandardCharsets.US_ASCII));
            raw.getOutputStream().flush();
            SSLSocket tls = (SSLSocket) Tls.clientContext(CERT, false).getSocketFactory().createSocket(raw, "proxied.hub.test", port, true);
            javax.net.ssl.SSLParameters p = tls.getSSLParameters();
            p.setServerNames(List.of(new javax.net.ssl.SNIHostName("proxied.hub.test")));
            tls.setSSLParameters(p);
            tls.startHandshake();
            Http.writeRequest(tls.getOutputStream(), "GET", "proxied.hub.test", "/", new Headers(), null);
            HttpResponse r = Http.readResponse(tls.getInputStream(), 65536);
            assertEquals(200, r.status());
            assertEquals("seen: PROXY TCP4 203.0.113.5 127.0.0.1 51234 " + app.getLocalPort(), r.bodyText());
        }

        // Without the header the hub refuses: nothing may forge or skip the visitor address.
        boolean refused = false;
        try (SSLSocket tls = Tls.connect(Tls.clientContext(CERT, false), "proxied.hub.test", "127.0.0.1", port, true, 5000)) {
            tls.startHandshake();
            Http.writeRequest(tls.getOutputStream(), "GET", "proxied.hub.test", "/", new Headers(), null);
            Http.readResponse(tls.getInputStream(), 65536);
        } catch (IOException e) {
            refused = true;
        }
        assertTrue(refused);

        // Raw TCP links get the same treatment on both ends.
        JsonObject tcp = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", app.getLocalPort()).put("kind", "tcp")
            .put("proxyProtocol", true).build());
        assertTrue(tcp.optBool("ok", false), tcp.toString());
        try (Socket v = new Socket("127.0.0.1", tcp.integer("hubPort"))) {
            v.getOutputStream().write("PROXY TCP6 2001:db8::7 ::1 4000 22\r\nGET / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            v.getOutputStream().flush();
            HttpResponse r = Http.readResponse(v.getInputStream(), 65536);
            assertEquals("seen: PROXY TCP6 2001:db8:0:0:0:0:0:7 127.0.0.1 4000 " + app.getLocalPort(), r.bodyText());
        }
        assertEquals(2, firstLines.size());
    }
}
