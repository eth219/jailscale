package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.file.Path;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * What a monitor reads (ARCHITECTURE.md §6.3), and from where. {@code /v1/status} is liveness on the
 * hub's public name; {@code /metrics} is the Prometheus text format on a listener of its own, which
 * this test binds to an ephemeral loopback port. Counters are asserted as deltas, because they
 * belong to the process and other tests in this JVM have been moving them.
 */
@Timeout(120)
class MetricsEndpointTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Hub hub;
    private int port;

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        Path root = TestDirs.newRoot("metrics");
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        // Port 0: the fixed default would collide with a second test JVM, and with whatever else
        // on this machine happens to own 9090.
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, false, HubConfig.POLICY_MEMBERS, true, "hub.test").withMetrics("127.0.0.1", 0));
        hub.start();
    }

    @AfterEach
    void stop() throws Exception {
        hub.close();
    }

    /** The hub's public name on 443, over TLS. */
    private HttpResponse get(String path) throws Exception {
        try (SSLSocket s = Tls.connect(Tls.clientContext(CERT, false), "hub.test", "127.0.0.1", port, true, 10_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", "hub.test", path, null, null);
            return Http.readResponse(s.getInputStream(), 1 << 20);
        }
    }

    /** The metrics listener: plain HTTP, loopback, no name and no certificate involved. */
    private HttpResponse scrape(String path) throws Exception {
        try (Socket s = new Socket("127.0.0.1", hub.metricsPort())) {
            s.setSoTimeout(10_000);
            Http.writeRequest(s.getOutputStream(), "GET", "127.0.0.1", path, null, null);
            return Http.readResponse(s.getInputStream(), 1 << 20);
        }
    }

    @Test
    void statusIsLivenessAndSaysWhichBuildIsUp() throws Exception {
        HttpResponse r = get("/v1/status");
        assertEquals(200, r.status());
        assertEquals("no-store", r.headers().get("Cache-Control"));
        JsonObject o = Json.parseObject(r.bodyText());
        assertTrue(o.optBool("ok", false), r.bodyText());
        assertEquals("hub.test", o.string("hostname"));
        assertEquals(Hub.version(), o.string("version"));
        assertTrue(o.lng("uptimeSeconds") >= 0, r.bodyText());
        // The certificate is the field worth alerting on, so it has to be a number, not "loaded".
        assertTrue(o.lng("certificateNotAfter") > 1_700_000_000L, r.bodyText());
    }

    /**
     * The public name answers how the hub is, not how much it is carrying. These fields were on
     * {@code /v1/status} and are on the metrics listener now; a stranger reading 443 gets neither
     * the hub's key nor its throughput.
     */
    @Test
    void statusDoesNotRepeatTheMetrics() throws Exception {
        String body = get("/v1/status").bodyText();
        for (String gone : new String[] {"hubKey", "binary", "nodesOnline", "nodesRegistered", "linksOpen",
            "relayBytes", "visitorsInFlight", "receiveBudgetBytes", "residentBytes"}) {
            assertFalse(body.contains(gone), gone + " is still on the public name: " + body);
        }
    }

    /** The scrape is not on the hub's own name at all, and says so in a way an operator can act on. */
    @Test
    void metricsAreGoneFromThePublicName() throws Exception {
        HttpResponse r = get("/metrics");
        assertEquals(404, r.status(), r.bodyText());
        assertFalse(r.bodyText().contains("jailhub_"), "the counters came back on 443: " + r.bodyText());
        assertTrue(r.bodyText().contains("--metrics-listen"), r.bodyText());
    }

    /** Nothing but the scrape lives on that port, whatever address an operator widens it to. */
    @Test
    void theMetricsListenerServesOnlyMetrics() throws Exception {
        assertEquals(404, scrape("/").status());
        assertEquals(404, scrape("/v1/status").status());
        assertEquals(404, scrape("/admin").status());
    }

    /** Nothing that names a person, a node or a link may be in what a stranger can scrape. */
    @Test
    void neitherEndpointCarriesWhoIsOnTheHub() throws Exception {
        String status = get("/v1/status").bodyText();
        String metrics = scrape("/metrics").bodyText();
        assertFalse(status.contains("mkey:"), status);
        assertFalse(metrics.contains("mkey:"), metrics);
        // No labels at all in the metrics except the build info, which is about the binary.
        for (String line : metrics.split("\n")) {
            if (line.startsWith("#") || line.startsWith("jailhub_build_info")) {
                continue;
            }
            assertFalse(line.contains("{"), "a labelled metric can leak what it counts: " + line);
        }
    }

    @Test
    void metricsIsTheTextFormatWithAHelpAndATypeForEveryName() throws Exception {
        HttpResponse r = scrape("/metrics");
        assertEquals(200, r.status());
        String body = r.bodyText();
        for (String name : new String[] {"jailhub_visitors_total", "jailhub_signatures_total",
            "jailhub_relay_bytes_total", "jailhub_nodes_online", "jailhub_links_open", "jailhub_uptime_seconds"}) {
            assertTrue(body.contains("# HELP " + name + " "), name + " has no HELP: " + body);
            assertTrue(body.contains("# TYPE " + name + " "), name + " has no TYPE: " + body);
            assertTrue(body.matches("(?s).*\n" + name + " \\d+\n.*") || body.startsWith(name + " "),
                name + " has no value: " + body);
        }
    }

    /** A visitor that reaches no link is still a visitor the hub turned away, and is counted. */
    @Test
    void aRefusedVisitorMovesTheRefusedCounter() throws Exception {
        long before = Metrics.VISITORS_REFUSED.sum();
        try (SSLSocket s = Tls.connect(Tls.clientContext(CERT, false), "nobody.hub.test", "127.0.0.1", port, true, 10_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", "nobody.hub.test", "/", null, null);
            Http.readResponse(s.getInputStream(), 1 << 20);
        } catch (Exception expected) {
            // the hub answers a name nobody serves with its own page or closes; either is a refusal
        }
        assertEquals(before + 1, Metrics.VISITORS_REFUSED.sum());
    }
}
