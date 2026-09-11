package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The hub's own page. Counts and resource use are public because they describe the service; the
 * node list and the controls over it are for a signed-in admin only.
 */
@Timeout(120)
class HomePageTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private int port;
    private Daemon alice;

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("home");
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, false, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.start();
    }

    @AfterEach
    void stop() throws Exception {
        if (alice != null) {
            alice.close();
        }
        hub.close();
    }

    private HttpResponse http(String method, String path, String cookie, String form) throws Exception {
        try (SSLSocket s = Tls.connect(Tls.clientContext(CERT, false), "hub.test", "127.0.0.1", port, true, 10_000)) {
            Headers h = new Headers();
            if (cookie != null) {
                h.add("Cookie", cookie);
            }
            byte[] body = null;
            if (form != null) {
                h.add("Content-Type", "application/x-www-form-urlencoded");
                body = form.getBytes(StandardCharsets.UTF_8);
            }
            Http.writeRequest(s.getOutputStream(), method, "hub.test", path, h, body);
            return Http.readResponse(s.getInputStream(), 1 << 20);
        }
    }

    /** Joins alice as the first admin and returns her session cookie for the web pages. */
    private String loginAsAdmin() throws Exception {
        Invites.Created boot = hub.invites().create(null, 1, 3600, "test", true);
        alice = new Daemon(NodeConfig.in(root.resolve("alice")));
        alice.start();
        Path sock = root.resolve("alice/jailscale.sock");
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("invite", boot.url())
            .put("addr", "127.0.0.1").put("user", "alice").put("caFile", CERT.toString()).build()).optBool("ok", false));
        JsonObject link = Ipc.call(sock, JsonObject.builder().put("cmd", "admin").build());
        HttpResponse login = http("GET", URI.create(link.string("url")).getPath(), null, null);
        assertEquals(302, login.status());
        String setCookie = login.headers().get("Set-Cookie");
        assertNotNull(setCookie);
        return setCookie.substring(0, setCookie.indexOf(';'));
    }

    @Test
    void anyoneSeesStatusButNotWhoIsOnIt() throws Exception {
        HttpResponse r = http("GET", "/", null, null);
        assertEquals(200, r.status());
        String html = r.bodyText();
        assertTrue(html.contains("Status"), html);
        assertTrue(html.contains("Uptime"), html);
        assertTrue(html.contains("Nodes"), html);
        assertTrue(html.contains("Memory"), html);
        assertFalse(html.contains("mkey:"), "a node's key must not be on the public page");
        assertFalse(html.contains("Ban"), "controls must not be on the public page");
    }

    @Test
    void thePageSaysHowToJoinThisParticularHub() throws Exception {
        assertTrue(http("GET", "/", null, null).bodyText().contains("needs an invitation"));
        hub.store().setSetting(Store.SETTING_REGISTRATION, "open");
        String html = http("GET", "/", null, null).bodyText();
        assertTrue(html.contains("Registration is open"), html);
        assertTrue(html.contains("jailscale up --hub hub.test"), html);
    }

    @Test
    void anAdminSeesTheNodesAndCanRemoveOrBanFromTheSamePage() throws Exception {
        String cookie = loginAsAdmin();
        String html = http("GET", "/", cookie, null).bodyText();
        assertTrue(html.contains("Signed in as"), html);
        assertTrue(html.contains("mkey:"), "an admin should see the node list");
        assertTrue(html.contains("Remove"), html);
        assertTrue(html.contains("Ban"), html);
        assertTrue(html.contains("<code>127.0.0.1</code>"), "the address is needed to ban it: " + html);

        String csrf = csrfOf(html);
        // A ban placed from the status page returns to the status page, not to /admin.
        HttpResponse post = http("POST", "/admin/ban/add", cookie, "csrf=" + csrf + "&back=%2F&cidr=198.51.100.4&reason=test");
        assertEquals(302, post.status());
        assertEquals("/", post.headers().get("Location"));
        assertEquals(1, hub.store().bans().size());
        assertTrue(hub.bans().isBanned("198.51.100.4"));

        assertTrue(http("GET", "/", cookie, null).bodyText().contains("198.51.100.4"));

        // And lifting it works the same way.
        String csrf2 = csrfOf(http("GET", "/", cookie, null).bodyText());
        assertEquals(302, http("POST", "/admin/ban/remove", cookie, "csrf=" + csrf2 + "&back=%2F&cidr=198.51.100.4").status());
        assertEquals(0, hub.store().bans().size());
    }

    @Test
    void rubbishInTheBanFormIsRefused() throws Exception {
        String cookie = loginAsAdmin();
        String csrf = csrfOf(http("GET", "/", cookie, null).bodyText());
        HttpResponse r = http("POST", "/admin/ban/add", cookie, "csrf=" + csrf + "&cidr=" + enc("not-an-address"));
        assertEquals(400, r.status());
        assertEquals(0, hub.store().bans().size());
    }

    @Test
    void aBannedAddressCannotRegister() throws Exception {
        hub.store().setSetting(Store.SETTING_REGISTRATION, "open");
        hub.store().addBan("127.0.0.1", "test");
        Daemon bob = new Daemon(NodeConfig.in(root.resolve("bob")));
        try {
            bob.start();
            JsonObject r = Ipc.call(root.resolve("bob/jailscale.sock"), JsonObject.builder().put("cmd", "up")
                .put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port).put("user", "bob")
                .put("caFile", CERT.toString()).build());
            assertFalse(r.optBool("ok", false), "a banned address joined: " + r);
        } finally {
            bob.close();
        }
        assertEquals(0, hub.store().nodes().size());
    }

    @Test
    void banningAnAddressDisconnectsWhatItAlreadyHasAndKeepsItOut() throws Exception {
        String cookie = loginAsAdmin();
        waitFor(() -> hub.registry().size() == 1);

        String csrf = csrfOf(http("GET", "/", cookie, null).bodyText());
        assertEquals(302, http("POST", "/admin/ban/add", cookie,
            "csrf=" + csrf + "&back=%2F&cidr=127.0.0.1&reason=test").status());

        // Already connected is not good enough: the ban has to take the session down now.
        waitFor(() -> hub.registry().size() == 0);
        // The node keeps its registration. A ban is about where it is connecting from, and telling
        // it "revoked" would make it wipe a registration the hub still holds.
        assertEquals(1, hub.store().nodes().size(), "the node record should survive a ban of its address");
        assertTrue(Ipc.call(root.resolve("alice/jailscale.sock"), JsonObject.builder().put("cmd", "status").build())
            .optBool("registered", false), "a banned node was told its registration was revoked");
        Thread.sleep(1500);
        assertEquals(0, hub.registry().size(), "a banned node reconnected");
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

    private static String csrfOf(String html) {
        Matcher m = Pattern.compile("name=csrf value=\"([^\"]+)\"").matcher(html);
        assertTrue(m.find(), html);
        return m.group(1);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
