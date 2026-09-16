package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** ARCHITECTURE.md §6.3: the admin page, logged in with a link the admin node obtained over the control channel. */
@Timeout(90)
class AdminWebTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private int port;
    private Daemon alice;
    private Daemon bob;

    @AfterEach
    void stop() throws Exception {
        if (alice != null) {
            alice.close();
        }
        if (bob != null) {
            bob.close();
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
            // The last argument is what frames a HEAD: the hub sends the Content-Length a GET would
            // have and no body, so a reader that took the length at face value would wait for bytes
            // that are not coming (HeadHasNoBodyTest).
            return Http.readResponse(s.getInputStream(), 1 << 20, method.equals("HEAD"));
        }
    }

    @Test
    void adminNodeLogsInAndApprovesAKnock() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("jw");
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, false, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.start();
        Invites.Created boot = hub.invites().create(null, 1, 3600, "test", true);

        alice = new Daemon(NodeConfig.in(root.resolve("alice")));
        alice.start();
        Path aSock = root.resolve("alice/jailscale.sock");
        assertTrue(Ipc.call(aSock, JsonObject.builder().put("cmd", "up").put("invite", boot.url().replace("hub.test", "hub.test"))
            .put("addr", "127.0.0.1").put("user", "alice").put("caFile", CERT.toString()).build()).optBool("ok", false));

        // bob knocks and waits.
        bob = new Daemon(NodeConfig.in(root.resolve("bob")));
        bob.start();
        Path bSock = root.resolve("bob/jailscale.sock");
        JsonObject knock = Ipc.call(bSock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "bob").put("caFile", CERT.toString()).build());
        assertEquals("pending", knock.string("status"), knock.toString());

        // Not logged in: 403. Bob (not admin) cannot get a link; alice can.
        assertEquals(403, http("GET", "/admin", null, null).status());
        Message denied = bob.debugRequest(new Message.AdminLinkRequest(), "AdminLink");
        assertTrue(denied instanceof Message.Error e && e.reason().equals("not-an-admin"), denied.toString());
        JsonObject link = Ipc.call(aSock, JsonObject.builder().put("cmd", "admin").build());
        assertTrue(link.optBool("ok", false), link.toString());
        String loginPath = URI.create(link.string("url")).getPath();
        assertTrue(loginPath.startsWith("/admin/login/"));

        // Fetching a login link is what spends it, and robots.txt is advice a link unfurler or a
        // browser prefetch never reads -- so the methods that cannot be a person clicking are
        // refused instead of consuming the token. These come before the GET below on purpose: if
        // either of them spent it, the GET would be the one-time second fetch and fail with 403.
        // Allow names GET alone, and not the GET, HEAD every other 405 on this hub says: a HEAD
        // here is the case the guard exists for, and RFC 9110 §15.5.6 requires the field to say
        // what would work -- which is the method that spends the token, not the one just refused.
        for (HttpResponse refused : new HttpResponse[] {
            http("HEAD", loginPath, null, null), http("POST", loginPath, null, "")}) {
            assertEquals(405, refused.status());
            assertEquals("GET", refused.headers().get("Allow"));
        }

        HttpResponse login = http("GET", loginPath, null, null);
        assertEquals(302, login.status());
        String setCookie = login.headers().get("Set-Cookie");
        assertNotNull(setCookie);
        String cookie = setCookie.substring(0, setCookie.indexOf(';'));
        assertEquals(403, http("GET", loginPath, null, null).status()); // one-time

        HttpResponse page = http("GET", "/admin", cookie, null);
        assertEquals(200, page.status());
        String html = page.bodyText();
        assertTrue(html.contains("Pending approval"), html);
        assertTrue(html.contains("bob") || html.contains("mkey:"), html);
        Matcher m = Pattern.compile("name=csrf value=\"([^\"]+)\"").matcher(html);
        assertTrue(m.find());
        String csrf = m.group(1);
        Matcher mk = Pattern.compile("name=mkey value=\"(mkey:[^\"]+)\"").matcher(html);
        assertTrue(mk.find());
        String bobKey = mk.group(1);

        // CSRF is enforced, whether the token is wrong or absent -- the absent case is a null
        // from the form map, which the comparison has to refuse rather than throw on.
        assertEquals(403, http("POST", "/admin/approve", cookie, "csrf=wrong&mkey=" + enc(bobKey) + "&user=bob").status());
        assertEquals(403, http("POST", "/admin/approve", cookie, "mkey=" + enc(bobKey) + "&user=bob").status());

        // Approve bob from the page; his daemon gets pushed the result.
        HttpResponse approve = http("POST", "/admin/approve", cookie, "csrf=" + csrf + "&mkey=" + enc(bobKey) + "&user=bobby");
        assertEquals(302, approve.status());
        long deadline = System.currentTimeMillis() + 10_000;
        while (!Ipc.call(bSock, JsonObject.builder().put("cmd", "status").build()).optBool("registered", false)
            && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        assertEquals("bobby", Ipc.call(bSock, JsonObject.builder().put("cmd", "status").build()).string("user"));

        // Create an invite from the page; it appears once with its secrets, and the store knows it.
        int before = hub.store().invites().size();
        assertEquals(302, http("POST", "/admin/invite/create", cookie, "csrf=" + csrf + "&user=carol&uses=2&ttl=1h").status());
        String after = http("GET", "/admin", cookie, null).bodyText();
        assertTrue(after.contains("/join/"), after);
        assertEquals(before + 1, hub.store().invites().size());

        // Auth keys from the page. Cleared fields mean the defaults, the way omitting the flag does
        // on the CLI and the way the invite form one row above already behaved -- they used to reach
        // parseInt and parseSeconds as "" and hand the admin a 400 quoting a Java parse error.
        assertEquals(302, http("POST", "/admin/authkey/create", cookie, "csrf=" + csrf + "&tag=ci&uses=&ttl=").status());
        assertEquals(1, hub.store().authKeys().size());
        Store.AuthKeyRec ak = hub.store().authKeys().get(0);
        assertEquals(1, ak.usesLeft(), "a blank uses field means one use");
        assertTrue(ak.expiresAt() > System.currentTimeMillis() + 6 * 86_400_000L, "a blank ttl field means 7d");

        // And the page cannot make the key the CLI is now refused: one with no uses left.
        HttpResponse dead = http("POST", "/admin/authkey/create", cookie, "csrf=" + csrf + "&tag=ci&uses=0&ttl=7d");
        assertEquals(400, dead.status());
        assertTrue(dead.bodyText().contains("uses must be at least 1"), dead.bodyText());
        assertEquals(1, hub.store().authKeys().size(), "the refused key was not created");

        // Settings: switch invite policy to admins; bob (not admin) may then only self-invite.
        assertEquals(302, http("POST", "/admin/settings", cookie, "csrf=" + csrf + "&invitePolicy=admins&registration=invite&knock=on").status());
        assertEquals("admins", hub.store().setting(Store.SETTING_INVITE_POLICY, "?"));
        JsonObject inv = Ipc.call(bSock, JsonObject.builder().put("cmd", "invite").put("user", "dave").build());
        assertTrue(!inv.optBool("ok", false) && inv.string("error").startsWith("policy"), inv.toString());
        assertTrue(Ipc.call(bSock, JsonObject.builder().put("cmd", "invite").put("self", true).build()).optBool("ok", false));

        // The shell login link works too, and keeps working: it is authorised by the IPC socket's
        // permissions and has no entry in the admin list for the per-request check to find.
        JsonObject shell = Ipc.call(root.resolve("hub/jailhub.sock"), JsonObject.builder().put("cmd", "admin-login-link").build());
        HttpResponse shellLogin = http("GET", URI.create(shell.string("url")).getPath(), null, null);
        assertEquals(302, shellLogin.status());
        String shellCookie = shellLogin.headers().get("Set-Cookie");
        shellCookie = shellCookie.substring(0, shellCookie.indexOf(';'));
        assertEquals(200, http("GET", "/admin", shellCookie, null).status());

        // The cookie carries the __Host- prefix, which bars a Domain attribute. Node links live on
        // siblings of the hub's own name, so without it a node could plant this cookie.
        assertTrue(setCookie.startsWith("__Host-"), setCookie);
        assertTrue(setCookie.contains("Path=/;") && setCookie.contains("Secure"), setCookie);

        // Losing admin ends the session immediately rather than at its twelve hour expiry.
        assertEquals(200, http("GET", "/admin", cookie, null).status());
        hub.store().removeAdmin("alice");
        assertEquals(403, http("GET", "/admin", cookie, null).status(), "removed admin kept access");
        assertEquals(403, http("POST", "/admin/approve", cookie, "csrf=" + csrf).status(), "removed admin could still act");

        // Logging out drops the session.
        hub.store().addAdmin("alice");
        HttpResponse back = http("GET", URI.create(Ipc.call(aSock, JsonObject.builder().put("cmd", "admin").build())
            .string("url")).getPath(), null, null);
        String c2 = back.headers().get("Set-Cookie");
        c2 = c2.substring(0, c2.indexOf(';'));
        String csrf2 = csrfOf(http("GET", "/admin", c2, null).bodyText());
        assertEquals(302, http("POST", "/admin/logout", c2, "csrf=" + csrf2).status());
        assertEquals(403, http("GET", "/admin", c2, null).status(), "session survived logout");
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
