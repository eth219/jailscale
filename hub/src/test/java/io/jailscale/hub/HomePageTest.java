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
        // §13.2: the columns are on the page, each with its tooltip, and the numbers behind them
        // are in the status JSON as well, so nothing is read from color or height alone.
        assertTrue(html.contains("<svg class=\"avail\""), html);
        assertTrue(html.contains("<title>") && html.contains("up throughout</title>"), html);
        assertTrue(html.contains("30 days ago") && html.contains("uptime</span><span>Today"), html);
        assertTrue(html.contains("Shorter bars are worse"), "colour is never the only channel: " + html);
        assertTrue(html.contains("Nodes"), html);
        assertTrue(html.contains("Memory"), html);
        assertFalse(html.contains("mkey:"), "a node's key must not be on the public page");
        assertFalse(html.contains("Ban"), "controls must not be on the public page");
    }

    @Test
    void thePageSaysHowToJoinThisParticularHub() throws Exception {
        String invite = http("GET", "/", null, null).bodyText();
        assertTrue(invite.contains("needs an invitation"), invite);
        assertTrue(invite.contains("jailscale up --invite"), invite);
        hub.store().setSetting(Store.SETTING_REGISTRATION, "open");
        String html = http("GET", "/", null, null).bodyText();
        assertTrue(html.contains("Registration is open"), html);
        assertTrue(html.contains("jailscale up --hub hub.test"), html);
    }

    /**
     * Either way round, the page has to answer the two questions that come before joining: where the
     * binary is, and what joining is for. It used to answer neither.
     */
    @Test
    void thePageSaysWhereTheBinaryIsAndWhatToDoWithIt() throws Exception {
        String html = http("GET", "/", null, null).bodyText();
        assertTrue(html.contains("github.com/eth219/jailscale/releases/latest"), html);
        assertTrue(html.contains("jailscale open 3000"), html);
        assertTrue(html.contains("https://&lt;name&gt;.hub.test"), html);
    }

    /**
     * What the hub can do with the traffic, and what it allows, taken from the constants that
     * enforce them rather than written out beside them.
     */
    @Test
    void thePageSaysWhatItCanSeeAndWhatItLimits() throws Exception {
        String html = http("GET", "/", null, null).bodyText();
        assertTrue(html.contains("What this hub can see"), html);
        assertTrue(html.contains("jailscale verify"), html);
        assertTrue(html.contains("Limits"), html);
        assertTrue(html.contains(SniRouter.MAX_PER_NAME + " at once"), html);
        assertTrue(html.contains(">" + Links.MAX_LINKS_PER_NODE + "<"), html);
        assertTrue(html.contains(HttpFront.HANDSHAKE_BURST + " per address"), html);
    }

    /**
     * Which build and which key this hub is running. The key is the string a node pins, character
     * for character, and {@code /v1/key} already serves it unauthenticated, so printing it gives
     * nothing away; what it buys is a second place to compare against what the node kept.
     */
    @Test
    void thePageNamesTheBuildAndTheKeyItIsRunning() throws Exception {
        String html = http("GET", "/", null, null).bodyText();
        assertTrue(html.contains("<code>" + hub.keys().publicText() + "</code>"), html);
        assertFalse(html.contains("Next hub key"), "no rotation is in progress: " + html);
        // No jailhub executable exists on a JVM, so the row is absent rather than a digest of java.
        assertFalse(html.contains("<td>Binary</td>"), html);
        // And what the two of them are worth is on the page beside them, not only in the docs.
        assertTrue(html.contains("a dishonest hub prints whatever it likes here"), html);
    }

    /** During a rotation a node accepts either key, so the page has to name both or mislead. */
    @Test
    void aRotationInProgressNamesBothKeys() throws Exception {
        String next = hub.keys().beginRotation();
        String html = http("GET", "/", null, null).bodyText();
        assertTrue(html.contains("<code>" + hub.keys().publicText() + "</code>"), html);
        assertTrue(html.contains("Next hub key"), html);
        assertTrue(html.contains("<code>" + next + "</code>"), html);
    }

    /** With nothing open the section still exists, and says so rather than showing an empty table. */
    @Test
    void anEmptyHubSaysSoInsteadOfShowingAnEmptyTable() throws Exception {
        String html = http("GET", "/", null, null).bodyText();
        assertTrue(html.contains("Open links"), html);
        assertTrue(html.contains("None open right now"), html);
    }

    /**
     * Two pages and two URLs, not one page with a script swapping panels: either can be sent to
     * someone, and both arrive with no script at all, which is the bargain the rest of this front
     * end makes. What is on which page is the point of the split -- the evidence that this hub is
     * up and worth joining stays on the front page, and the list that grows is the one that moved.
     */
    @Test
    void theDirectoryIsItsOwnUrlAndEachPageSaysWhereYouAre() throws Exception {
        String home = http("GET", "/", null, null).bodyText();
        assertTrue(home.contains("<span aria-current=\"page\">Hub</span>"), home);
        assertTrue(home.contains("<a href=\"/links\">Links</a>"), home);
        assertFalse(home.contains("<script"), "no script on either page: " + home);

        HttpResponse r = http("GET", "/links", null, null);
        assertEquals(200, r.status());
        String links = r.bodyText();
        assertTrue(links.contains("<span aria-current=\"page\">Links</span>"), links);
        assertTrue(links.contains("<a href=\"/\">Hub</a>"), links);
        assertTrue(links.contains("None open right now"), links);
        assertFalse(links.contains("<script"), "no script on either page: " + links);
        // The availability record is what says this hub is real, so it stays where a first visitor
        // lands rather than moving behind a click.
        assertTrue(home.contains("<svg class=\"avail\""), home);
        assertFalse(links.contains("<svg class=\"avail\""), links);
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

    /**
     * A build that is not a release has to say so where the version is printed. The string on its
     * own does not: "0.1.0-SNAPSHOT" reads as a release to anyone who does not know Maven, and the
     * live hub served exactly that for a fortnight after v0.1.2 shipped, from a binary that was
     * neither 0.1.0 nor current. Only a tag build replaces the pom's version, so every source,
     * `edge` and workflow_dispatch build lands here.
     */
    @Test
    void aBuildThatIsNotAReleaseSaysSoBesideItsVersion() throws Exception {
        String page = http("GET", "/", null, null).bodyText();
        boolean release = !Hub.version().endsWith("-SNAPSHOT") && !Hub.version().equals("dev");
        assertEquals(!release, page.contains("(not a release build)"),
            "the page and the version disagree about whether this is a release: " + Hub.version());
        // The tests run from a snapshot pom, so this is the branch that is actually exercised here;
        // if the pom ever carries a release version this assertion is what says the other one is.
        assertFalse(release, "expected the test build to be a snapshot, not " + Hub.version());
    }

    /**
     * Two mechanisms that pull in opposite directions, and the rule that decides which goes where.
     * A page that is disallowed is never fetched, so its {@code noindex} is never read -- which is
     * why the pages that must stay out of an index are the ones robots.txt does *not* name. The
     * assertions that give this test a direction to fail in are the negative ones: a robots.txt
     * that disallowed /links and /join, which is the intuitive and wrong thing to write, satisfies
     * every positive assertion here.
     */
    @Test
    void whatIsServedToWhoeverHoldsTheUrlIsKeptOutOfSearchAndTheHubPageIsNot() throws Exception {
        HttpResponse robots = http("GET", "/robots.txt", null, null);
        assertEquals(200, robots.status());
        assertEquals("text/plain; charset=utf-8", robots.headers().get("Content-Type"));
        String txt = robots.bodyText();
        assertTrue(txt.contains("User-agent: *"), txt);
        // Fetching a login link spends it, so that one is asked for by name.
        assertTrue(txt.contains("Disallow: /admin"), txt);
        // And these are not, on purpose: a crawler that is turned away at robots.txt never reads
        // the noindex, and a URL linked from somewhere else gets listed on the link alone -- which
        // for an invitation would publish the token.
        assertFalse(txt.contains("Disallow: /links"), "disallowing it is what stops the noindex being read: " + txt);
        assertFalse(txt.contains("Disallow: /join"), "an invitation must be fetchable for its noindex to count: " + txt);
        assertFalse(txt.contains("Disallow: /\n"), "the hub's own page is what the operator wants found: " + txt);

        String meta = "<meta name=\"robots\" content=\"noindex,nofollow\">";
        // An invitation renders for any token, because viewing one never spends it.
        assertTrue(http("GET", "/links", null, null).bodyText().contains(meta));
        assertTrue(http("GET", "/join/" + enc("not-a-real-token"), null, null).bodyText().contains(meta));
        assertTrue(http("GET", "/admin", null, null).bodyText().contains(meta));

        String home = http("GET", "/", null, null).bodyText();
        assertFalse(home.contains("name=\"robots\""), home);
    }
}
