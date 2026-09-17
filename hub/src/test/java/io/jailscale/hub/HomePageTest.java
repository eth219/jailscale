package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import java.nio.file.Files;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

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
        java.net.ServerSocket portSocket = TestPorts.listen(1024);
        port = portSocket.getLocalPort();
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, false, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.listenOn(portSocket);
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
        HttpResponse invite = http("GET", "/join/" + enc("not-a-real-token"), null, null);
        assertTrue(invite.bodyText().contains(meta));
        // The one page here whose body is a credential is also the one that must not be kept: the
        // two that carry nothing secret said no-store while this one did not.
        assertEquals("no-store", invite.headers().get("Cache-Control"));
        assertTrue(http("GET", "/admin", null, null).bodyText().contains(meta));

        String home = http("GET", "/", null, null).bodyText();
        assertFalse(home.contains("name=\"robots\""), home);
    }

    /**
     * The half of the grading that has to hold for the other half to mean anything: a hub with
     * nothing wrong says so, in one line, and carries no warning on any row. A page that graded
     * everything, or a verdict hard-coded to "Degraded", passes every assertion in the test below
     * and fails here.
     */
    @Test
    void aHubWithNothingWrongSaysSoInOneLineAndMarksNoRow() throws Exception {
        String page = http("GET", "/", null, null).bodyText();
        assertTrue(page.contains("All systems operational"), page);
        assertFalse(page.contains("<b>Warning</b>"), "nothing here is wrong: " + page);
        assertFalse(page.contains("<b>Critical</b>"), "nothing here is wrong: " + page);
        // The dot is beside the words and never instead of them (the rule the strips follow).
        assertTrue(page.contains("class=\"verdict\""), page);
    }

    /**
     * And the direction it fails in: a hub whose only node has gone is degraded, the line says which
     * row to look at, and that row is marked. The node is registered throughout -- what changed is
     * that it is not online -- so this cannot pass by the hub simply forgetting it.
     */
    @Test
    void aRegisteredNodeThatIsOfflineIsNamedInTheVerdictAndMarkedOnItsRow() throws Exception {
        loginAsAdmin();
        assertEquals(1, hub.store().nodes().size());
        assertTrue(http("GET", "/", null, null).bodyText().contains("All systems operational"));

        alice.close();
        alice = null;
        waitFor(() -> hub.registry().size() == 0);

        String page = http("GET", "/", null, null).bodyText();
        assertEquals(1, hub.store().nodes().size(), "still registered, just not online");
        assertTrue(page.contains("Degraded &mdash; the one registered node is offline"), page);
        assertTrue(page.contains("<b>Warning</b>: 0 online of 1 registered"), page);
        assertFalse(page.contains("All systems operational"), page);
    }

    /**
     * The thresholds, at values no fixture can hold: a certificate six days from expiry cannot be a
     * test resource, because it would have to be reissued every week to stay six days away. The
     * boundaries are asserted on both sides, since an off-by-one here is the difference between
     * being told on the last day and being told on the day after.
     */
    @Test
    void theCertificateIsGradedByHowMuchLifeIsLeft() {
        long day = 86_400_000L;
        assertEquals(HttpFront.Health.OK, HttpFront.certificateHealth(true, 90 * day));
        assertEquals(HttpFront.Health.OK, HttpFront.certificateHealth(true, 14 * day));
        assertEquals(HttpFront.Health.WARNING, HttpFront.certificateHealth(true, 14 * day - 1));
        assertEquals(HttpFront.Health.WARNING, HttpFront.certificateHealth(true, 3 * day));
        assertEquals(HttpFront.Health.CRITICAL, HttpFront.certificateHealth(true, 3 * day - 1));
        assertEquals(HttpFront.Health.CRITICAL, HttpFront.certificateHealth(true, 0));
        assertEquals(HttpFront.Health.CRITICAL, HttpFront.certificateHealth(true, -5 * day));
        // Not loaded is not the same as expired: nothing is being served, and nothing has failed.
        assertEquals(HttpFront.Health.WARNING, HttpFront.certificateHealth(false, 0));
    }

    /**
     * The two words the line can say and everything it says after them. A live hub can be driven
     * into one grade at a time, so the tests above never reach "Critical" at all and never reach
     * two problems at once: a verdict hard-coded to "Degraded", or one that named only the first
     * problem it found, passes every one of them. This drives the renderer directly, where both
     * are reachable.
     */
    @Test
    void theVerdictTakesTheWorstGradeAndNamesEveryProblemUnderIt() {
        HttpFront.Problem ok = new HttpFront.Problem(HttpFront.Health.OK, "");
        HttpFront.Problem warning = new HttpFront.Problem(HttpFront.Health.WARNING, "a warning");
        HttpFront.Problem critical = new HttpFront.Problem(HttpFront.Health.CRITICAL, "a critical");
        assertTrue(HttpFront.verdict(List.of(ok, ok)).contains("All systems operational"));
        assertTrue(HttpFront.verdict(List.of(ok, warning)).contains("Degraded &mdash; a warning"));
        // Critical takes the word, and does not hide the warning underneath it: worst named first.
        String both = HttpFront.verdict(List.of(warning, critical));
        assertTrue(both.contains("Critical &mdash; a critical; a warning"), both);
        assertFalse(both.contains("Degraded"), both);
        // The dot never carries it alone, on this line as on the strips (§13.2).
        assertTrue(both.contains("class=\"sw\""), both);
    }

    /**
     * The headers every answer on this name carries, checked on the four shapes of answer there
     * are: a page, the JSON, an error, and the admin front. They are applied at the write and not
     * in each handler precisely so that this holds for a route nobody thought about, which is why
     * the admin 403 is in the list -- its forms are what {@code form-action} and
     * {@code frame-ancestors} are for.
     */
    @Test
    void everyAnswerOnThisNameCarriesTheSameSecurityHeaders() throws Exception {
        for (String path : new String[] {"/", "/links", "/v1/status", "/admin", "/no-such-page"}) {
            HttpResponse r = http("GET", path, null, null);
            String csp = r.headers().get("Content-Security-Policy");
            assertNotNull(csp, path);
            assertTrue(csp.contains("default-src 'none'"), path + ": " + csp);
            assertTrue(csp.contains("frame-ancestors 'none'"), path + ": " + csp);
            assertTrue(csp.contains("form-action 'self'"), path + ": " + csp);
            assertEquals("nosniff", r.headers().get("X-Content-Type-Options"), path);
            assertEquals("no-referrer", r.headers().get("Referrer-Policy"), path);
            // And no HSTS, which is a decision and not an omission (#98): it is scoped to the host
            // and not the port, so it would pin this hub's raw TCP ports to https as well, and
            // those speak no TLS. A year, and nobody can take it back.
            assertNull(r.headers().get("Strict-Transport-Security"), path);
        }
    }

    /** The icon, under both names, and linked from the frame so the second name is rarely asked for. */
    @Test
    void theHubHasAnIconAndServesItUnderBothNames() throws Exception {
        for (String path : new String[] {"/favicon.svg", "/favicon.ico"}) {
            HttpResponse r = http("GET", path, null, null);
            assertEquals(200, r.status(), path);
            assertEquals("image/svg+xml", r.headers().get("Content-Type"), path);
            assertTrue(r.bodyText().startsWith("<svg"), path);
        }
        String link = "<link rel=\"icon\" href=\"/favicon.svg\">";
        assertTrue(http("GET", "/", null, null).bodyText().contains(link));
        // The admin front builds a frame of its own, which is how it came to be the half of the hub
        // without an icon. Its 403 is that frame with no session needed to reach it, so dropping the
        // link there fails here rather than passing on the strength of the pages out front.
        assertTrue(http("GET", "/admin", null, null).bodyText().contains(link), "the admin frame links it too");
    }

    /**
     * The hub's own page introduces itself to whatever unfurls it; the other two do not, and that
     * is the half that can fail. A block of meta tags added to the shared frame would give an
     * invitation -- whose URL is a credential -- a card in a chat window, and would put other
     * people's names in a preview of the directory.
     */
    @Test
    void onlyTheHubsOwnPageOffersItselfForAPreview() throws Exception {
        String home = http("GET", "/", null, null).bodyText();
        assertTrue(home.contains("<meta property=\"og:title\" content=\"hub.test\">"), home);
        assertTrue(home.contains("<meta name=\"description\""), home);
        assertTrue(home.contains("<meta name=\"twitter:card\" content=\"summary\">"), home);

        assertFalse(http("GET", "/links", null, null).bodyText().contains("og:"), "the directory is not a card");
        assertFalse(http("GET", "/join/" + enc("not-a-real-token"), null, null).bodyText().contains("og:"),
            "an invitation is not a card");
    }

    /**
     * A person who mistypes gets the page, with the way back on it. A node's client does not: the
     * 426 that answers a control connection without an Upgrade is for a machine, and framing it
     * would be bytes that reader has to skip. That second assertion is what stops this from being
     * satisfied by wrapping everything.
     */
    @Test
    void whatAPersonCanMistypeIsAPageAndWhatAMachineAsksForIsNot() throws Exception {
        HttpResponse missing = http("GET", "/no-such-page", null, null);
        assertEquals(404, missing.status());
        assertTrue(missing.headers().get("Content-Type").startsWith("text/html"), missing.headers().get("Content-Type"));
        String body = missing.bodyText();
        assertTrue(body.contains("<a href=\"/\">Hub</a>"), "a way back: " + body);
        assertTrue(body.contains("/no-such-page"), body);
        assertTrue(body.contains("noindex"), "an error page is not for an index: " + body);

        HttpResponse machine = http("POST", "/v1/noise", null, "");
        assertEquals(426, machine.status());
        assertTrue(machine.headers().get("Content-Type").startsWith("text/plain"), machine.bodyText());
        // The paths a scraper or a crawler holds are answered the same way, on both the method
        // they got wrong and the path that moved: a poll every fifteen seconds should not be
        // downloading a page to discard.
        for (String path : new String[] {"/metrics", "/robots.txt", "/v1/key"}) {
            HttpResponse wrongMethod = http("POST", path, null, "");
            assertEquals(405, wrongMethod.status(), path);
            assertEquals("GET, HEAD", wrongMethod.headers().get("Allow"), path);
            assertTrue(wrongMethod.headers().get("Content-Type").startsWith("text/plain"), path);
        }
        HttpResponse moved = http("GET", "/metrics", null, null);
        assertEquals(404, moved.status());
        assertTrue(moved.headers().get("Content-Type").startsWith("text/plain"), moved.bodyText());
        assertTrue(moved.bodyText().contains("--metrics-listen"), moved.bodyText());
    }

    /**
     * The numbers the strip draws, in text. A hub that was down for 42 minutes three days ago has to
     * say so somewhere a phone, a keyboard and a screen reader can reach -- the tooltip is none of
     * those -- and the number has to be the one {@code /v1/status} reports, or the picture and the
     * table behind it have quietly come apart.
     *
     * <p>The record is written to disk before the hub starts, because that is how a real gap is
     * made: {@link Availability} books the interval between the last stamp and the start as down,
     * and a gap in the file is a period a previous process recorded and this one inherits.
     */
    @Test
    void theDaysThatWereNotGreenAreNamedInTextAndMatchTheJson() throws Exception {
        Path root2 = TestDirs.newRoot("avail");
        Path state = root2.resolve("hub");
        Files.createDirectories(state);
        long now = System.currentTimeMillis();
        long day = 86_400_000L;
        long downFrom = now - 3 * day - 12 * 3_600_000L;
        Files.writeString(state.resolve("availability.json"), JsonObject.builder()
            .put("since", now - 30 * day)
            .put("lastStamp", now)
            .put("gaps", java.util.List.of(java.util.List.of(downFrom, downFrom + 42 * 60_000L)))
            .put("peers", JsonObject.builder().build())
            .toJson());

        java.net.ServerSocket port2Socket = TestPorts.listen(1024);
        int port2 = port2Socket.getLocalPort();
        Hub down = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port2), state, "127.0.0.1", port2,
            CERT, KEY, false, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        down.listenOn(port2Socket);
        try {
            down.start();
        } catch (Exception e) {
            down.close();   // as in AdminCommandTest: a throw here would otherwise leak the socket
            throw e;
        }
        try {
            String page = get(port2, "/").bodyText();
            assertTrue(page.contains("<details>"), "the numbers have to be reachable without a hover: " + page);
            // The row, not the count: Availability books the interval between the written lastStamp
            // and this process starting as down too, and on a slow enough machine that rounds to a
            // minute and becomes a second row. What has to be there is the outage that was written.
            assertTrue(page.contains("42 min down"), page);
            assertTrue(page.contains("with downtime, of the last 30"), "the summary says what, not what colour: " + page);

            // The same number, from the same array, in the answer a monitor reads. The tooltip and
            // this list and the JSON are three renderings of one thing, and this is what says so.
            JsonObject status = Json.parseObject(get(port2, "/v1/status").bodyText());
            assertTrue(status.object("availability").object("process").array("downMinutesPerDay").toString().contains("42"),
                status.toString());
        } finally {
            down.close();
        }

        // And the other direction: the hub this class starts has nothing to report, so it says
        // nothing. Without this, a page that printed an empty details element on every hub -- or
        // thirty rows of "no record" -- would pass everything above.
        assertFalse(http("GET", "/", null, null).bodyText().contains("<details>"), "nothing was down here");
    }

    /** A page or a JSON answer from a hub other than the one this class starts. */
    private HttpResponse get(int p, String path) throws Exception {
        try (SSLSocket s = Tls.connect(Tls.clientContext(CERT, false), "hub.test", "127.0.0.1", p, true, 10_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", "hub.test", path, new Headers(), null);
            return Http.readResponse(s.getInputStream(), 1 << 20);
        }
    }

    /**
     * That the page carries these two facts at all, and that it takes them from the constants the
     * handshake enforces rather than from a number somebody typed. It cannot fail on a protocol
     * bump -- page and assertion read the same constant, which is the point of the page reading it
     * -- so what it catches is the paragraph going away, a number written by hand drifting from
     * {@code MIN_PROTO}, and the wrong one of the two branches below being taken. That the floor is
     * enforced at all is {@link ProtoSkewTest}'s.
     */
    @Test
    void thePageSaysWhichClientsThisHubTakesAndHowToCheckTheOneYouGet() throws Exception {
        String page = http("GET", "/", null, null).bodyText();
        assertTrue(page.contains("<b>protocol " + Message.PROTO + "</b>"), page);
        assertTrue(page.contains("<tr><td>Protocol</td><td>" + Message.PROTO), page);
        // The two are equal today, so the page says "nothing older"; when they part, it has to say
        // the floor instead, and this is the assertion that notices.
        if (NodeSession.MIN_PROTO == Message.PROTO) {
            assertTrue(page.contains("nothing older"), page);
        } else {
            assertTrue(page.contains("protocol " + NodeSession.MIN_PROTO + " and newer"), page);
        }
        // A number the reader cannot get out of their own copy is one they can only check by
        // attempting a join, which is what this paragraph exists to spare them (#168). Held against
        // the paragraph and not the page: eight other places say <code>jailscale ...</code>, so a
        // whole-page contains() would stay green with this sentence moved somewhere it answers
        // nothing -- which is the move worth catching, the clause going away being the obvious one.
        int protocolPara = page.indexOf("<p>This hub speaks");
        assertTrue(protocolPara >= 0, page);
        String paragraph = page.substring(protocolPara, page.indexOf("</p>", protocolPara));
        assertTrue(paragraph.contains("<code>jailscale version</code>"),
            "the paragraph naming this hub's protocol does not say where to get the reader's own: " + paragraph);

        // And the file the reader is about to download, which is the one they can do something
        // about -- the paragraph further down is about the hub's own binary and is not this.
        assertTrue(page.contains("jailscale update --download"), page);
        assertTrue(page.contains("SHA256SUMS.txt"), page);
        assertTrue(page.contains("docs/release-verification.md"), page);
        // The signature is over RELEASE.txt and not over the checksum list, which the page said
        // until review; the two are one step apart and the page has to get the step right.
        assertTrue(page.contains("RELEASE.txt"), page);
    }

    /**
     * The operator block, and the half that matters more: a hub nobody has configured says nothing
     * at all. The alternative shape -- a section on every hub reading "operator: not set" -- is a
     * worse page for the case that needs it least, and it is what this would quietly become if the
     * condition were ever dropped.
     */
    @Test
    void whoRunsThisHubAppearsOnlyWhenSomebodyHasSaidSo() throws Exception {
        String bare = http("GET", "/", null, null).bodyText();
        assertFalse(bare.contains("Who runs this hub"), "nothing was configured: " + bare);
        assertFalse(bare.contains("What it keeps"), bare);
        // And the sentence this issue exists to replace stays on the hub that has not replaced it.
        assertTrue(bare.contains("rather than one to depend on"), bare);

        hub.store().setSetting(Store.SETTING_OPERATOR, "Example Ltd");
        hub.store().setSetting(Store.SETTING_CONTACT, "mailto:abuse@example.com");
        hub.store().setSetting(Store.SETTING_TERMS, "https://example.com/aup");
        String named = http("GET", "/", null, null).bodyText();
        // With an id, because the closing line below links back to it.
        assertTrue(named.contains("<h2 id=\"who\">Who runs this hub</h2>"), named);
        assertTrue(named.contains("Run by <b>Example Ltd</b>"), named);
        assertTrue(named.contains("<a href=\"mailto:abuse@example.com\">Contact</a>"), named);
        assertTrue(named.contains("<a href=\"https://example.com/aup\">What is allowed here</a>"), named);
        // The retention sentence is the part an operator cannot write for themselves, so it is not
        // theirs to configure: it says what the process does, and where that stops.
        assertTrue(named.contains("thirty days of uptime record"), named);
        assertTrue(named.contains("keeps no list"), named);
        assertTrue(named.contains("is the operator's and not something this page can answer for"), named);
        // Three attempts at an inventory were each found short, so the sentence says the shape of
        // what is kept rather than a list that goes stale the next time the store grows -- and
        // names the two parts a visitor is actually asking about: what a machine said about itself,
        // and that it stays until somebody removes it.
        assertTrue(named.contains("its hostname, its system, and the address it knocked from"), named);
        assertTrue(named.contains("stays until the"), named);
        assertTrue(named.contains("<b>Not the visitors.</b>"), named);
        // The closing line is the point of the issue: a hub that has named an operator stops
        // telling visitors not to depend on it and points at who to ask instead.
        assertFalse(named.contains("rather than one to depend on"), named);
        assertTrue(named.contains("Who that is, and on what terms"), named);

        // One of the three is enough to draw it, since a hub that names only where to write has
        // said the thing that matters most.
        hub.store().setSetting(Store.SETTING_OPERATOR, "");
        hub.store().setSetting(Store.SETTING_TERMS, "");
        String contactOnly = http("GET", "/", null, null).bodyText();
        assertTrue(contactOnly.contains("Who runs this hub"), contactOnly);
        assertFalse(contactOnly.contains("Run by <b>"), contactOnly);
        assertFalse(contactOnly.contains("What is allowed here"), contactOnly);
        // And the closing line goes with the section and not with the operator name: one of the
        // three is what draws the block, so one of the three is what has to replace the warning.
        // This is the case where two separately written conditions would part, leaving a link to
        // an anchor that was never drawn.
        assertTrue(contactOnly.contains("<a href=\"#who\">Who runs this hub</a>"), contactOnly);
        assertFalse(contactOnly.contains("rather than one to depend on"), contactOnly);

        // A setting also arrives from the replication stream, where AdminIpc's rule never ran, so
        // the page cannot assume it was stripped on the way in: the store is written directly here
        // to stand for a primary that strips nothing. Blank has to be unset on this side too, or
        // the block is drawn around an empty name and the warning is dropped on the strength of it.
        hub.store().setSetting(Store.SETTING_CONTACT, "   ");
        String blank = http("GET", "/", null, null).bodyText();
        assertFalse(blank.contains("Who runs this hub"), blank);
        assertTrue(blank.contains("rather than one to depend on"), blank);

        // And the scheme, for the same reason and by the same route: written straight to the store
        // to stand for a peer running a build from before the rule. A check that guards only the
        // door an admin knocks on is not a check, so this is what says the read side has one --
        // drop it and every assertion above still passes.
        hub.store().setSetting(Store.SETTING_CONTACT, "javascript:alert(1)");
        String hostile = http("GET", "/", null, null).bodyText();
        assertFalse(hostile.contains("javascript:"), hostile);
        assertFalse(hostile.contains("Who runs this hub"), hostile);
        assertTrue(hostile.contains("rather than one to depend on"), hostile);

        // The two settings do not take the same values -- terms refuses mailto: where it is set --
        // so the page has to read each one against its own rule rather than against "is this a
        // link at all", or an address a peer replicated in is published as terms of use.
        hub.store().setSetting(Store.SETTING_CONTACT, "");
        hub.store().setSetting(Store.SETTING_TERMS, "mailto:legal@example.com");
        String wrongTerms = http("GET", "/", null, null).bodyText();
        assertFalse(wrongTerms.contains("What is allowed here"), wrongTerms);
        assertFalse(wrongTerms.contains("Who runs this hub"), wrongTerms);
    }
}
