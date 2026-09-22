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
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
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

    /**
     * Joins alice as the first admin. This used to go on and fetch a login link for the web pages;
     * #253 removed them, so what is left is the join, and the admin surface is {@link #admin}.
     */
    private void joinAsAdmin() throws Exception {
        Invites.Created boot = hub.invites().create(null, 1, 3600, "test", true);
        alice = new Daemon(NodeConfig.in(root.resolve("alice")));
        alice.start();
        Path sock = root.resolve("alice/jailscale.sock");
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("invite", boot.url())
            .put("addr", "127.0.0.1").put("user", "alice").put("caFile", CERT.toString()).build()).optBool("ok", false));
    }

    /**
     * One admin command through the handler behind the state-directory socket, which since #253 is
     * the only admin surface there is. Returns the last line the command replied with.
     */
    private JsonObject admin(JsonObject req) throws Exception {
        JsonObject[] last = new JsonObject[1];
        new AdminIpc(hub).handle(req, obj -> last[0] = obj);
        return last[0];
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

    /** One page and no script: what tells a first visitor this hub is real. */
    @Test
    void theHubPageIsOneUrlWithNoScript() throws Exception {
        String home = http("GET", "/", null, null).bodyText();
        assertFalse(home.contains("<script"), "no script on the page: " + home);
        assertFalse(home.contains("<nav>"), "one page, nothing to navigate to: " + home);
        assertTrue(home.contains("<h2>Status</h2>"), home);
    }

    /**
     * Placing and lifting a ban. This used to go through the admin page's form; #253 removed the
     * page, so it goes through the socket command that the form always stood in front of. The
     * assertions are on the store, which is where they were, so what the ban does is still checked
     * -- only the surface that asks for it has changed.
     */
    @Test
    void anAddressCanBeBannedAndUnbanned() throws Exception {
        joinAsAdmin();
        assertTrue(admin(JsonObject.builder().put("cmd", "ban-add")
            .put("cidr", "198.51.100.4").put("reason", "test").build()).optBool("ok", false));
        assertEquals(1, hub.store().bans().size());
        assertTrue(hub.bans().isBanned("198.51.100.4"));

        assertTrue(admin(JsonObject.builder().put("cmd", "ban-remove")
            .put("cidr", "198.51.100.4").build()).optBool("ok", false));
        assertEquals(0, hub.store().bans().size());
        assertFalse(hub.bans().isBanned("198.51.100.4"));
    }

    @Test
    void rubbishInABanIsRefused() throws Exception {
        joinAsAdmin();
        JsonObject r = admin(JsonObject.builder().put("cmd", "ban-add").put("cidr", "not-an-address").build());
        assertFalse(r.optBool("ok", false), "a ban of rubbish was accepted: " + r);
        assertTrue(r.optString("error", "").contains("not an address"), r.toString());
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
        joinAsAdmin();
        waitFor(() -> hub.registry().size() == 1);

        assertTrue(admin(JsonObject.builder().put("cmd", "ban-add")
            .put("cidr", "127.0.0.1").put("reason", "test").build()).optBool("ok", false));

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
     * why the page that must stay out of an index is one robots.txt does *not* name. The
     * assertions that give this test a direction to fail in are the negative ones: a robots.txt
     * that disallowed /join, which is the intuitive and wrong thing to write, satisfies every
     * positive assertion here.
     */
    @Test
    void whatIsServedToWhoeverHoldsTheUrlIsKeptOutOfSearchAndTheHubPageIsNot() throws Exception {
        HttpResponse robots = http("GET", "/robots.txt", null, null);
        assertEquals(200, robots.status());
        assertEquals("text/plain; charset=utf-8", robots.headers().get("Content-Type"));
        String txt = robots.bodyText();
        assertTrue(txt.contains("User-agent: *"), txt);
        // The one entry was /admin, because fetching a login link spent it. #253 removed the page,
        // so what is left is an empty Disallow, which is how robots.txt says "all of it".
        assertTrue(txt.contains("Disallow:"), txt);
        assertFalse(txt.contains("Disallow: /admin"), "the admin page is gone; robots.txt should not name it: " + txt);
        // And these are not, on purpose: a crawler that is turned away at robots.txt never reads
        // the noindex, and a URL linked from somewhere else gets listed on the link alone -- which
        // for an invitation would publish the token.
        assertFalse(txt.contains("Disallow: /join"), "an invitation must be fetchable for its noindex to count: " + txt);
        assertFalse(txt.contains("Disallow: /\n"), "the hub's own page is what the operator wants found: " + txt);

        String meta = "<meta name=\"robots\" content=\"noindex,nofollow\">";
        // An invitation renders for any token, because viewing one never spends it.
        HttpResponse invite = http("GET", "/join/" + enc("not-a-real-token"), null, null);
        assertTrue(invite.bodyText().contains(meta));
        // The one page here whose body is a credential is also the one that must not be kept: the
        // two that carry nothing secret said no-store while this one did not.
        assertEquals("no-store", invite.headers().get("Cache-Control"));
        // The error pages too, and the 500 frame is built by hand rather than through page(), so
        // it is asserted on directly -- it is the one frame left that could drift (#253 took the
        // other one with the admin page).
        assertTrue(http("GET", "/no-such-page", null, null).bodyText().contains(meta));
        assertTrue(HttpFront.ERROR_PAGE.contains(meta), HttpFront.ERROR_PAGE);

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
     * And the direction it fails in: a hub whose only node has gone is degraded, and the verdict
     * line says so with the count behind it. The node is registered throughout -- what changed is
     * that it is not online -- so this cannot pass by the hub simply forgetting it.
     *
     * <p>It used to add "and that row is marked", which was the admin table #253 removed. The
     * counts it asserts were always the public page's, so what is checked here is unchanged.
     */
    @Test
    void aRegisteredNodeThatIsOfflineIsNamedInTheVerdict() throws Exception {
        joinAsAdmin();
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
        // The dot never carries it alone, on this line as on the strips (§13).
        assertTrue(both.contains("class=\"sw\""), both);
    }

    /**
     * The headers every answer on this name carries, checked on the four shapes of answer there
     * are: a page, the JSON, an error, and the admin front. They are applied at the write and not
     * in each handler precisely so that this holds for a route nobody thought about, which is why a
     * path with no handler at all is in the list. {@code form-action} and {@code frame-ancestors}
     * were there for the admin page's forms and are asserted still, since #253 removed the forms
     * and not the policy.
     */
    @Test
    void everyAnswerOnThisNameCarriesTheSameSecurityHeaders() throws Exception {
        for (String path : new String[] {"/", "/v1/status", "/no-such-page"}) {
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
        // A second frame built by hand is how the hub came to have a half without an icon. The
        // admin front was that second frame until #253; the 500 page is the one left, and it is a
        // string constant rather than a route, so dropping the link from it fails here rather than
        // passing on the strength of the pages out front.
        assertTrue(HttpFront.ERROR_PAGE.contains(link), "the error frame links it too: " + HttpFront.ERROR_PAGE);
    }

    /**
     * The hub's own page introduces itself to whatever unfurls it; an invitation does not, and that
     * is the half that can fail. A block of meta tags added to the shared frame would give an
     * invitation -- whose URL is a credential -- a card in a chat window.
     */
    @Test
    void onlyTheHubsOwnPageOffersItselfForAPreview() throws Exception {
        String home = http("GET", "/", null, null).bodyText();
        assertTrue(home.contains("<meta property=\"og:title\" content=\"hub.test\">"), home);
        assertTrue(home.contains("<meta name=\"description\""), home);
        assertTrue(home.contains("<meta name=\"twitter:card\" content=\"summary\">"), home);

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
        // The directory that used to be here is a mistype now, and answered as one (#252).
        assertEquals(404, http("GET", "/links", null, null).status(), "the directory is gone");

        HttpResponse machine = http("POST", "/v1/noise", null, "");
        assertEquals(426, machine.status());
        assertTrue(machine.headers().get("Content-Type").startsWith("text/plain"), machine.bodyText());
        // The paths a crawler or a monitor holds are answered the same way when the method is
        // wrong: a poll every fifteen seconds should not be downloading a page to discard.
        for (String path : new String[] {"/robots.txt", "/v1/key"}) {
            HttpResponse wrongMethod = http("POST", path, null, "");
            assertEquals(405, wrongMethod.status(), path);
            assertEquals("GET, HEAD", wrongMethod.headers().get("Allow"), path);
            assertTrue(wrongMethod.headers().get("Content-Type").startsWith("text/plain"), path);
        }
    }

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
