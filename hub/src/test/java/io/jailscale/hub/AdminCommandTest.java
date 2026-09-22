package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Args;
import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * {@code jailhub <words>} to the request that goes down the admin socket
 * ({@link AdminIpc#requestFor}), and back to the case that answers it. Every admin command in the
 * binary passes through that one method, and none of it was covered: the seven verbs any test
 * reached were reached by building the {@code JsonObject} by hand, which is the half of the path
 * an operator never types.
 *
 * <p>The point of a table here is the derivation {@code <word0>-<word1>}: a subcommand renamed on
 * one side of the socket and not the other produces "unknown command" at runtime and nothing at
 * build time.
 */
@Timeout(90)
class AdminCommandTest {

    /** A command as typed, and the verb it has to become. */
    private record Route(String verb, String... argv) {
        String typed() {
            return "jailhub " + String.join(" ", argv);
        }
    }

    /** Every verb {@link AdminIpc#handle} answers, and the words that have to produce it. */
    private static List<Route> routes() {
        return List.of(
            new Route("status", "status"),
            new Route("node-list", "node", "list"),
            new Route("node-approve", "node", "approve", "3"),
            new Route("node-deny", "node", "deny", "3"),
            new Route("node-remove", "node", "remove", "3"),
            new Route("node-rename", "node", "rename", "3", "--user", "bob"),
            new Route("name-list", "name", "list"),
            new Route("name-reassign", "name", "reassign", "web", "--user", "bob"),
            new Route("name-release", "name", "release", "web"),
            new Route("ban-list", "ban", "list"),
            new Route("ban-add", "ban", "add", "203.0.113.7"),
            new Route("ban-remove", "ban", "remove", "203.0.113.7"),
            new Route("user-list", "user", "list"),
            new Route("user-remove", "user", "remove", "alice"),
            new Route("invite-create", "invite", "create"),
            new Route("invite-list", "invite", "list"),
            new Route("invite-revoke", "invite", "revoke", "inv_1"),
            new Route("admin-add", "admin", "add", "alice"),
            new Route("admin-remove", "admin", "remove", "alice"),
            new Route("key-rotate", "key", "rotate"),
            new Route("setting", "setting", "knock", "off"),
            new Route("address-check", "address", "check"));
    }

    private static JsonObject req(String... argv) {
        return AdminIpc.requestFor(Args.parse(argv, Main.FLAGS));
    }

    @Test
    void everyAdminVerbHasAWordThatReachesIt() {
        for (Route r : routes()) {
            assertEquals(r.verb(), req(r.argv()).string("cmd"), r::typed);
        }
    }

    /**
     * And the third side: a command an admin can run is a command the binary tells them about.
     * {@code name list}, {@code name reassign} and {@code name release} were routed, handled and
     * written up in ARCHITECTURE.md 11.4, and absent from the usage text -- so the way to take
     * back a claimed name was discoverable only by reading the source.
     *
     */
    @Test
    void everyRoutedVerbIsInTheUsageText() {
        for (Route r : routes()) {
            String line = Main.USAGE.lines()
                .filter(l -> l.strip().startsWith("jailhub " + r.argv()[0]))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no usage line for " + r.typed()));
            if (r.argv().length > 1 && !r.argv()[1].startsWith("--")) {
                assertTrue(line.contains(r.argv()[1]), r.typed() + " is not on its usage line: " + line.strip());
            }
        }
    }

    /**
     * And the other half of the pair: each of those verbs reaches a case in {@link AdminIpc#handle}
     * on a running hub. Only the fall-through reply proves a missing handler -- a verb that lands
     * and then refuses ("no node matches 3") has been routed, which is all this asserts.
     *
     */
    @Test
    void everyRoutedVerbLandsOnTheServer() throws Exception {
        Hub hub = startedHub();
        try {
            AdminIpc ipc = new AdminIpc(hub);
            for (Route r : routes()) {
                // Every field any case reads, so a verb that lands gets as far as its own objection.
                JsonObject req = JsonObject.builder().put("cmd", r.verb()).put("mkey", "3").put("user", "alice")
                    .put("cidr", "203.0.113.7").put("name", "web")
                    .put("id", "x").put("key", "knock").put("value", "off").put("tag", "ci").build();
                JsonObject[] last = new JsonObject[1];
                try {
                    ipc.handle(req, obj -> last[0] = obj);
                } catch (Exception e) {
                    continue; // it landed: a case ran far enough to object to the arguments
                }
                assertFalse(last[0] != null && ("unknown command " + r.verb()).equals(last[0].optString("error", "")),
                    r.verb() + " is routed from the CLI but has no case in AdminIpc.handle");
            }
        } finally {
            hub.close();
        }
    }

    /** {@code setting} is the one whose second word is a value, not part of the verb. */
    @Test
    void settingKeepsItsSecondWordAsTheKey() {
        JsonObject r = req("setting", "invitePolicy", "admins");
        assertEquals("setting", r.string("cmd"));
        assertEquals("invitePolicy", r.string("key"));
        assertEquals("admins", r.string("value"));
    }

    // --- what each verb carries -------------------------------------------------------------------

    @Test
    void aNodeIsNamedByWhateverTheOperatorHadToHand() {
        // The server resolves an id, a full mkey or a unique prefix; the CLI passes the word on.
        assertEquals("7", req("node", "approve", "7").string("mkey"));
        assertEquals("mkey:abcd", req("node", "remove", "mkey:abcd").string("mkey"));
        assertFalse(req("node", "approve", "7").has("user"), "no --user must stay absent, not empty");
        assertEquals("bob", req("node", "approve", "7", "--user", "bob").string("user"));
    }

    @Test
    void banCarriesItsReasonOnlyWhenGiven() {
        assertEquals("203.0.113.7", req("ban", "add", "203.0.113.7").string("cidr"));
        assertFalse(req("ban", "add", "203.0.113.7").has("reason"));
        assertEquals("noisy", req("ban", "add", "10.0.0.0/8", "--reason", "noisy").string("reason"));
        assertEquals("10.0.0.0/8", req("ban", "remove", "10.0.0.0/8").string("cidr"));
    }

    @Test
    void inviteCreateDefaultsAreTheServersToChoose() {
        JsonObject bare = req("invite", "create");
        assertFalse(bare.has("user"));
        assertEquals(0, bare.lng("uses"), "0 is the sentinel that lets the hub apply its own default");
        assertFalse(bare.has("ttl"), "an absent ttl must not become 0, which means something else");
        assertFalse(bare.bool("admin"));

        JsonObject full = req("invite", "create", "--user", "carol", "--uses", "3", "--ttl", "24h", "--admin");
        assertEquals("carol", full.string("user"));
        assertEquals(3, full.lng("uses"));
        assertEquals(86400, full.lng("ttl"));
        assertTrue(full.bool("admin"));
    }

    @Test
    void keyRotateLeavesTheGraceToTheServerUnlessAsked() {
        assertFalse(req("key", "rotate").has("grace"));
        assertEquals(30 * 86400, req("key", "rotate", "--grace", "30d").lng("grace"));
        assertEquals(1, req("key", "rotate", "--grace", "1").lng("grace"));
    }

    @Test
    void theRestCarryTheOneWordTheyNeed() {
        assertEquals("alice", req("user", "remove", "alice").string("user"));
        assertEquals("alice", req("admin", "add", "alice").string("user"));
        assertEquals("alice", req("admin", "remove", "alice").string("user"));
        assertEquals("inv_1", req("invite", "revoke", "inv_1").string("id"));
        assertEquals("web", req("name", "release", "web").string("name"));
        assertEquals("bob", req("name", "reassign", "web", "--user", "bob").string("user"));
    }

    // --- refusals ---------------------------------------------------------------------------------

    /**
     * The words a command cannot do without. Each is rejected here, in the CLI, rather than sent as
     * a request with a missing field for the server to fail on: {@code Main} turns an
     * {@link IllegalArgumentException} into the usage text and exit 2, and a request that reaches
     * the socket first gets "jailhub serve is not running" whenever the hub is down -- an answer
     * that sends the reader after the wrong problem.
     */
    @Test
    void aMissingWordIsNamedRatherThanSent() {
        record Missing(String says, String... argv) {}
        for (Missing m : List.of(
            new Missing("missing <node>", "node", "approve"),
            new Missing("missing <node>", "node", "deny"),
            new Missing("missing <node>", "node", "remove"),
            new Missing("missing <node>", "node", "rename"),
            new Missing("missing <user>", "user", "remove"),
            new Missing("missing <ip|cidr>", "ban", "add"),
            new Missing("missing <ip|cidr>", "ban", "remove"),
            new Missing("missing <name>", "name", "release"),
            new Missing("missing <id>", "invite", "revoke"),
            new Missing("missing <user>", "admin", "add"),
            new Missing("missing <user>", "admin", "remove"),
            new Missing("missing <key>", "setting"),
            new Missing("missing <value>", "setting", "knock"))) {
            String typed = "jailhub " + String.join(" ", m.argv());
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> req(m.argv()),
                typed + " was accepted");
            assertEquals(m.says(), e.getMessage(), typed);
        }
    }

    @Test
    void reassigningANameWithoutAnOwnerIsRefused() {
        // --user is the whole point of the command, so this one is required rather than optional.
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> req("name", "reassign", "web"));
        assertEquals("--user is required", e.getMessage());
    }

    /**
     * A value with a space in it arrives as several positional words, and taking the first of them
     * was silent: {@code jailhub setting operator Example Ltd} stored "Example" and replied ok. The
     * operator has to be told, and told with the line they meant in front of them -- all of it, not
     * the first two words and an ellipsis, since the difference between the two is one more thing
     * to work out at a prompt.
     */
    @Test
    void aSettingValueWithSpacesIsRefusedRatherThanTruncated() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> req("setting", "operator", "Example", "Ltd"));
        assertEquals("a value with spaces has to be quoted: jailhub setting operator \"Example Ltd\"", e.getMessage());
        IllegalArgumentException more = assertThrows(IllegalArgumentException.class,
            () -> req("setting", "operator", "The", "Example", "Company", "Ltd"));
        assertEquals("a value with spaces has to be quoted: jailhub setting operator \"The Example Company Ltd\"",
            more.getMessage());
        // And the quoted form, which is one positional, still goes through.
        assertEquals("Example Ltd", req("setting", "operator", "Example Ltd").string("value"));
    }

    /**
     * The one expiry an operator has left to watch is the hub's own wildcard (§15), and until the
     * maintenance cut the only places it was published were the public page and {@code /v1/status}
     * -- so an operator watching from a terminal had to load a web page. {@code jailhub status}
     * carries it now, in unix seconds as the JSON endpoint reports it.
     *
     * <p>Against the certificate's own notAfter and not merely "present": a field that carried 0,
     * or the wrong unit, would pass a null check and read as 1970 on the operator's screen.
     */
    @Test
    void statusCarriesWhenTheWildcardExpires() throws Exception {
        try (Hub hub = startedHub()) {
            JsonObject[] last = new JsonObject[1];
            new AdminIpc(hub).handle(JsonObject.builder().put("cmd", "status").build(), o -> last[0] = o);
            long expected = hub.tls().leaf().getNotAfter().getTime() / 1000;
            assertEquals(expected, last[0].lng("certificateNotAfter"),
                "jailhub status should say when the wildcard runs out, in unix seconds");
        }
    }

    /** A throwaway hub on a free port, with the test certificate. */
    private static Hub startedHub() throws Exception {
        Path root = TestDirs.newRoot("ja");
        java.net.ServerSocket portSocket = TestPorts.listen(1024);
        int port = portSocket.getLocalPort();
        HubConfig cfg = HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath(),
            Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath(),
            true, HubConfig.POLICY_MEMBERS, true, "hub.test");
        Hub hub = new Hub(cfg);
        hub.listenOn(portSocket);
        try {
            hub.start();
        } catch (Exception e) {
            hub.close();   // which gives the socket back; a throw here used to leak only a number
            throw e;
        }
        return hub;
    }

    /**
     * {@code setting} is the one admin command that writes a free string into the store, and every
     * reader of those three keys compares against one spelling ({@code "open".equals(...)},
     * {@code "off".equals(...)}). Unchecked, {@code jailhub setting knock of} answered ok and left
     * knocking on, and {@code jailhub setting knok off} stored a key nothing reads -- the operator
     * is told the change was made either way, which is the worst of the three outcomes.
     */
    @Test
    void settingRefusesAKeyOrValueNothingReads() throws Exception {
        Hub hub = startedHub();
        try {
            AdminIpc ipc = new AdminIpc(hub);
            assertEquals("on", hub.store().setting(Store.SETTING_KNOCK, "on"));

            assertEquals("knock is on or off, not of", set(ipc, "knock", "of"));
            assertEquals("knock is on or off, not OFF", set(ipc, "knock", "OFF"));
            assertEquals("registration is invite or open, not opne", set(ipc, "registration", "opne"));
            assertEquals("invitePolicy is members or admins, not admin", set(ipc, "invitePolicy", "admin"));
            assertEquals("no such setting knok (contact, invitePolicy, knock, operator, registration, terms)",
                set(ipc, "knok", "off"), "the list an operator is offered has to be all of them");
            assertEquals("on", hub.store().setting(Store.SETTING_KNOCK, "on"), "a refused setting must not have been written");

            assertNull(set(ipc, "knock", "off"));
            assertEquals("off", hub.store().setting(Store.SETTING_KNOCK, "on"));
            // Stripped for these as well as for the text settings: a trailing space out of a shell
            // or a copied line is not a fourth value, and refusing it says "knock is on or off, not
            // off", an error whose difference from the value the operator cannot see.
            assertNull(set(ipc, "knock", " on "));
            assertEquals("on", hub.store().setting(Store.SETTING_KNOCK, "off"));
            assertNull(set(ipc, "registration", "open"));
            assertNull(set(ipc, "invitePolicy", "admins"));
        } finally {
            hub.close();
        }
    }

    /**
     * The three settings that take text rather than one of a fixed few (#99). Two of them end up in
     * an {@code href} on a page anyone can load, so the scheme is checked where it is set: an
     * operator who pastes the wrong thing is told at the prompt, and a visitor never finds out
     * instead. Empty is not a refusal -- it is how a value comes back off the page.
     */
    @Test
    void theOperatorSettingsTakeTextAndRefuseAHrefNobodyMeantToPublish() throws Exception {
        Hub hub = startedHub();
        try {
            AdminIpc ipc = new AdminIpc(hub);
            assertNull(set(ipc, "operator", "Example Ltd"));
            assertNull(set(ipc, "contact", "mailto:abuse@example.com"));
            assertNull(set(ipc, "terms", "https://example.com/aup"));
            assertEquals("Example Ltd", hub.store().setting(Store.SETTING_OPERATOR, ""));
            assertEquals("mailto:abuse@example.com", hub.store().setting(Store.SETTING_CONTACT, ""));

            assertEquals("contact takes an https:// or mailto: URL, up to 200 characters, or empty to clear",
                set(ipc, "contact", "javascript:alert(1)"));
            assertEquals("contact takes an https:// or mailto: URL, up to 200 characters, or empty to clear",
                set(ipc, "contact", "http://example.com/abuse"), "plain http is not a contact this hub will print");
            assertEquals("terms takes an https:// URL, up to 200 characters, or empty to clear",
                set(ipc, "terms", "mailto:legal@example.com"));
            // A scheme is case-insensitive, so refusing this one would be the same invisible
            // difference between the error and the value as `knock "off "` was.
            assertNull(set(ipc, "terms", "HTTPS://example.com/aup"));
            assertEquals("HTTPS://example.com/aup", hub.store().setting(Store.SETTING_TERMS, ""));
            assertEquals("operator takes a name, up to 120 characters, or empty to clear",
                set(ipc, "operator", "x".repeat(121)));
            assertEquals("mailto:abuse@example.com", hub.store().setting(Store.SETTING_CONTACT, ""),
                "a refused value must not have been written");

            assertNull(set(ipc, "contact", ""), "empty is how it comes back off the page");
            assertEquals("", hub.store().setting(Store.SETTING_CONTACT, "unset"));
            // Spaces are the same act, and not a third state: stored as typed, they would neither
            // clear the value nor be refused, and the page would keep the section around a blank.
            assertNull(set(ipc, "operator", "   "));
            assertEquals("", hub.store().setting(Store.SETTING_OPERATOR, "unset"));
        } finally {
            hub.close();
        }
    }

    /** Sends one {@code setting} request; returns the refusal, or null when it was accepted. */
    private static String set(AdminIpc ipc, String key, String value) throws Exception {
        JsonObject[] last = new JsonObject[1];
        ipc.handle(JsonObject.builder().put("cmd", "setting").put("key", key).put("value", value).build(), o -> last[0] = o);
        return last[0].optBool("ok", false) ? null : last[0].string("error");
    }

    /**
     * A flag placed before the words is the shape whose meaning depends on the flag being declared
     * in {@link Main#FLAGS}: anywhere else {@code Args} rescues it, because the word after it is
     * another option or the end of the line. Here the next word is the subcommand, so an undeclared
     * {@code --admin} takes "invite" as its value and the command becomes {@code create}.
     *
     * <p>Written the obvious way first -- {@code invite create --admin --user carol} -- this test
     * passed with {@code --admin} deleted from the list, and proved nothing.
     */
    @Test
    void aFlagBeforeTheSubcommandNeedsTheFlagsList() {
        JsonObject r = req("--admin", "invite", "create");
        assertEquals("invite-create", r.string("cmd"));
        assertTrue(r.bool("admin"));

        // And in its usual place it carries the same meaning.
        JsonObject after = req("invite", "create", "--admin", "--user", "carol");
        assertTrue(after.bool("admin"));
        assertEquals("carol", after.string("user"));
    }
}
