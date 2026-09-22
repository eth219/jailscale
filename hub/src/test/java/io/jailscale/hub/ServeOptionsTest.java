package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.util.Args;
import java.net.URI;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * {@code jailhub serve} and its twenty-odd options ({@link HubConfig#fromArgs}). Sixteen tests
 * built a {@link HubConfig} through {@code withCert} instead, which skips this method entirely, so
 * every default and every refusal here was running unexamined on the live hub.
 *
 * <p>The refusals matter more than they look: these options are typed once into a systemd unit and
 * then not read again for months, and the ones that are a pair or an enum fail silently when they
 * are wrong -- a listener on the wrong interface, or a check the operator believes is on.
 */
class ServeOptionsTest {

    private static final String STATE = "/tmp/jailhub-serve-options-test";

    private static HubConfig serve(String... extra) {
        String[] argv = new String[extra.length + 5];
        argv[0] = "serve";
        argv[1] = "--base-url";
        argv[2] = "https://hub.example.com";
        argv[3] = "--state";
        argv[4] = STATE;
        System.arraycopy(extra, 0, argv, 5, extra.length);
        return HubConfig.fromArgs(Args.parse(argv, Main.FLAGS));
    }

    private static String refused(String... extra) {
        return assertThrows(IllegalArgumentException.class, () -> serve(extra),
            () -> "accepted: jailhub serve " + String.join(" ", extra)).getMessage();
    }

    /**
     * Every option this binary reads with {@code flag()} has to be in {@link Main#FLAGS}, and the
     * shape that proves it is the flag placed last: with no next word, an option the list does not
     * know is refused as needing a value. One was missing once and got away with it under the old
     * parser, which guessed "true" for any option followed by another option or by nothing -- so
     * the flag had never actually been parsed as one.
     *
     * <p>Kept as a list rather than derived, so adding an option here is the deliberate act that
     * adding one to FLAGS should be.
     */
    @Test
    void everyBooleanServeOptionIsInTheFlagsList() {
        for (String flag : new String[] {"debug", "admin", "help", "acme-staging", "no-selfcheck",
            "no-address-check"}) {
            Args a = Args.parse(new String[] {"serve", "--" + flag}, Main.FLAGS);
            assertTrue(a.flag(flag), "--" + flag + " is not in Main.FLAGS");
            assertEquals("serve", a.positional(0), "--" + flag + " swallowed the subcommand");
        }
    }

    // --- what an operator gets by typing as little as possible -----------------------------------

    @Test
    void theDefaultsAreTheOnesDocumentedInTheUsage() {
        HubConfig c = serve();
        assertEquals("0.0.0.0", c.listenHost());
        assertEquals(443, c.listenPort());
        assertEquals("hub.example.com", c.hostname());
        assertEquals("hub.example.com", c.dnsSuffix(), "the dns suffix follows the base url unless told otherwise");
        assertEquals(Path.of(STATE), c.stateDir());
        assertEquals(Path.of(STATE, "jailhub.sock"), c.socketPath());

        assertFalse(c.registrationOpen(), "registration is invite-only until asked otherwise");
        assertEquals(HubConfig.POLICY_MEMBERS, c.invitePolicy());
        assertTrue(c.knock());

        assertTrue(c.acme(), "no --tls-cert means the hub gets its own certificate");
        assertEquals(HubConfig.LETS_ENCRYPT, c.acmeDirectory());
        assertNull(c.acmeEmail());
        assertNull(c.tlsCert());
        assertNull(c.tlsKey());
        assertEquals("0.0.0.0", c.dnsListenHost());
        assertEquals(53, c.dnsListenPort());
        assertTrue(c.selfCheck());
        assertTrue(c.addressCheck());

    }

    @Test
    void eachOptionMovesTheOneThingItNames() {
        assertEquals(8443, serve("--listen", "127.0.0.1:8443").listenPort());
        assertEquals("127.0.0.1", serve("--listen", "127.0.0.1:8443").listenHost());
        assertTrue(serve("--registration", "open").registrationOpen());
        assertFalse(serve("--registration", "invite").registrationOpen());
        assertEquals(HubConfig.POLICY_ADMINS, serve("--invite-policy", "admins").invitePolicy());
        assertFalse(serve("--knock", "off").knock());
        assertTrue(serve("--knock", "on").knock());
        assertEquals("nodes.example.com", serve("--dns-suffix", "nodes.example.com").dnsSuffix());
        assertEquals("you@example.com", serve("--acme-email", "you@example.com").acmeEmail());
        assertEquals("127.0.0.1", serve("--dns-listen", "127.0.0.1:5353").dnsListenHost());
        assertEquals(5353, serve("--dns-listen", "127.0.0.1:5353").dnsListenPort());
    }

    @Test
    void theAdvertisedAddressIsOptionalAndFoundFromTheGlueOtherwise() {
        assertNull(serve().advertise(), "no --advertise means the address is found from the glue");
        assertEquals("203.0.113.1", serve("--advertise", "203.0.113.1").advertise());
    }

    @Test
    void anIpv6ListenerKeepsItsBrackets() {
        // The host is split on the LAST colon, or "[::]:443" would become host "[" port ":]:443".
        HubConfig c = serve("--listen", "[::]:443");
        assertEquals("[::]", c.listenHost());
        assertEquals(443, c.listenPort());
    }

    // --- certificate: built-in ACME, or your own files --------------------------------------------

    @Test
    void ownFilesTurnAcmeOffAndComeAsAPair() {
        HubConfig c = serve("--tls-cert", "/etc/ssl/hub.crt", "--tls-key", "/etc/ssl/hub.key");
        assertFalse(c.acme());
        assertEquals(Path.of("/etc/ssl/hub.crt"), c.tlsCert());
        assertEquals(Path.of("/etc/ssl/hub.key"), c.tlsKey());

        // Half a pair is the dangerous shape: it would start with ACME on for a name the operator
        // has already got a certificate for, and rate-limit the account for nothing.
        assertEquals("--tls-cert and --tls-key go together", refused("--tls-cert", "/etc/ssl/hub.crt"));
        assertEquals("--tls-cert and --tls-key go together", refused("--tls-key", "/etc/ssl/hub.key"));
    }

    @Test
    void anExplicitAcmeDirectoryBeatsTheStagingFlag() {
        assertEquals(HubConfig.LETS_ENCRYPT_STAGING, serve("--acme-staging").acmeDirectory());
        URI pebble = URI.create("https://127.0.0.1:14000/dir");
        assertEquals(pebble, serve("--acme-directory", pebble.toString()).acmeDirectory());
        assertEquals(pebble, serve("--acme-staging", "--acme-directory", pebble.toString()).acmeDirectory(),
            "the named directory wins, or --acme-staging would silently redirect it");
    }

    @Test
    void theTwoChecksAreSeparateSwitches() {
        // Kept honest by ReachabilityTest as well; here to record that neither is on a default path.
        assertFalse(serve("--no-selfcheck").selfCheck());
        assertTrue(serve("--no-selfcheck").addressCheck());
        assertFalse(serve("--no-address-check").addressCheck());
        assertTrue(serve("--no-address-check").selfCheck());
    }

    // --- the listeners ---------------------------------------------------------------------------

    @Test
    void theDnsListenerCannotBeTurnedOff() {
        // --dns-listen has no "none": the hub answers dns-01 for its own wildcard from here, so a
        // hub without it cannot get a certificate at all.
        assertEquals("--dns-listen must be host:port", refused("--dns-listen", "none"));
    }

    // --- the base url and the enums ---------------------------------------------------------------

    @Test
    void theBaseUrlIsRequiredAndHasToBeHttpsWithAHost() {
        assertEquals("--base-url is required",
            assertThrows(IllegalArgumentException.class,
                () -> HubConfig.fromArgs(Args.parse(new String[] {"serve"}, Main.FLAGS))).getMessage());
        for (String bad : new String[] {"http://hub.example.com", "hub.example.com", "https:///join"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> HubConfig.fromArgs(Args.parse(new String[] {"serve", "--base-url", bad, "--state", STATE}, Main.FLAGS)),
                "accepted --base-url " + bad);
            assertEquals("--base-url must be https://<host>", e.getMessage());
        }
    }

    @Test
    void aListenerWithoutAPortIsRefused() {
        assertEquals("--listen must be host:port", refused("--listen", "0.0.0.0"));
    }

    /**
     * An IPv6 address has colons of its own, so `--listen ::443` parses as the host `:` and binds
     * nothing -- it used to reach the operator as `SocketException: Unresolved address`, a sentence
     * that says nothing about brackets (#63). Both host:port flags parse the same way and both
     * had it.
     */
    @Test
    void anUnbracketedIpv6ListenerSaysToBracketIt() {
        String want = " needs an IPv6 address in brackets, as in ";
        for (String flag : new String[] {"--listen", "--dns-listen"}) {
            String msg = refused(flag, "::443");
            assertTrue(msg.startsWith(flag + want), flag + " said: " + msg);
        }
        assertEquals("--listen needs an IPv6 address in brackets, as in --listen [::]:443 for every address"
            + " or --listen [2001:db8::1]:443 for one", refused("--listen", "2001:db8::1:443"));
        // Brackets and no port: the last colon is inside the address, so the check has to look for
        // the one after the bracket or it refuses this for the one thing it got right.
        assertEquals("--listen must be [address]:port for an IPv6 address", refused("--listen", "[::]"));
        assertEquals("--dns-listen must be [address]:port for an IPv6 address", refused("--dns-listen", "[2001:db8::1]"));
    }

    /**
     * And the bracketed form is still accepted, on every one of them. This guards the check above
     * and not the parser under it: the brackets already survived {@code substring}, so deleting
     * the check leaves this green. What it can fail is a check that rejects the valid form too.
     */
    @Test
    void aBracketedIpv6ListenerIsTheForm() {
        HubConfig c = serve("--listen", "[::]:443", "--dns-listen", "[::]:53");
        assertEquals("[::]", c.listenHost());
        assertEquals("[::]", c.dnsListenHost());
    }

    /**
     * The three options whose readers compare against one spelling. {@code --invite-policy} was
     * always checked; {@code --registration} and {@code --knock} were not, and a typo in either
     * selected the other setting without a word -- a hub the operator had opened staying closed,
     * or knocking they had turned off still being answered.
     */
    @Test
    void anEnumOptionIsRefusedRatherThanSilentlyMeaningTheOtherValue() {
        assertEquals("--invite-policy must be members or admins", refused("--invite-policy", "admin"));
        assertEquals("--registration must be invite or open", refused("--registration", "opne"));
        assertEquals("--registration must be invite or open", refused("--registration", "Open"));
        assertEquals("--knock must be on or off", refused("--knock", "of"));
        assertEquals("--knock must be on or off", refused("--knock", "false"));
    }
}
