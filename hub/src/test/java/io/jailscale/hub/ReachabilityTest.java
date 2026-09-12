package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The address check's decision table (ARCHITECTURE.md §7.2). Both things that touch the world are
 * passed in, so every verdict is reachable here -- including the two that must never be confused:
 * "cannot check from this host", which is normal behind a translated address, and "something else
 * is answering for this name", which is not.
 */
class ReachabilityTest {

    private static final String OURS = "hkey:ours";
    private static final String HOST = "hub.example.com";

    /** Answers from a fixed table; a name that is not in it has no records. */
    private static Reachability.Resolver resolver(Map<String, Set<String>> table) {
        return name -> {
            for (Map.Entry<String, Set<String>> e : table.entrySet()) {
                // The wildcard probe uses a random label, so match on the suffix for it.
                if (e.getKey().startsWith("*.") ? name.endsWith(e.getKey().substring(1)) : name.equals(e.getKey())) {
                    return e.getValue();
                }
            }
            return Set.of();
        };
    }

    private static Set<String> set(String... v) {
        return new LinkedHashSet<>(java.util.List.of(v));
    }

    private static Reachability.Result check(Map<String, Set<String>> dns, Reachability.KeyAt keyAt) {
        return Reachability.check(HOST, OURS, 443, resolver(dns), keyAt);
    }

    @Test
    void noSelfcheckDoesNotSilenceTheAddressCheck() {
        // The two checks fail in opposite ways, so one flag cannot serve both: --no-selfcheck
        // exists because the dns-01 check holds issuance until it passes, and an operator who
        // needs the hub to start should not lose a report that can only write a log line. The
        // half that matters most to that operator -- do the records exist and agree -- asks
        // public resolvers and never needs to reach this host at all.
        HubConfig a = HubConfig.fromArgs(io.jailscale.proto.util.Args.parse(
            new String[] {"--no-selfcheck", "serve", "--base-url", "https://hub.example.com"}, Main.FLAGS));
        assertTrue(!a.selfCheck(), "--no-selfcheck still turns the dns-01 check off");
        assertTrue(a.addressCheck(), "--no-selfcheck must not turn the address check off");

        // Main.FLAGS, and the flag placed before a positional word: that is the argv shape whose
        // meaning depends on the flag being declared, so a flag the CLI forgot fails here too.
        HubConfig b = HubConfig.fromArgs(io.jailscale.proto.util.Args.parse(
            new String[] {"--no-address-check", "serve", "--base-url", "https://hub.example.com"}, Main.FLAGS));
        assertTrue(!b.addressCheck(), "--no-address-check turns the address check off");
        assertTrue(b.selfCheck(), "--no-address-check must not turn the dns-01 check off");
    }

    @Test
    void theAddressAnsweringWithOurOwnKeyIsProof() {
        Reachability.Result r = check(Map.of(HOST, set("203.0.113.10"), "*." + HOST, set("203.0.113.10")),
            (address, host, port) -> OURS);
        assertEquals(Reachability.PROVEN, r.verdict());
        assertNull(r.problem());
        assertEquals(java.util.List.of("203.0.113.10"), r.addresses());
    }

    @Test
    void anotherHubAnsweringForThisNameIsTheAlarm() {
        Reachability.Result r = check(Map.of(HOST, set("203.0.113.10"), "*." + HOST, set("203.0.113.10")),
            (address, host, port) -> "hkey:somebody-else");
        assertEquals(Reachability.ELSEWHERE, r.verdict());
        assertTrue(r.problem().contains("hkey:somebody-else"), r.problem());
        assertTrue(r.problem().contains(OURS), r.problem());
        assertTrue(r.problem().contains("203.0.113.10"), r.problem());
    }

    @Test
    void notBeingAbleToReachOurOwnAddressIsNotAnAlarm() {
        // A cloud instance usually cannot connect to its own public address. Calling that a failure
        // would make the check cry wolf on the most ordinary deployment there is.
        Reachability.Result r = check(Map.of(HOST, set("203.0.113.10"), "*." + HOST, set("203.0.113.10")),
            (address, host, port) -> {
                throw new IOException("connection timed out");
            });
        assertEquals(Reachability.INCONCLUSIVE, r.verdict());
        assertTrue(r.problem().contains("connection timed out"), r.problem());
        assertTrue(r.problem().contains("does not mean"), r.problem());
    }

    @Test
    void aMissingRecordIsNamedForWhatItBreaks() {
        Reachability.Result none = check(Map.of(), (a, h, p) -> OURS);
        assertEquals(Reachability.MISCONFIGURED, none.verdict());
        assertTrue(none.problem().contains("no address record for " + HOST), none.problem());

        Reachability.Result noWildcard = check(Map.of(HOST, set("203.0.113.10")), (a, h, p) -> OURS);
        assertEquals(Reachability.MISCONFIGURED, noWildcard.verdict());
        assertTrue(noWildcard.problem().contains("no address record for *." + HOST), noWildcard.problem());
    }

    @Test
    void theApexAndTheWildcardHaveToAgree() {
        // §15's case: only the wildcard is proxied, so the hub's own name and the names it serves
        // arrive in different places and only one of them works.
        Reachability.Result r = check(Map.of(HOST, set("203.0.113.10"), "*." + HOST, set("198.51.100.7")),
            (a, h, p) -> OURS);
        assertEquals(Reachability.MISCONFIGURED, r.verdict());
        assertTrue(r.problem().contains("203.0.113.10"), r.problem());
        assertTrue(r.problem().contains("198.51.100.7"), r.problem());
    }

    @Test
    void noResolverAnsweringIsInconclusiveRatherThanBroken() {
        Reachability.Result r = Reachability.check(HOST, OURS, 443,
            name -> {
                throw new IOException("network is unreachable");
            },
            (a, h, p) -> OURS);
        assertEquals(Reachability.INCONCLUSIVE, r.verdict());
        assertTrue(r.problem().contains("network is unreachable"), r.problem());
    }

    @Test
    void aStaleCachedApexNextToTheNewAddressIsNotADisagreement() {
        // Mid-change: a resolver still has the old address cached for the apex, while the wildcard
        // probe is a label nobody ever asked for and so comes back fresh. The names still share an
        // address, and that address answering with our key is the proof.
        Reachability.Result r = check(
            Map.of(HOST, set("198.51.100.7", "203.0.113.10"), "*." + HOST, set("203.0.113.10")),
            (address, host, port) -> address.equals("203.0.113.10") ? OURS : "hkey:previous-hub");
        assertEquals(Reachability.PROVEN, r.verdict(), r.problem());
        assertEquals(java.util.List.of("203.0.113.10"), r.addresses());
    }

    @Test
    void anotherHubAtOneAddressDoesNotHideOursAtAnother() {
        Reachability.Result r = check(
            Map.of(HOST, set("198.51.100.7", "203.0.113.10"), "*." + HOST, set("198.51.100.7", "203.0.113.10")),
            (address, host, port) -> address.equals("198.51.100.7") ? "hkey:previous-hub" : OURS);
        assertEquals(Reachability.PROVEN, r.verdict(), r.problem());
    }

    @Test
    void somethingThatIsNotAHubAnsweringIsAFaultNotAnExcuse() {
        // The handshake completed and a 403 page came back: a TLS-terminating proxy is in front,
        // which §7.2 says cannot be. Calling that "cannot check from here" would hide the one
        // misconfiguration the check was written to catch.
        Reachability.Result r = check(Map.of(HOST, set("203.0.113.10"), "*." + HOST, set("203.0.113.10")),
            (address, host, port) -> {
                throw new Reachability.NotAHub("/v1/key answered HTTP 403");
            });
        assertEquals(Reachability.MISCONFIGURED, r.verdict());
        assertTrue(r.problem().contains("not a hub"), r.problem());
        assertTrue(r.problem().contains("HTTP 403"), r.problem());
    }

    @Test
    void aNonHubAnswerOutranksAnUnreachableAddress() {
        Reachability.Result r = check(
            Map.of(HOST, set("203.0.113.10", "203.0.113.11"), "*." + HOST, set("203.0.113.10", "203.0.113.11")),
            (address, host, port) -> {
                if (address.equals("203.0.113.10")) {
                    throw new IOException("timed out");
                }
                throw new Reachability.NotAHub("/v1/key answered HTTP 404");
            });
        assertEquals(Reachability.MISCONFIGURED, r.verdict());
    }

    @Test
    void everyAddressIsTriedBeforeGivingUp() {
        // Round-robin A records are ordinary; one unreachable address must not hide a good one.
        Reachability.Result r = check(
            Map.of(HOST, set("203.0.113.10", "203.0.113.11"), "*." + HOST, set("203.0.113.10", "203.0.113.11")),
            (address, host, port) -> {
                if (address.equals("203.0.113.10")) {
                    throw new IOException("timed out");
                }
                return OURS;
            });
        assertEquals(Reachability.PROVEN, r.verdict());
    }
}
