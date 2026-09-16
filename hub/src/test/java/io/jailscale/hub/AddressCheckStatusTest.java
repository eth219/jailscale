package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.json.JsonObject;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * What the address check leaves behind (ARCHITECTURE.md §7.2). The decision itself is
 * {@link ReachabilityTest}'s; this is the half an operator touches -- the verdict that stands
 * between runs, and the surfaces that carry it. It used to exist only as a line written to the log
 * at boot, so a record edited afterwards was never noticed and the answer could not be asked for.
 *
 * <p>Nothing here reaches the network: the run is stubbed through {@link Hub#addressProbe}, the
 * hub is built but not started, and the admin commands are handed to {@link AdminIpc} directly.
 * Every verdict below would take a real misconfiguration to produce.
 */
@Timeout(90)
class AddressCheckStatusTest {

    private static Reachability.Result result(String verdict, String problem) {
        return new Reachability.Result(verdict, problem, List.of("203.0.113.10"));
    }

    @Test
    void theVerdictStandsBetweenRunsAndSaysWhenItLastMoved() throws Exception {
        try (Hub hub = hub(true)) {
            assertNull(hub.addressStatus(), "nothing has been checked yet, which is not a verdict");
            AtomicReference<Reachability.Result> answer =
                new AtomicReference<>(result(Reachability.MISCONFIGURED, "no address record for *.hub.test"));
            hub.addressProbe = answer::get;

            Reachability.Status broken = hub.checkAddress();
            assertEquals(Reachability.MISCONFIGURED, broken.verdict());
            assertTrue(broken.fault());
            assertEquals(broken, hub.addressStatus(), "the verdict is kept, not just logged");

            // The next pass finding the same thing must not restate when the fault began. Long
            // enough for the wall clock to move: `since` is stamped from System.currentTimeMillis(),
            // and on a host whose system time ticks in ~15.6 ms steps -- Windows by default, which
            // CI builds on -- three in-process calls a few milliseconds apart land on one tick and
            // the strict comparison below would fail on a build with nothing wrong with it.
            Thread.sleep(25);
            Reachability.Status again = hub.checkAddress();
            assertEquals(broken.since(), again.since());
            assertTrue(again.at() >= broken.at());

            answer.set(result(Reachability.PROVEN, null));
            Reachability.Status fixed = hub.checkAddress();
            assertEquals(Reachability.PROVEN, fixed.verdict());
            assertTrue(fixed.since() > broken.since(), "a verdict that moved starts its own clock");
            assertTrue(fixed.ok());
        }
    }

    @Test
    void aNodeArrivingFromOutsideMovesTheStandingVerdictAtOnce() throws Exception {
        // The translated-address case (§7.2): this host cannot dial its own public address, and the
        // node that just handshook against the pinned key already knows the answer. Waiting for the
        // next pass to say so would leave the page reading "inconclusive" for an hour.
        try (Hub hub = hub(true)) {
            hub.addressProbe = () -> result(Reachability.INCONCLUSIVE, "could not reach it from this host.");
            assertEquals(Reachability.INCONCLUSIVE, hub.checkAddress().verdict());

            long ran = hub.addressStatus().at();
            Thread.sleep(25);
            hub.reachedBy("hub.test", "203.0.113.5");
            Reachability.Status s = hub.addressStatus();
            assertEquals(Reachability.OUTSIDE, s.verdict());
            assertTrue(s.ok());
            assertEquals(ran, s.at(), "the arrival moved the verdict, not when the check last ran");
            assertTrue(s.text("hub.test").contains("203.0.113.5"), s.text("hub.test"));

            // A node on this machine says nothing about what the world is told, so it moves
            // nothing -- and cannot take the standing proof away either.
            hub.reachedBy("hub.test", "127.0.0.1");
            assertEquals(Reachability.OUTSIDE, hub.addressStatus().verdict());
        }
    }

    @Test
    void everySurfaceCarriesTheSameVerdict() throws Exception {
        try (Hub hub = hub(true)) {
            hub.addressProbe = () -> result(Reachability.ELSEWHERE, "another hub answers there");

            // The command an operator types after editing a record: it runs now and answers.
            JsonObject ran = admin(hub, "address-check");
            assertTrue(ran.optBool("ok", false), ran.toString());
            assertEquals(Reachability.ELSEWHERE, ran.object("addressCheck").string("verdict"));

            // And the same verdict is there to be looked up afterwards, which is the whole point.
            JsonObject check = admin(hub, "status").object("addressCheck");
            assertEquals(Reachability.ELSEWHERE, check.string("verdict"));
            assertTrue(check.bool("fault"));
            assertEquals("another hub answers there", check.string("problem"));

            // A monitor alerts on the fault gauge and not on the verdict, so that inconclusive --
            // the ordinary answer from behind a translated address -- never pages anybody.
            String metrics = Metrics.prometheus(hub);
            assertTrue(metrics.contains("jailhub_address_check_fault 1"), metrics);
            assertTrue(metrics.contains("jailhub_address_check{verdict=\"elsewhere\"} 0"), metrics);

            hub.addressProbe = () -> result(Reachability.INCONCLUSIVE, "could not reach it from this host.");
            hub.checkAddress();
            assertTrue(Metrics.prometheus(hub).contains("jailhub_address_check_fault 0"),
                "inconclusive is not a fault");
        }
    }

    @Test
    void theCheckBeingOffLeavesNothingBehindAndRefusesToRun() throws Exception {
        // --no-address-check is one switch over the repeat, the log and the command: an operator
        // who turned it off is told so rather than "unknown command", and the status carries no
        // field at all rather than one saying "unknown" about records nobody has looked at.
        try (Hub hub = hub(false)) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> admin(hub, "address-check"));
            assertTrue(e.getMessage().contains("--no-address-check"), e.getMessage());

            JsonObject status = admin(hub, "status");
            assertTrue(status.optBool("ok", false), status.toString());
            assertFalse(status.has("addressCheck"), status.toString());
            assertNull(hub.addressStatus());
            assertFalse(Metrics.prometheus(hub).contains("jailhub_address_check"));
        }
    }

    @Test
    void standingDownDropsTheVerdictAndTheRefusalNamesNoPeerItDoesNotHave() throws Exception {
        // A hub that stood down by epoch (§13.5) rather than by --peer: the records are the new
        // primary's now, so the verdict it reached as a primary stops being about anything, and
        // nothing may revive it -- a standby that kept checking would find the other hub's key at
        // the shared address and file that as a fault every hour.
        try (Hub hub = hub(true)) {
            hub.addressProbe = () -> result(Reachability.PROVEN, null);
            hub.checkAddress();
            assertNotNull(hub.addressStatus());

            hub.demote(9, "other.hub.test");
            assertTrue(hub.isStandby());
            assertNull(hub.addressStatus(), "a standby carries no verdict about the primary's records");
            hub.reachedBy("hub.test", "203.0.113.5");
            assertNull(hub.addressStatus(), "and an arrival does not bring one back");
            assertFalse(Metrics.prometheus(hub).contains("jailhub_address_check"));

            // The refusal says what is wrong, rather than dereferencing a peer this hub never had.
            assertNull(hub.config().peer());
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> admin(hub, "address-check"));
            assertEquals("this hub is a standby; the records to check are the primary's", e.getMessage());
        }
    }

    @Test
    void aRunOvertakenByStandingDownIsKeptNowhere() throws Exception {
        // The loop tests standby before the run, and the run is slow enough to be overtaken -- an
        // unanswered resolver costs five seconds and the dial another. Demotion inside the probe
        // is that interleaving exactly: what comes back was computed as a primary, about records
        // that are the new primary's now, and recording it would leave a fault standing on a
        // standby that no later pass ever clears.
        try (Hub hub = hub(true)) {
            hub.addressProbe = () -> {
                try {
                    hub.demote(9, "other.hub.test");
                } catch (java.io.IOException e) {
                    throw new IllegalStateException(e);
                }
                return result(Reachability.ELSEWHERE, "another hub answers there");
            };
            assertEquals(Reachability.ELSEWHERE, hub.checkAddress().verdict(), "the caller still gets its answer");
            assertNull(hub.addressStatus(), "but a standby keeps no verdict");
            assertFalse(Metrics.prometheus(hub).contains("jailhub_address_check"));
        }
    }

    /** One admin command, handed to the handler the socket would hand it to. */
    private static JsonObject admin(Hub hub, String cmd) throws Exception {
        JsonObject[] last = new JsonObject[1];
        new AdminIpc(hub).handle(JsonObject.builder().put("cmd", cmd).build(), o -> last[0] = o);
        return last[0];
    }

    /**
     * A hub with its state and keys and nothing listening: {@code start()} would bind 443 and,
     * with the address check on, send this build's own DNS queries to the public resolvers.
     */
    private static Hub hub(boolean addressCheck) throws Exception {
        Path root = TestDirs.newRoot("ac");
        int port;
            port = TestPorts.reserve();
        HubConfig cfg = HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath(),
            Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath(),
            true, HubConfig.POLICY_MEMBERS, true, "hub.test").withAddressCheck(addressCheck);
        return new Hub(cfg);
    }
}
