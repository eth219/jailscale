package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.json.Json;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import io.jailscale.proto.net.TestPorts;

/**
 * The signed pointer that says which release is current (docs/update-freshness), against one this
 * test publishes itself.
 *
 * <p>What is being tested is the difference between "you are up to date" and "I cannot tell", and
 * the fact that the answer now comes from bytes a key signed rather than from a release index
 * anybody who can publish could edit. Each case bends exactly one thing about the pointer and
 * leaves the rest honest, so a check that stopped happening fails here rather than passing quietly.
 */
class UpdateIndexTest {

    private static final String RUNNING = "0.1.0";
    /** 2026-01-01T00:00:00Z, and a pointer issued an hour before it. */
    private static final long NOW = 1_767_225_600_000L;
    private static final String ISSUED = "2025-12-31T23:00:00Z";
    private static final String FAR = "2026-04-01T00:00:00Z";
    private static final String PAST = "2025-12-31T23:30:00Z";

    private record Published(Map<String, byte[]> files, List<String> keys) {}

    /** The two assets on loopback, under the fixed pre-release the client compiles in. */
    private static ServerSocket serve(Map<String, byte[]> files) throws IOException {
        ServerSocket ss = TestPorts.listen(50);
        Thread t = new Thread(() -> {
            while (!ss.isClosed()) {
                try (Socket s = ss.accept()) {
                    HttpRequest r = Http.readRequest(s.getInputStream(), 0);
                    byte[] body = files.get(r.path());
                    var out = s.getOutputStream();
                    out.write(("HTTP/1.1 " + (body == null ? "404 Not Found" : "200 OK") + "\r\nContent-Length: "
                        + (body == null ? 0 : body.length) + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                    if (body != null) {
                        out.write(body);
                    }
                    out.flush();
                } catch (Exception e) {
                    return;
                }
            }
        }, "canned-index");
        t.setDaemon(true);
        t.start();
        return ss;
    }

    private static Updates.Source at(ServerSocket ss, Published p) {
        return new Updates.Source("http://" + ss.getInetAddress().getHostAddress() + ":" + ss.getLocalPort() + "/",
            p.keys());
    }

    /** A pointer as tools/refresh-index.sh writes one: the format line, then one field per line. */
    private static String document(long seq, String tag, String issued, String expires) {
        return Updates.INDEX_FORMAT + "\nseq: " + seq + "\ntag: " + tag
            + "\nissued: " + issued + "\nexpires: " + expires + "\n";
    }

    private static Published publish(String document) throws GeneralSecurityException {
        return publish(document, document);
    }

    /** @param signed what the signature is actually over, which an honest release makes the document */
    private static Published publish(String document, String signed) throws GeneralSecurityException {
        KeyPair kp = ReleaseKeyTest.keyPair();
        Map<String, byte[]> files = new HashMap<>();
        files.put("/release-index/latest.txt", document.getBytes(StandardCharsets.UTF_8));
        files.put("/release-index/latest.txt.sig",
            ReleaseKeyTest.sign(kp, signed.getBytes(StandardCharsets.UTF_8)));
        return new Published(files, List.of(ReleaseKeyTest.spki(kp)));
    }

    private static Updates.Result check(Published p, ServerSocket ss) {
        return Updates.check(RUNNING, at(ss, p), NOW, null);
    }

    private static Updates.Result check(Published p, ServerSocket ss, Path floor) {
        return Updates.check(RUNNING, at(ss, p), NOW, floor);
    }

    /** What the node wrote down, read back as the node would rather than as a string it contains. */
    private static long seqIn(Path floor) throws IOException {
        return Json.parseObject(Files.readString(floor)).lng("seq");
    }

    @Test
    void theAnnouncementComesFromTheSignedPointer() throws Exception {
        Published p = publish(document(7, "v0.2.0", ISSUED, FAR));
        try (ServerSocket ss = serve(p.files())) {
            Updates.Result r = check(p, ss);
            assertNull(r.error(), r.line());
            assertTrue(r.newer());
            assertEquals(Updates.Outcome.NEWER, r.outcome());
            assertEquals("0.2.0", r.latest());
            assertTrue(r.line().contains("0.2.0 is out"), r.line());
        }
    }

    @Test
    void aPointerSignedByNobodyThisBuildAcceptsIsRefused() throws Exception {
        // The reason the whole exercise exists: before this, the version a node announced came from
        // a release index nobody had signed. A signature that does not verify is not a smaller
        // answer than one that does -- there is no unsigned path left to fall back to.
        Published p = publish(document(7, "v0.2.0", ISSUED, FAR), "some other bytes entirely");
        try (ServerSocket ss = serve(p.files())) {
            Updates.Result r = check(p, ss);
            assertNotNull(r.error());
            assertFalse(r.newer());
            // Bytes arrived and were rejected: the one a node says out loud, unlike a failed fetch.
            assertEquals(Updates.Outcome.REFUSED, r.outcome());
            assertTrue(r.error().contains("matches none of the keys"), r.error());
        }
    }

    @Test
    void anExpiredPointerCannotTellRatherThanSayingUpToDate() throws Exception {
        // A node on the release the pointer names, with a pointer nobody has re-issued. "You are
        // the latest release" is exactly the sentence a withheld upgrade would produce, so it is
        // the one thing this must not say.
        Published p = publish(document(7, "v" + RUNNING, ISSUED, PAST));
        try (ServerSocket ss = serve(p.files())) {
            Updates.Result r = check(p, ss);
            assertNull(r.error(), r.line());
            assertFalse(r.newer());
            assertEquals(Updates.Outcome.STALE, r.outcome());
            assertFalse(r.line().contains("is the latest release"), r.line());
            assertTrue(r.line().startsWith("cannot tell"), r.line());
        }
    }

    @Test
    void anExpiredPointerStillAnnouncesAnUpgradeItNames() throws Exception {
        // And does not block one: the signature, the tag binding and never-below-running all still
        // hold over a stale pointer, so refusing would forbid a real upgrade to avert a risk the
        // refusal does not reduce. `newer` is what --download acts on.
        Published p = publish(document(7, "v0.2.0", ISSUED, PAST));
        try (ServerSocket ss = serve(p.files())) {
            Updates.Result r = check(p, ss);
            assertNull(r.error(), r.line());
            assertTrue(r.newer());
            assertEquals(Updates.Outcome.STALE, r.outcome());
            assertTrue(r.line().contains("there may be something newer still"), r.line());
        }
    }

    @Test
    void aClockThatDisagreesCannotTellRatherThanFailing() throws Exception {
        // A VM with no NTP is the ordinary cause, and both documents promise it reports "cannot
        // tell" -- so this is the same answer an expiry gives, not the error a refusal gives, and
        // the upgrade the pointer names is still offered rather than withheld over a clock.
        Published p = publish(document(7, "v0.2.0", "2026-06-01T00:00:00Z", "2026-09-01T00:00:00Z"));
        try (ServerSocket ss = serve(p.files())) {
            Updates.Result r = check(p, ss);
            assertEquals(Updates.Outcome.CANNOT_TELL, r.outcome());
            assertTrue(r.cannotTell());
            assertTrue(r.newer(), "an upgrade is still an upgrade when the clock is wrong");
            assertNotNull(r.error());
            assertTrue(r.error().contains("ahead of this clock"), r.error());
        }
    }

    @Test
    void theSkewAllowanceIsWhatDecidesIt() throws Exception {
        // Pins the boundary rather than a value five months out, so setting CLOCK_SKEW_MS to zero
        // fails here instead of leaving the suite green.
        long issued = NOW + Updates.CLOCK_SKEW_MS - 60_000;
        Published inside = publish(document(7, "v0.2.0", Instant.ofEpochMilli(issued).toString(), FAR));
        try (ServerSocket ss = serve(inside.files())) {
            assertEquals(Updates.Outcome.NEWER, Updates.check(RUNNING, at(ss, inside), NOW, null).outcome());
        }
        Published outside = publish(document(7, "v0.2.0",
            Instant.ofEpochMilli(issued + 120_000).toString(), FAR));
        try (ServerSocket ss = serve(outside.files())) {
            assertEquals(Updates.Outcome.CANNOT_TELL, Updates.check(RUNNING, at(ss, outside), NOW, null).outcome());
        }
    }

    @Test
    void aBuildWithNoKeyCannotTellEither() throws Exception {
        // It already refuses to download, for the same reason: a check that cannot be made is not
        // quietly skipped. Before this, such a build still announced versions from an unsigned index.
        Published p = publish(document(7, "v0.2.0", ISSUED, FAR));
        try (ServerSocket ss = serve(p.files())) {
            Updates.Result r = Updates.check(RUNNING,
                new Updates.Source(at(ss, p).base(), List.of()), NOW);
            assertNotNull(r.error());
            assertFalse(r.newer());
            assertTrue(r.error().contains("no release signing key"), r.error());
        }
    }

    @Test
    void anIndexThatIsNotThereIsAnErrorAndNotAnAnswer() throws Exception {
        Published p = publish(document(7, "v0.2.0", ISSUED, FAR));
        try (ServerSocket ss = serve(Map.of())) { // the release exists for nobody
            Updates.Result r = check(p, ss);
            assertNotNull(r.error());
            assertFalse(r.newer());
            // Nothing arrived to judge, which is a node without a network -- not a pointer this
            // node looked at and refused. The daemon logs one of those and not the other.
            assertEquals(Updates.Outcome.UNREACHABLE, r.outcome());
        }
    }

    // --- the fortnight before it runs out -------------------------------------------------------

    @Test
    void aPointerRunningOutSaysSoWhileThereIsStillTimeToFixIt() throws Exception {
        // Re-issuing is a person at a laptop calling KMS, so the warning has to arrive before the
        // pointer stops answering, not after. Thirteen days out it does; fifteen days out there is
        // nothing to say yet.
        long soon = NOW + 13L * 24 * 60 * 60 * 1000;
        Published p = publish(document(7, "v" + RUNNING, ISSUED, Instant.ofEpochMilli(soon).toString()));
        try (ServerSocket ss = serve(p.files())) {
            Updates.Result r = check(p, ss);
            assertEquals(Updates.Outcome.CURRENT, r.outcome());
            assertTrue(r.expiringSoon(NOW));
            assertNotNull(r.warning(NOW));
            assertTrue(r.warning(NOW).contains("no longer tell"), r.warning(NOW));
        }
        long later = NOW + 15L * 24 * 60 * 60 * 1000;
        Published q = publish(document(7, "v" + RUNNING, ISSUED, Instant.ofEpochMilli(later).toString()));
        try (ServerSocket ss = serve(q.files())) {
            Updates.Result r = check(q, ss);
            assertFalse(r.expiringSoon(NOW));
            assertNull(r.warning(NOW));
        }
    }

    @Test
    void aPointerThatHasAlreadyExpiredDoesNotAlsoWarnAboutExpiring() throws Exception {
        // It has stopped answering, which `line()` already says. Two sentences about the same fact,
        // one of them in the future tense, would be worse than one.
        Published p = publish(document(7, "v" + RUNNING, ISSUED, PAST));
        try (ServerSocket ss = serve(p.files())) {
            Updates.Result r = check(p, ss);
            assertEquals(Updates.Outcome.STALE, r.outcome());
            assertFalse(r.expiringSoon(NOW));
            assertNull(r.warning(NOW));
        }
    }

    @Test
    void aRefusedPointersExpiryIsNotThisNodesToRepeat(@TempDir Path home) throws Exception {
        // A refused pointer carries dates too -- chosen by whoever published the document this node
        // just rejected. Repeating one as "the release index expires on ..." would be the node
        // stating an attacker's date as a fact about the current index, daily, beside the refusal.
        Path floor = home.resolve("update.json");
        Published newer = publish(document(9, "v0.3.0", ISSUED, FAR));
        try (ServerSocket ss = serve(newer.files())) {
            assertEquals(Updates.Outcome.NEWER, check(newer, ss, floor).outcome());
        }
        long soon = NOW + 3L * 24 * 60 * 60 * 1000;
        Published replayed = publish(document(7, "v0.2.0", ISSUED, Instant.ofEpochMilli(soon).toString()));
        try (ServerSocket ss = serve(replayed.files())) {
            Updates.Result r = check(replayed, ss, floor);
            assertEquals(Updates.Outcome.REFUSED, r.outcome());
            assertFalse(r.expiringSoon(NOW), "a refused pointer's expiry is not the index's");
            assertNull(r.warning(NOW));
        }
    }

    @Test
    void aClockThisNodeDoesNotTrustDoesNotDateTheWarningEither() throws Exception {
        // The skew case says "cannot tell" because this node's clock disagrees with the document.
        // A fortnight measured with that same clock is not something to then assert.
        long issued = NOW + Updates.CLOCK_SKEW_MS + 120_000;
        long soon = NOW + 3L * 24 * 60 * 60 * 1000;
        Published p = publish(document(7, "v0.2.0", Instant.ofEpochMilli(issued).toString(),
            Instant.ofEpochMilli(soon).toString()));
        try (ServerSocket ss = serve(p.files())) {
            Updates.Result r = check(p, ss);
            assertEquals(Updates.Outcome.CANNOT_TELL, r.outcome());
            assertNull(r.warning(NOW));
        }
    }

    // --- the document itself ---------------------------------------------------------------------

    @Test
    void readsWhatTheToolingWrites() throws Exception {
        Updates.Index i = Updates.Index.parse(document(7, "v0.2.0", ISSUED, FAR));
        assertEquals(7, i.seq());
        assertEquals("v0.2.0", i.tag());
        assertEquals(Instant.parse(ISSUED).toEpochMilli(), i.issued());
        assertEquals(Instant.parse(FAR).toEpochMilli(), i.expires());
    }

    @Test
    void anUnknownFieldIsIgnoredAndAnUnknownFormatIsNot() throws Exception {
        // §5.4's additive rule applied to a file: a later release may say more than this build
        // needs, and a format line it was not taught is a change it cannot assume is additive.
        Updates.Index i = Updates.Index.parse(document(7, "v0.2.0", ISSUED, FAR) + "channel: beta\n");
        assertEquals("v0.2.0", i.tag());
        assertTrue(assertThrows(IOException.class,
            () -> Updates.Index.parse("jailscale-index 2\nseq: 7\ntag: v0.2.0\nissued: " + ISSUED
                + "\nexpires: " + FAR + "\n")).getMessage().contains("not in a format this build reads"));
    }

    @Test
    void aRepeatedFieldIsReadTheWayTheOtherSignedDocumentIsRead() throws Exception {
        // Both parsers take the last one. A tool and a node reading one signed document differently
        // is the failure worth ruling out, whichever end they agree on.
        Updates.Index i = Updates.Index.parse(Updates.INDEX_FORMAT + "\nseq: 7\ntag: v0.1.9\ntag: v0.2.0\n"
            + "issued: " + ISSUED + "\nexpires: " + FAR + "\n");
        assertEquals("v0.2.0", i.tag());
        Updates.Manifest m = Updates.Manifest.parse(Updates.MANIFEST_FORMAT + "\ntag: v0.1.9\ntag: v0.2.0\n"
            + "sha256sums: " + "0".repeat(64) + "\n");
        assertEquals("v0.2.0", m.tag());
    }

    @Test
    void whatItCannotReadItRefusesRatherThanGuesses() {
        assertThrows(IOException.class, () -> Updates.Index.parse(document(7, "v0.2.0", ISSUED, "soon")));
        assertThrows(IOException.class, () -> Updates.Index.parse(
            Updates.INDEX_FORMAT + "\nseq: seven\ntag: v0.2.0\nissued: " + ISSUED + "\nexpires: " + FAR + "\n"));
        assertThrows(IOException.class, () -> Updates.Index.parse(
            Updates.INDEX_FORMAT + "\nseq: -1\ntag: v0.2.0\nissued: " + ISSUED + "\nexpires: " + FAR + "\n"));
        // Zero is refused as well, and not for tidiness: `Seen` reads a stored zero as "no floor at
        // all", so a pointer at zero would be accepted and then remembered as never having been seen.
        assertThrows(IOException.class, () -> Updates.Index.parse(document(0, "v0.2.0", ISSUED, FAR)));
        // A tag that would steer the URL somewhere else on a host that is otherwise the right one.
        assertThrows(IOException.class, () -> Updates.Index.parse(document(7, "../../evil", ISSUED, FAR)));
        // Every field is required: a pointer missing one is not a pointer with a default.
        assertThrows(IOException.class, () -> Updates.Index.parse(
            Updates.INDEX_FORMAT + "\nseq: 7\ntag: v0.2.0\nissued: " + ISSUED + "\n"));
        // Expiring before it was issued is not a stale pointer, it is a broken one.
        assertThrows(IOException.class, () -> Updates.Index.parse(document(7, "v0.2.0", FAR, ISSUED)));
    }

    @Test
    void aSequenceHasOneSpelling() throws Exception {
        // `09` is nine to Long.parseLong and nine to the shell's guards, and then kills the shell on
        // the next arithmetic expansion; `+9` is nine here and nothing there. Either way the tooling
        // and the fleet would be holding different sequences over identical signed bytes, so a
        // sequence that cannot be spelled the same way twice is refused instead.
        assertTrue(assertThrows(IOException.class, () -> Updates.Index.parse(
            Updates.INDEX_FORMAT + "\nseq: 09\ntag: v0.2.0\nissued: " + ISSUED + "\nexpires: " + FAR + "\n"))
            .getMessage().contains("one spelling"));
        assertThrows(IOException.class, () -> Updates.Index.parse(
            Updates.INDEX_FORMAT + "\nseq: +9\ntag: v0.2.0\nissued: " + ISSUED + "\nexpires: " + FAR + "\n"));
        assertEquals(9, Updates.Index.parse(document(9, "v0.2.0", ISSUED, FAR)).seq());
    }

    @Test
    void anIndentedFieldIsNotAFieldHereEither() throws Exception {
        // The shell reader anchors the name at the start of the line. A line this accepted and that
        // one did not would be the two of them reading one signed document differently -- which is
        // the whole failure the last-one-wins rule above exists to rule out.
        Updates.Index i = Updates.Index.parse(document(5, "v0.2.0", ISSUED, FAR) + " seq: 99\n");
        assertEquals(5, i.seq());
    }

    @Test
    void anInstantTooLargeToHoldIsRefusedRatherThanThrown() {
        // Instant.parse accepts instants either side of what a long of milliseconds can hold, and
        // toEpochMilli then throws ArithmeticException -- which used to escape a method declaring
        // IOException and reach the operator as "could not check for updates: long overflow".
        assertTrue(assertThrows(IOException.class, () -> Updates.Index.parse(
            document(7, "v0.2.0", ISSUED, "+999999999-12-31T23:59:59.999999999Z")))
            .getMessage().contains("cannot read"));
    }

    // --- the floor: what stops an older signed pointer being put back up ---------------------------

    @Test
    void aPointerThatWentBackwardsIsRefused(@TempDir Path home) throws Exception {
        // The prevention half (docs/update-freshness, step 3). Everything about this pointer is
        // genuine -- it is signed, unexpired, and names a release above the running one -- and it is
        // still refused, because this node has already been told about a later one. Without the
        // floor, whoever can publish can put an old pointer back up and hold a node on the release
        // it names for as long as they like.
        Path floor = home.resolve("update.json");
        Published newer = publish(document(9, "v0.3.0", ISSUED, FAR));
        try (ServerSocket ss = serve(newer.files())) {
            assertEquals("0.3.0", check(newer, ss, floor).latest());
        }
        assertEquals(9, seqIn(floor));

        Published replayed = publish(document(7, "v0.2.0", ISSUED, FAR));
        try (ServerSocket ss = serve(replayed.files())) {
            Updates.Result r = check(replayed, ss, floor);
            assertNotNull(r.error());
            assertFalse(r.newer());
            assertEquals(Updates.Outcome.REFUSED, r.outcome());
            assertTrue(r.error().contains("went backwards"), r.error());
            assertTrue(r.error().contains("9"), r.error()); // what it has seen, so the operator can tell
        }
        // And the refusal did not quietly lower the floor it was refused against.
        assertEquals(9, seqIn(floor));
    }

    @Test
    void theSameSequenceAgainIsTheNormalCase(@TempDir Path home) throws Exception {
        // A daily check reads the same pointer it read yesterday. Only *below* is a refusal.
        Path floor = home.resolve("update.json");
        Published p = publish(document(9, "v0.3.0", ISSUED, FAR));
        try (ServerSocket ss = serve(p.files())) {
            assertNull(check(p, ss, floor).error());
            assertNull(check(p, ss, floor).error());
        }
    }

    @Test
    void aRefusedPointerIsNotOneThisNodeHasSeen(@TempDir Path home) throws Exception {
        // The floor must not be advanced by a pointer that failed a check above it -- otherwise a
        // pointer nobody accepted still raises the bar for the ones that follow.
        Path floor = home.resolve("update.json");
        Published bad = publish(document(11, "v0.4.0", ISSUED, FAR), "not the document");
        try (ServerSocket ss = serve(bad.files())) {
            assertNotNull(check(bad, ss, floor).error());
        }
        assertFalse(Files.exists(floor), "a signature that did not verify wrote a floor");
    }

    @Test
    void aNodeWithNowhereToKeepTheFloorStillChecks(@TempDir Path home) throws Exception {
        // `jailscale update` runs on machines with no state directory, and there the floor is the
        // weaker one it has always had: the version this binary is. It is not a reason to refuse.
        Published p = publish(document(7, "v0.2.0", ISSUED, FAR));
        try (ServerSocket ss = serve(p.files())) {
            assertNull(check(p, ss, null).error());
            // An unwritable home does not fail the check either; the floor simply does not advance.
            Path unwritable = home.resolve("nope/update.json");
            Files.createFile(home.resolve("nope"));
            Updates.Result r = check(p, ss, unwritable);
            assertNull(r.error(), r.line());
            assertTrue(r.newer());
        }
    }

    @Test
    void aFloorThatCannotBeReadIsRebuiltRatherThanFatal(@TempDir Path home) throws Exception {
        // Whoever can corrupt this file is already on this machine as this user. Refusing to check
        // for updates ever again would be a worse answer than taking the next pointer that verifies.
        Path floor = home.resolve("update.json");
        Files.writeString(floor, "{ this is not json");
        Published p = publish(document(7, "v0.2.0", ISSUED, FAR));
        try (ServerSocket ss = serve(p.files())) {
            assertNull(check(p, ss, floor).error());
        }
        assertEquals(7, seqIn(floor));
    }
}
