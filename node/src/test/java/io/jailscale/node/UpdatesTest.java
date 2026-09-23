package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.net.TestPorts;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class UpdatesTest {

    private static int cmp(String a, String b) {
        Integer c = Updates.compare(a, b);
        assertTrue(c != null, a + " vs " + b + " should be comparable");
        return Integer.signum(c);
    }

    @Test
    void ordersReleases() {
        assertEquals(0, cmp("0.1.0", "0.1.0"));
        assertEquals(-1, cmp("0.1.0", "0.1.1"));
        assertEquals(-1, cmp("0.1.0", "0.2.0"));
        assertEquals(-1, cmp("0.9.9", "1.0.0"));
        assertEquals(1, cmp("1.0.0", "0.9.9"));
        // Ten is above nine, which is where a string comparison would have said the opposite.
        assertEquals(-1, cmp("0.9.0", "0.10.0"));
        assertEquals(-1, cmp("0.1.9", "0.1.10"));
        // A missing component is zero, and the tag's leading v is not part of the number.
        assertEquals(0, cmp("0.1", "0.1.0"));
        assertEquals(0, cmp("v0.1.0", "0.1.0"));
        assertEquals(-1, cmp("v0.1.0", "v0.2.0"));
    }

    @Test
    void aSnapshotIsBelowTheReleaseItIsHeadingFor() {
        // Otherwise the machine this is developed on would be told it is behind by its own build.
        assertEquals(-1, cmp("0.2.0-SNAPSHOT", "0.2.0"));
        assertEquals(1, cmp("0.2.0-SNAPSHOT", "0.1.0"));
        assertEquals(-1, cmp("0.2.0-SNAPSHOT", "0.2.1"));
    }

    @Test
    void whatItCannotReadItDoesNotGuess() {
        // "cannot tell" has to stay distinguishable from "no update", or a source build quietly
        // reports itself current for ever.
        assertNull(Updates.compare("dev", "0.1.0"));
        assertNull(Updates.compare("0.1.0", "not-a-version"));
        assertNull(Updates.compare(null, "0.1.0"));
        assertNull(Updates.compare("", "0.1.0"));
        assertNull(Updates.compare("0.1.0.1.2", "0.1.0"));
        assertNull(Updates.compare("-1.0.0", "0.1.0"));
    }

    private static Updates.Result result(String running, String tag, boolean newer, String error) {
        return new Updates.Result(running, tag, newer, 0, error,
            error != null ? Updates.Outcome.UNKNOWN : newer ? Updates.Outcome.NEWER : Updates.Outcome.CURRENT);
    }

    @Test
    void everyOutcomeSaysSomethingUseful() {
        // "GitHub lists", not "is the latest release": which release is current is GitHub's word
        // and nothing signs it, and the line says so rather than promising more than it knows.
        assertEquals("jailscale 0.1.0 is the latest release GitHub lists.", result("0.1.0", "v0.1.0", false, null).line());
        assertTrue(result("0.1.0", "v0.2.0", true, null).line().contains("0.2.0 is out"));
        assertTrue(result("0.1.0", "v0.2.0", true, null).line().contains(Updates.PAGE));
        assertEquals("could not check for updates: no route to host",
            result("0.1.0", null, false, "no route to host").line());
        // The version is the tag's, derived rather than carried beside it, so the two cannot disagree.
        assertEquals("0.2.0", result("0.1.0", "v0.2.0", true, null).latest());
        assertEquals("0.2.0", result("0.1.0", "0.2.0", true, null).latest());
        assertNull(result("0.1.0", null, false, "x").latest());
    }

    @Test
    void theUpdateUrlIsNotSomethingAPeerCanChoose() throws Exception {
        // The hub is trusted to route bytes, not to say what this node should run (§11.2). If this
        // ever becomes configurable, a compromised hub can point every node at a binary it picked --
        // and the page that says which release is current is the first thing it would move.
        assertEquals("https://github.com/gosuda/jailscale/releases/latest", Updates.PAGE);
        assertEquals("https://github.com/gosuda/jailscale/releases/tag/", Updates.TAG_PAGE);
        assertEquals("https", URI.create(Updates.PAGE).getScheme());
        // And the same for where a download comes from and the key it must be signed with: the pair
        // production uses is built from two constants, so there is no configuration that moves it.
        assertEquals("https://github.com/gosuda/jailscale/releases/download/", Updates.DOWNLOADS);
        assertEquals(Updates.DOWNLOADS, Updates.Source.compiledIn().base());
        assertEquals(ReleaseKey.PUBLIC_KEYS, Updates.Source.compiledIn().keys());
    }

    // --- what GitHub's answer is read as ---------------------------------------------------------

    /** 2026-01-01T00:00:00Z. */
    private static final long NOW = 1_767_225_600_000L;

    /** What releases/latest answers: a redirect to the newest release's own page. */
    private static Updates.Latest redirect(String location) {
        return () -> HttpResponse.redirect(location);
    }

    /** {@link Updates#check} as the CLI calls it, with the compiled-in key list and a canned answer. */
    private static Updates.Result check(String running, Updates.Latest latest) {
        return Updates.check(running, latest, ReleaseKey.PUBLIC_KEYS, NOW);
    }

    @Test
    void aHigherTagInTheRedirectIsNewerAndTheSameTagIsCurrent() {
        Updates.Result r = check("0.1.0", redirect(Updates.TAG_PAGE + "v0.2.0"));
        assertEquals(Updates.Outcome.NEWER, r.outcome(), r.line());
        assertTrue(r.newer());
        assertEquals("v0.2.0", r.tag());
        assertEquals("0.2.0", r.latest());
        assertNull(r.error());
        assertEquals(NOW, r.checkedAt());
        assertTrue(r.line().startsWith("jailscale 0.2.0 is out; this is 0.1.0."), r.line());

        Updates.Result same = check("0.2.0", redirect(Updates.TAG_PAGE + "v0.2.0"));
        assertEquals(Updates.Outcome.CURRENT, same.outcome(), same.line());
        assertFalse(same.newer());
        assertEquals("v0.2.0", same.tag());
        assertNull(same.error());
        assertEquals("jailscale 0.2.0 is the latest release GitHub lists.", same.line());
        // A build ahead of the newest release -- the snapshot this is developed on -- is not
        // behind, and not an error either; and it is not "the latest release", so the line does
        // not say it is.
        Updates.Result ahead = check("0.3.0-SNAPSHOT", redirect(Updates.TAG_PAGE + "v0.2.0"));
        assertEquals(Updates.Outcome.CURRENT, ahead.outcome(), ahead.line());
        assertFalse(ahead.newer());
        assertEquals("jailscale 0.3.0-SNAPSHOT is not behind the latest release GitHub lists, 0.2.0.", ahead.line());
        // A relative Location resolves against the page that was asked, which is a way GitHub
        // could legitimately spell the same answer.
        assertEquals("v0.2.0", check("0.1.0", redirect("/gosuda/jailscale/releases/tag/v0.2.0")).tag());
    }

    @Test
    void aBuildWithNoSigningKeyDoesNotAnnounceWhatItCouldNotCheck() {
        // --download refuses on an empty key list; announcing NEWER first would promise the check
        // it then cannot make, so the announcement is refused one step earlier, whatever GitHub said.
        Updates.Result r = Updates.check("0.1.0", redirect(Updates.TAG_PAGE + "v0.2.0"), List.of(), NOW);
        assertEquals(Updates.Outcome.UNKNOWN, r.outcome(), r.line());
        assertFalse(r.newer());
        assertNull(r.tag());
        assertTrue(r.line().contains("carries no release signing key"), r.line());
        // And the list this build compiles in is not empty, or the check above is the whole product.
        assertFalse(ReleaseKey.PUBLIC_KEYS.isEmpty());
    }

    @Test
    void noAnswerIsUnknownRatherThanUpToDate() {
        // "You are the latest release" is the sentence a withheld upgrade produces, so every way
        // of not getting an answer has to come out as something other than that -- and other than
        // "newer", which would send --download after a tag nobody named.
        Updates.Latest down = () -> {
            throw new IOException("no route to host");
        };
        Updates.Result r = check("0.1.0", down);
        assertEquals(Updates.Outcome.UNKNOWN, r.outcome());
        assertFalse(r.newer());
        assertNull(r.tag());
        assertEquals("could not check for updates: no route to host", r.line());
        List<Updates.Latest> odd = List.of(
            () -> new HttpResponse(302), // a redirect with nowhere in it
            () -> HttpResponse.redirect("   "),
            () -> HttpResponse.html(200, "<html>"), // a page where the redirect should be
            () -> HttpResponse.text(503, "later"),
            // 3xx with a Location that is not a redirect a download would follow either: the one
            // rule, HttpCall.isRedirect, and not a range check that lets these two through.
            () -> new HttpResponse(300).header("Location", Updates.TAG_PAGE + "v0.2.0"),
            () -> new HttpResponse(305).header("Location", Updates.TAG_PAGE + "v0.2.0"),
            () -> {
                throw new HttpException(429, "slow down");
            },
            () -> {
                throw new IllegalStateException("a bug, not a network");
            });
        for (Updates.Latest o : odd) {
            Updates.Result u = check("0.1.0", o);
            assertEquals(Updates.Outcome.UNKNOWN, u.outcome(), u.line());
            assertFalse(u.newer(), u.line());
            assertNull(u.tag(), u.line());
            assertNotNull(u.error(), u.line());
            assertTrue(u.line().startsWith("could not check for updates: "), u.line());
        }
    }

    @Test
    void onlyARedirectToAReleasePageNamesARelease() {
        // The tag is pasted into a download URL, so a Location that is not exactly a release page
        // under this repository is not an answer -- not a login page, not the releases list, not a
        // release on another host, and not a tag with a path step in it.
        for (String elsewhere : List.of(
                "https://github.com/login?return_to=%2Fgosuda%2Fjailscale%2Freleases%2Flatest",
                "https://github.com/gosuda/jailscale/releases",
                "https://github.com/gosuda/jailscale/releases/",
                "https://github.com/gosuda/jailscale/releases/tag/",
                "https://github.com/gosuda/jailscale/releases/download/v0.2.0/jailscale.jar",
                "https://github.com/gosuda/other/releases/tag/v0.2.0",
                // Where the project lived until v0.2.1: GitHub redirects that name to this one, and
                // a node built before the move is still asking it.
                "https://github.com/eth219/jailscale/releases/tag/v0.2.0",
                "https://example.com/gosuda/jailscale/releases/tag/v0.2.0",
                "http://github.com/gosuda/jailscale/releases/tag/v0.2.0",
                "https://github.com/gosuda/jailscale/releases/tag/v0.2.0/../../../evil",
                "https://github.com/gosuda/jailscale/releases/tag/../download/v9",
                "https://github.com/gosuda/jailscale/releases/tag/v0.2.0?x=1",
                "https://github.com/gosuda/jailscale/releases/tag/" + "v".repeat(65),
                "::not a url::")) {
            Updates.Result r = check("0.1.0", redirect(elsewhere));
            assertEquals(Updates.Outcome.UNKNOWN, r.outcome(), elsewhere + " -> " + r.line());
            assertFalse(r.newer(), elsewhere);
            assertNull(r.tag(), elsewhere);
        }
    }

    @Test
    void aDevBuildCannotTellAndSaysSo() {
        // A source build has nothing to compare with. Not "current" -- that would report a dev
        // build up to date for ever -- and not a network failure either; what GitHub said is kept.
        Updates.Result r = check("dev", redirect(Updates.TAG_PAGE + "v0.2.0"));
        assertEquals(Updates.Outcome.UNKNOWN, r.outcome());
        assertFalse(r.newer());
        assertEquals("v0.2.0", r.tag());
        assertTrue(r.line().startsWith("could not check for updates: cannot compare this build (dev)"), r.line());
    }

    @Test
    void theRedirectIsReadAndNotFollowed() throws Exception {
        // GitHub answers releases/latest with a 302 to the release's own page, and the tag is in
        // the Location. Following it would fetch a page of HTML for nothing; here it would also
        // leave loopback for github.com, find no v9.9.9 there, and come out UNKNOWN rather than
        // NEWER. And a HEAD, because nothing of a body is wanted from either answer.
        AtomicReference<String> asked = new AtomicReference<>();
        try (ServerSocket ss = TestPorts.listen(5)) {
            Thread t = new Thread(() -> {
                try (Socket s = ss.accept()) {
                    HttpRequest req = Http.readRequest(s.getInputStream(), 0);
                    asked.set(req.method() + " " + req.path());
                    s.getOutputStream().write(("HTTP/1.1 302 Found\r\nLocation: " + Updates.TAG_PAGE + "v9.9.9"
                        + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                    s.getOutputStream().flush();
                } catch (Exception e) {
                    asked.set("failed: " + e);
                }
            }, "canned-latest");
            t.setDaemon(true);
            t.start();
            URI page = URI.create("http://" + ss.getInetAddress().getHostAddress() + ":" + ss.getLocalPort()
                + "/gosuda/jailscale/releases/latest");
            Updates.Result r = check("0.1.0", Updates.Latest.at(page));
            t.join(5_000);
            assertEquals("HEAD /gosuda/jailscale/releases/latest", asked.get());
            assertEquals(Updates.Outcome.NEWER, r.outcome(), r.line());
            assertEquals("v9.9.9", r.tag());
        }
    }

    // --- what a download is checked against ------------------------------------------------------

    private static final String SUMS = """
        6d0b1a4dce6e5e0d3e4b0ee0d0ab2a56b57e0dd8a2b1a06e0a49f24a2b5c93aa  jailscale-linux-amd64
        0000000000000000000000000000000000000000000000000000000000000001  jailhub-linux-amd64
        0000000000000000000000000000000000000000000000000000000000000002 *jailscale.jar
        """;

    @Test
    void aNameThatIsNotInTheListIsAnErrorRatherThanAPass() {
        // This is `sha256sum --ignore-missing -c` made into a bug: it exits 0 for having verified
        // nothing when the name it was handed is absent, which is what the install instructions warn
        // a human about. In code the same shape would be a download nothing was compared with.
        IOException e = assertThrows(IOException.class, () -> Updates.hashFor(SUMS, "jailscale-darwin-arm64"));
        assertTrue(e.getMessage().contains("no line for jailscale-darwin-arm64"), e.getMessage());
    }

    @Test
    void readsBothChecksumFormatsAndOnlyTheNameItWasAsked() throws Exception {
        assertEquals("6d0b1a4dce6e5e0d3e4b0ee0d0ab2a56b57e0dd8a2b1a06e0a49f24a2b5c93aa",
            Updates.hashFor(SUMS, "jailscale-linux-amd64"));
        // shasum writes "*name" in binary mode where sha256sum writes two spaces; both are published,
        // because the release hashes on whichever of the two the runner has (§14).
        assertEquals("0000000000000000000000000000000000000000000000000000000000000002",
            Updates.hashFor(SUMS, "jailscale.jar"));
        // The hub's binary is in the same file and is not this one.
        assertEquals("0000000000000000000000000000000000000000000000000000000000000001",
            Updates.hashFor(SUMS, "jailhub-linux-amd64"));
        // A name that merely starts the same must not match: jailscale-linux-amd64 is not the .exe.
        assertThrows(IOException.class, () -> Updates.hashFor(SUMS, "jailscale-linux-amd64.exe"));
        assertThrows(IOException.class, () -> Updates.hashFor(SUMS, "jailscale"));
    }

    @Test
    void aHashThatIsNotOneIsRefused() {
        assertThrows(IOException.class, () -> Updates.hashFor("zz  jailscale.jar\n", "jailscale.jar"));
        assertThrows(IOException.class, () -> Updates.hashFor("abc123  jailscale.jar\n", "jailscale.jar"));
        assertThrows(IOException.class, () -> Updates.hashFor(
            "0000000000000000000000000000000000000000000000000000000000000001  jailscale.jar\n"
            + "0000000000000000000000000000000000000000000000000000000000000002  jailscale.jar\n", "jailscale.jar"));
    }

    @Test
    void namesTheFileThisPlatformShouldRun() {
        assertEquals("linux-amd64", Updates.target("Linux", "amd64"));
        assertEquals("linux-amd64", Updates.target("Linux", "x86_64"));
        assertEquals("linux-arm64", Updates.target("Linux", "aarch64"));
        assertEquals("darwin-arm64", Updates.target("Mac OS X", "aarch64"));
        assertEquals("windows-amd64", Updates.target("Windows 11", "amd64"));
        // Targets the release does not build today are still named: the signed SHA256SUMS.txt is the
        // list of what was built, and hashFor refuses a name that is not in it. A second copy of
        // release.yml's matrix here would be the one forgotten when it grows. An OS or a CPU this
        // has no name for is null, because there is no name to look up.
        assertEquals("darwin-amd64", Updates.target("Mac OS X", "x86_64"));
        assertEquals("windows-arm64", Updates.target("Windows 11", "aarch64"));
        assertNull(Updates.target("FreeBSD", "amd64"));
        assertNull(Updates.target("Linux", "riscv64"));
        // "Darwin" contains "win"; it is a Mac, and the same classification windows() uses says so.
        assertEquals("darwin-arm64", Updates.target("Darwin", "arm64"));
        assertEquals("macos", HubLink.osName("Darwin"));

        assertEquals("jailscale-darwin-arm64", Updates.asset("darwin-arm64", true));
        assertEquals("jailscale-windows-amd64.exe", Updates.asset("windows-amd64", true));
        assertNull(Updates.asset(null, true));
        // Off the native image it is the JAR, whatever the machine is -- including the machines
        // above that have no binary of their own.
        assertEquals("jailscale.jar", Updates.asset(null, false));
        assertEquals("jailscale.jar", Updates.asset("linux-amd64", false));
    }

    @Test
    void aTagFromTheNetworkDoesNotGetToSteerTheUrl() throws Exception {
        assertEquals("https://github.com/gosuda/jailscale/releases/download/v0.2.0/SHA256SUMS.txt",
            Updates.assetUrl(Updates.DOWNLOADS, "v0.2.0", Updates.SUMS).toString());
        // The tag is whatever GitHub's redirect said, and it is pasted into a URL. A relative step
        // or a second host in there would leave the releases path while looking like a version.
        assertThrows(IOException.class, () -> Updates.assetUrl(Updates.DOWNLOADS, "../../../evil", "x"));
        assertThrows(IOException.class, () -> Updates.assetUrl(Updates.DOWNLOADS, "v0.2.0/../..", "x"));
        assertThrows(IOException.class, () -> Updates.assetUrl(Updates.DOWNLOADS, "v0.2.0/x", "x"));
        assertThrows(IOException.class, () -> Updates.assetUrl(Updates.DOWNLOADS, "//evil.example.com/", "x"));
        assertThrows(IOException.class, () -> Updates.assetUrl(Updates.DOWNLOADS, "", "x"));
        assertThrows(IOException.class, () -> Updates.assetUrl(Updates.DOWNLOADS, null, "x"));
        assertThrows(IOException.class, () -> Updates.assetUrl(Updates.DOWNLOADS, "v".repeat(65), "x"));
    }

    @Test
    void theInstallCommandAsksForRootOnlyWhereItIsNeeded(@TempDir Path tmp) throws Exception {
        Path downloaded = tmp.resolve("jailscale-linux-amd64");
        Files.writeString(downloaded, "x");
        Path mine = tmp.resolve("jailscale");
        Files.writeString(mine, "old");
        // A path under a directory that does not exist, so "not writable" is a property of the test
        // rather than of the machine running it -- /usr/local/bin is writable on some of them.
        Path theirs = tmp.resolve("no-such-dir").resolve("jailscale");

        // A path this user can write is not a path to type sudo at, and typing it anyway is how a
        // user-owned install ends up root-owned and unwritable by the next upgrade.
        assertEquals("install -m 755 " + q(downloaded) + " " + q(mine), Updates.installCommand(downloaded, mine, false));
        assertEquals("sudo install -m 755 " + q(downloaded) + " " + q(theirs),
            Updates.installCommand(downloaded, theirs, false));
        // Nothing said where this binary is: fall back to the path the install instructions use.
        assertTrue(Updates.installCommand(downloaded, null, false).endsWith(" /usr/local/bin/jailscale"));

        // Windows refuses to overwrite a file in use and allows it to be renamed, so the old one is
        // moved aside rather than replaced.
        String win = Updates.installCommand(downloaded, Path.of("C:\\bin\\jailscale.exe"), true);
        assertTrue(win.contains("Move-Item -Force"), win);
        assertTrue(win.contains("jailscale.exe.old"), win);
        assertFalse(win.contains("sudo"), win);
    }

    @Test
    void aJarIsCopiedRatherThanInstalledAsABinary(@TempDir Path tmp) throws Exception {
        // `install -m 755` on a jar produces an executable file that is not one, and points the
        // operator at /usr/local/bin, which is not where a jar goes.
        Path downloaded = tmp.resolve("jailscale.jar");
        Files.writeString(downloaded, "x");
        Path running = tmp.resolve("jailscale-0.1.3.jar");
        Files.writeString(running, "old");
        assertEquals("cp " + q(downloaded) + " " + q(running), Updates.installCommand(downloaded, running, false));
        // And with nowhere known to put it, a path with a blank in it rather than a confident wrong one.
        assertEquals("sudo cp " + q(downloaded) + " /path/to/jailscale.jar",
            Updates.installCommand(downloaded, null, false));
    }

    /** What the command prints for a path: a test cannot pick where @TempDir is, or what is in it. */
    private static String q(Path p) {
        return Updates.shellQuote(p.toString());
    }

    @Test
    void thePrintedCommandSurvivesASpaceInEitherPath() {
        // --dir "$HOME/My Downloads" and a jar under Application Support both put a space in a path
        // the operator is told to paste; unquoted, `install` sees three sources and a directory.
        assertEquals("/usr/local/bin/jailscale", Updates.shellQuote("/usr/local/bin/jailscale"));
        assertEquals("'/Users/me/My Downloads/jailscale-darwin-arm64'",
            Updates.shellQuote("/Users/me/My Downloads/jailscale-darwin-arm64"));
        assertEquals("'/tmp/it'\\''s/x'", Updates.shellQuote("/tmp/it's/x"));
        assertEquals("'$HOME/x'", Updates.shellQuote("$HOME/x")); // and a shell does not expand it
        assertEquals("'=dl/x'", Updates.shellQuote("=dl/x")); // zsh: =cmd is a command-path expansion
        assertEquals("a=b/x", Updates.shellQuote("a=b/x")); // but only at the start of the word
        assertEquals("''", Updates.shellQuote(""));
        // Through installCommand, with paths whose separators Path.of rewrites on Windows, so the
        // assertion is on the quoting rather than on the slashes.
        Path from = Path.of("/Users/me/My Downloads/jailscale-darwin-arm64");
        Path to = Path.of("/no such dir/jailscale");
        String cmd = Updates.installCommand(from, to, false);
        assertEquals("sudo install -m 755 " + Updates.shellQuote(from.toString()) + " " + Updates.shellQuote(to.toString()), cmd);
        assertTrue(cmd.startsWith("sudo install -m 755 '"), cmd);
        assertTrue(cmd.endsWith("/jailscale'") || cmd.endsWith("\\jailscale'"), cmd);

        // PowerShell: single quotes, in which only a quote means anything.
        assertEquals("'C:\\Program Files\\jailscale.exe'", Updates.powershellQuote("C:\\Program Files\\jailscale.exe"));
        assertEquals("'it''s.exe'", Updates.powershellQuote("it's.exe"));
        String win = Updates.installCommand(Path.of("C:\\Users\\me\\My Downloads\\jailscale-windows-amd64.exe"),
            Path.of("C:\\Program Files\\jailscale\\jailscale.exe"), true);
        assertTrue(win.contains("'C:\\Program Files\\jailscale\\jailscale.exe' 'C:\\Program Files\\jailscale\\jailscale.exe.old'"), win);
        assertTrue(win.contains("Move-Item 'C:\\Users\\me\\My Downloads\\jailscale-windows-amd64.exe'"), win);
    }

    @Test
    void selfIsNeverTheJavaLauncher() {
        // These run on a JVM, so ProcessHandle's command here is the java binary. Returning it would
        // put `install -m 755 jailscale.jar /path/to/bin/java` in front of an operator -- and on a
        // user-owned prefix, without even a sudo to make them look twice. What a JVM build replaces
        // is the jar it was started from, and a directory of classes under a test runner is neither,
        // so the answer here is nothing at all.
        assertFalse(Updates.nativeImage(), "these tests are supposed to run on a JVM");
        Path self = Updates.self();
        assertTrue(self == null || self.getFileName().toString().endsWith(".jar"),
            "self() returned " + self + ", which is not a jar and not null");
    }
}
