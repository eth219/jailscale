package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * What the {@code jailscale} binary prints, asserted by running it.
 *
 * <p>Every other end-to-end test here speaks the daemon's IPC directly, which is the same call the
 * CLI makes and none of the code around it: {@code Main} was the least covered class in the project
 * at 3.9% of its lines, and {@code Service.daemonCommand} -- the command both {@code up} and
 * {@code service install} build -- at 25.9%, while `CliFlagsTest` checked only that the flag table
 * and the usage text agree. So the layer the user actually sees was the one nothing ran. This runs
 * it as a process: real argument parsing, real IPC, a daemon the CLI spawns for itself through
 * {@link io.jailscale.node.Service#daemonCommand}, and stdout asserted as text.
 *
 * <p>Running it as a process has a cost worth stating: a coverage tool attached to the test JVM
 * cannot see into the child, so {@code Main} still reads as 3.9% of its lines covered with these
 * tests passing, exactly as it did without them. The number is wrong, not the tests -- whoever next
 * measures coverage here should not conclude the CLI is unexercised and should not chase the number
 * by moving assertions in-process, which would give up the argument parsing, the process exit code
 * and the daemon spawn that are the point.
 *
 * <p>The child's stdout is a pipe, so the CLI does not touch the clipboard and these tests cannot
 * replace the clipboard of whoever runs them. That is the CLI's rule and not an arrangement here:
 * it copies only when someone is looking at the output. This was first attempted by emptying the
 * child's {@code PATH} so {@code pbcopy}/{@code xclip}/{@code clip.exe} could not be found, which
 * worked everywhere except the one platform nobody could test locally -- {@code CreateProcess}
 * searches System32 before {@code PATH}, and that is where {@code clip.exe} is, so the windows-2025
 * job failed against a comment claiming the copy could not happen "by construction". The PATH is
 * still emptied, now as a second lock on the same door rather than the only one.
 */
@Timeout(180)
class CliTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Path home;
    private Path emptyPath;
    private Hub hub;
    private int port;
    private ServerSocket app;

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.INFO);
        root = TestDirs.newRoot("jcli");
        home = root.resolve("alice");
        emptyPath = Files.createDirectories(root.resolve("nopath"));
        port = TestPorts.reserve();
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.start();
        app = TestPorts.listen(8);
        Thread.ofVirtual().start(() -> {
            while (!app.isClosed()) {
                try {
                    Socket c = app.accept();
                    Thread.ofVirtual().start(() -> serveApp(c));
                } catch (IOException e) {
                    return;
                }
            }
        });
    }

    private void serveApp(Socket c) {
        try (c) {
            HttpRequest r = Http.readRequest(c.getInputStream(), 4096);
            HttpResponse.text(200, "local " + r.path()).writeTo(c.getOutputStream());
        } catch (Exception e) {
            // visitor gone
        }
    }

    @AfterEach
    void stop() throws Exception {
        killSpawnedDaemon();
        app.close();
        hub.close();
    }

    /**
     * The daemon the CLI started is a process of its own, so nothing in this class's lifecycle ends
     * it. Its pid is in the lock file it holds (ARCHITECTURE.md §9.4), which is also how a second
     * daemon is told who has the directory.
     */
    private void killSpawnedDaemon() throws IOException {
        Path lock = home.resolve("daemon.lock");
        if (!Files.exists(lock)) {
            return;
        }
        String text = Files.readString(lock, StandardCharsets.UTF_8).trim();
        if (text.isEmpty()) {
            return;
        }
        long pid;
        try {
            pid = ((JsonObject) Json.parse(text)).lng("pid");
        } catch (RuntimeException e) {
            return; // a half-written lock is not worth failing a teardown over
        }
        ProcessHandle.of(pid).ifPresent(p -> {
            p.destroy();
            try {
                if (!p.onExit().orTimeout(10, TimeUnit.SECONDS).thenApply(x -> true).exceptionally(x -> false).get()) {
                    p.destroyForcibly();
                }
            } catch (Exception e) {
                p.destroyForcibly();
            }
        });
    }

    /** What one run of the binary produced. */
    private record Run(int exit, String out, String err) {
        String all() {
            return out + err;
        }
    }

    /**
     * The classpath the child needs, taken from where these classes were actually loaded from
     * rather than from {@code java.class.path}: under surefire that property can be a manifest-only
     * booter jar, and the daemon the child spawns for itself copies it into its own command line.
     */
    private static String classpath() throws Exception {
        Set<String> entries = new LinkedHashSet<>();
        for (Class<?> c : List.of(io.jailscale.node.Main.class, io.jailscale.hub.Main.class,
                io.jailscale.proto.json.JsonObject.class, io.jailscale.crypto.KeyText.class)) {
            entries.add(Path.of(c.getProtectionDomain().getCodeSource().getLocation().toURI()).toAbsolutePath().toString());
        }
        return String.join(File.pathSeparator, entries);
    }

    private Run cli(String... args) throws Exception {
        List<String> full = new ArrayList<>(List.of(args));
        full.add("--home");
        full.add(home.toAbsolutePath().toString());
        return run(io.jailscale.node.Main.class, full);
    }

    /** The other binary, for the paths the two entry points share. It is given no state directory. */
    private Run jailhub(String... args) throws Exception {
        return run(io.jailscale.hub.Main.class, List.of(args));
    }

    private Run run(Class<?> main, List<String> args) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(ProcessHandle.current().info().command()
            .orElse(Path.of(System.getProperty("java.home"), "bin", "java").toString()));
        cmd.add("-cp");
        cmd.add(classpath());
        cmd.add(main.getName());
        cmd.addAll(args);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        // See the class comment: no pbcopy, no xclip, no clip.exe.
        pb.environment().put("PATH", emptyPath.toString());
        pb.environment().remove("JAILSCALE_DAEMON_OPTS");
        Process p = pb.start();
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String err = new String(p.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(p.waitFor(120, TimeUnit.SECONDS), "the CLI did not exit: " + cmd);
        return new Run(p.exitValue(), out, err);
    }

    private Run ok(Run r) {
        assertEquals(0, r.exit(), "exit " + r.exit() + "\nstdout: " + r.out() + "\nstderr: " + r.err());
        return r;
    }

    /** Joins this hub with registration open, then waits until the daemon says it is connected. */
    private void join() throws Exception {
        Run up = ok(cli("up", "--hub", "hub.test", "--hub-addr", "127.0.0.1", "--port", String.valueOf(port),
            "--user", "alice", "--ca-file", CERT.toString()));
        // The progress lines the daemon streams back arrive before the result and are printed as
        // they arrive, which is the whole point of `up` taking a stream and not a call: a join that
        // hangs has to say which step it is on. So the outcome is somewhere in the output, not at
        // the start of it.
        assertTrue(up.out().contains("pinned hub key hkey:"), up.all());
        assertTrue(up.out().contains("joined as node "), up.all());
        assertTrue(up.out().contains("(alice)"), up.all());
        long deadline = System.currentTimeMillis() + 30_000;
        while (System.currentTimeMillis() < deadline) {
            if (ok(cli("status")).out().contains("\"connected\":true")) {
                return;
            }
            Thread.sleep(200);
        }
        throw new AssertionError("the daemon never reported itself connected: " + ok(cli("status")).out());
    }

    /**
     * The line is the binary's name, its version, and the protocol it speaks -- the last because
     * the hub's page names a protocol ("this hub speaks protocol N and takes nothing older") and
     * the only other way to find out whether the copy in your hand satisfies that sentence was to
     * attempt a join and read the rejection (#140).
     *
     * <p>The number is asserted against {@link Message#PROTO} rather than against a literal, so
     * this fails in both directions it has to: dropping the suffix stops the line matching at all,
     * and a hand-written number in {@code Main} that is not the one the protocol holds fails the
     * comparison. A literal here would pass a flag day while the CLI lied about it. Both were
     * checked by making them happen.
     *
     * <p>The number is read from {@code Message.PROTO} reflectively, and that is not decoration.
     * {@code PROTO} is a compile-time constant: written as {@code Message.PROTO}, javac folds it
     * into this class exactly as it folds it into {@code Main}, and the assertion would compare
     * two copies of the same vintage -- a tree that recompiled {@code proto} alone would print a
     * stale number and pass. A reflective read goes to the loaded {@code proto} class instead, so
     * the child's folded copy is checked against what the protocol holds now. Falsified by doing
     * it: bumping {@code PROTO} and rebuilding only {@code proto} fails this test.
     */
    @Test
    void versionIsTheBinaryNameItsVersionAndTheProtocolItSpeaks() throws Exception {
        Run r = ok(cli("version"));
        Matcher m = Pattern.compile("^jailscale \\S+ \\(protocol (\\d+)\\)$").matcher(r.out().strip());
        // The shape carries the old assertion too: a line with the version missing is
        // `jailscale (protocol 1)`, which this does not match.
        assertTrue(m.matches(), "not the version line: " + r.all());
        int proto = Message.class.getField("PROTO").getInt(null);
        assertEquals(String.valueOf(proto), m.group(1),
            "the CLI names a protocol this build does not speak: " + r.out());
    }

    @Test
    void noCommandIsTheUsageAndAFailingExit() throws Exception {
        Run r = cli();
        // 2, not 0: `jailscale` on its own in a script is a mistake, and asking for help is not.
        assertEquals(2, r.exit(), r.all());
        assertTrue(r.out().contains("jailscale up --invite"), r.all());
        // Asking for help succeeds, and the usage goes to stdout so it can be paged. Both forms:
        // a bare `--help` used to print this same text and exit 2, because the branch that answers
        // it is the one for "no command given" and the exit was chosen from the command rather than
        // from the flag, so `jailscale --help | less` reported a failure.
        Run help = ok(cli("up", "--help"));
        assertTrue(help.out().contains("jailscale up --invite"), help.all());
        Run bare = ok(cli("--help"));
        assertEquals(help.out(), bare.out(), bare.all());
    }

    /**
     * The same two entry points, the same rule. `jailhub` carried an identical copy of the exit
     * that made `--help` a failure, and fixing one of two identical bugs is how the second one
     * survives -- so both are asserted here, where the assertion costs one process each.
     */
    @Test
    void theHubBinaryAnswersHelpTheSameWay() throws Exception {
        Run help = jailhub("--help");
        assertEquals(0, help.exit(), help.all());
        assertTrue(help.out().contains("jailhub"), help.all());

        Run bare = jailhub();
        assertEquals(2, bare.exit(), bare.all());
        assertEquals(help.out(), bare.out(), bare.all());
    }

    @Test
    void anUnknownCommandIsNamedAndTheUsageFollowsOnStderr() throws Exception {
        Run r = cli("opne", "8080");
        assertEquals(2, r.exit(), r.all());
        assertTrue(r.err().contains("unknown command opne"), r.all());
        assertTrue(r.err().contains("jailscale open PORT"), r.all());
        assertEquals("", r.out(), "nothing belongs on stdout when the command was not understood");
    }

    @Test
    void aCommandThatNeedsADaemonSaysHowToStartOneRatherThanFailingBlankly() throws Exception {
        Run r = cli("status");
        assertEquals(1, r.exit(), r.all());
        assertTrue(r.err().contains("daemon is not running"), r.all());
        assertTrue(r.err().contains("jailscale up"), "the message has to name the way out: " + r.err());
        // And it did not start one behind the reader's back: only `up` may do that.
        assertFalse(Files.exists(home.resolve("daemon.lock")), "status started a daemon");
    }

    @Test
    void aMissingArgumentIsNamedForWhatItIsMissing() throws Exception {
        Run r = cli("open");
        assertEquals(2, r.exit(), r.all());
        assertTrue(r.err().contains("open needs a local port"), r.all());
        Run gate = cli("gate");
        assertEquals(2, gate.exit(), gate.all());
        assertTrue(gate.err().contains("gate needs a link name"), gate.all());
    }

    @Test
    void joinOpenListAndCloseAreWhatTheUserReads() throws Exception {
        join();

        // The whole of what `open` prints, not a substring of it: this is the line the user reads,
        // and one line is all of it into a pipe. A second line here means the clipboard was taken
        // from a process nobody is watching, on whatever machine ran this.
        Run open = ok(cli("open", String.valueOf(app.getLocalPort()), "--name", "demo"));
        assertEquals("https://demo.hub.test:" + port + "  ->  127.0.0.1:" + app.getLocalPort(),
            open.out().strip(), open.all());

        Run ls = ok(cli("ls"));
        assertTrue(ls.out().contains("demo"), ls.all());
        assertTrue(ls.out().contains("https://demo.hub.test:" + port), ls.all());
        assertTrue(ls.out().contains("127.0.0.1:" + app.getLocalPort()), ls.all());
        assertTrue(ls.out().contains("open"), "a link the node is serving reads as open: " + ls.out());

        Run close = ok(cli("close", "demo"));
        assertEquals("closed demo", close.out().strip(), close.all());

        Run empty = ok(cli("ls"));
        assertTrue(empty.out().contains("no open links"), empty.all());
        assertTrue(empty.out().contains("jailscale open"), "an empty list says what to do next: " + empty.out());
    }

    @Test
    void inviteSaysWhatTheOtherSideRuns() throws Exception {
        join();
        Run r = ok(cli("invite", "--user", "bob"));
        assertTrue(r.out().contains("created an invite."), r.all());
        int link = r.out().indexOf("https://hub.test:" + port + "/join/");
        assertNotEquals(-1, link, r.all());
        String url = r.out().substring(link).split("\\s+")[0];
        // The line the reader is meant to paste has to carry the same link, not a second one.
        assertTrue(r.out().contains("the other side runs: jailscale up --invite " + url), r.all());
    }

    @Test
    void theGateSaysWhoCanReachTheNameEitherWay() throws Exception {
        join();
        ok(cli("open", String.valueOf(app.getLocalPort()), "--name", "demo"));

        Run on = ok(cli("gate", "demo"));
        assertTrue(on.out().startsWith("visit link: https://demo.hub.test:" + port), on.all());

        Run off = ok(cli("gate", "demo", "--off"));
        assertEquals("turned the gate off. anyone can now reach demo.", off.out().strip(), off.all());
    }
}
