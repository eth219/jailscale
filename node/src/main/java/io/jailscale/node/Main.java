package io.jailscale.node;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Args;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Entry point of the {@code jailscale} binary: a CLI that talks to the resident daemon over IPC. */
public final class Main {

    /**
     * What the binary can be told to do. Package-private so {@link CliFlagsTest} can hold
     * {@link #FLAGS} against it: a flag that is declared and named nowhere here is one nothing
     * reads, which is what {@code --new-link} and {@code --foreground} both turned out to be.
     */
    static final String USAGE = """
        jailscale up --invite https://hub.example.com/join/TOKEN [--user NAME]
        jailscale up --hub HOST [--code XXXX-XXXX] [--user NAME]
                     [--hub-key hkey:... [--tls-insecure]] [--ca-file PEM] [--port 443] [--hub-addr IP] [--connections 1..4]
        jailscale open PORT [--name NAME] [--host 127.0.0.1] [--gate] [--proxy-protocol]
        jailscale gate NAME [--ttl 24h | --off]              each run issues a fresh visit link
        jailscale ls | close NAME
        jailscale status | down | leave | netcheck | daemon
        jailscale verify                                     check that this node, not the hub, terminates the TLS for its names
        jailscale invite [--user NAME] [--uses N] [--ttl 24h] [--self]
        jailscale update                                     say whether a newer release is out
        jailscale update --download [--dir DIR]               fetch that release and check its signature; installing it stays yours
        jailscale version
        """;

    /**
     * Options that take no value. Every option this binary reads with {@code flag()} has to be
     * here, or {@link Args#parse} reads the next word as its value -- and anything here that
     * nothing reads is a flag the CLI accepts and ignores. {@code --new-link} was the second kind:
     * documented on {@code gate}, declared here, read nowhere, because {@code gate NAME} issues a
     * fresh link every run with or without it.
     */
    static final String[] FLAGS = {"debug", "self", "tls-insecure", "help", "gate", "off",
        "proxy-protocol", "download"};

    private Main() {}

    public static void main(String[] argv) {
        Args a;
        try {
            a = Args.parse(argv, FLAGS);
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            System.exit(2);
            return;
        }
        if (a.flag("debug")) {
            Log.setLevel(Log.Level.DEBUG);
        }
        String cmd = a.positional(0);
        if (cmd == null || a.flag("help")) {
            System.out.print(USAGE);
            // Asking for help succeeded, whether or not a command was named with it. This used to
            // key off the command instead, so `jailscale --help` printed the usage and exited 2 --
            // `jailscale --help | less` reported a failure, and a script that checked the status of
            // its own --help saw one. Only a bare invocation with nothing to do is an error.
            System.exit(a.flag("help") ? 0 : 2);
            return;
        }
        NodeConfig cfg = configOf(a);
        try {
            switch (cmd) {
                // The protocol number, beside the version, because the hub's page names one
                // ("this hub speaks protocol N and takes nothing older") and a reader holding a
                // copy of this binary had no way to print the other. It is the same constant
                // HubLink puts in every Hello -- but PROTO is a compile-time constant and javac
                // folds it into the string here, so what this prints is the number `node` was
                // last compiled against, not the one `proto` holds now. A clean build is what
                // makes them the same, and a clean build is what CI and every release do.
                case "version" -> System.out.println("jailscale " + Version.string() + " (protocol " + Message.PROTO + ")");
                case "update" -> update(a);
                case "daemon" -> runDaemon(cfg);
                case "up" -> up(cfg, a);
                case "status" -> print(call(cfg, JsonObject.builder().put("cmd", "status").build(), false));
                case "down", "leave", "netcheck" -> print(call(cfg, JsonObject.builder().put("cmd", cmd).build(), false));
                case "verify" -> {
                    // The rows are the answer; `ok` only says the daemon ran the check. Exit
                    // status still says whether every name verified, for anything scripting this.
                    JsonObject r = call(cfg, JsonObject.builder().put("cmd", "verify").build(), false);
                    print(r);
                    if (!r.optBool("allOk", true)) {
                        System.exit(1);
                    }
                }
                case "invite" -> invite(cfg, a);
                case "open" -> open(cfg, a);
                case "ls" -> ls(cfg);
                case "gate" -> {
                    String name = a.positional(1);
                    if (name == null) {
                        throw new IllegalArgumentException("gate needs a link name");
                    }
                    JsonObject.Builder b = JsonObject.builder().put("cmd", "gate").put("name", name).put("off", a.flag("off"));
                    if (a.has("ttl")) {
                        b.put("ttl", a.seconds("ttl", 0));
                    }
                    JsonObject r = call(cfg, b.build(), false);
                    if (r.optBool("gate", false)) {
                        String v = r.string("visitUrl");
                        System.out.println("visit link: " + v);
                    } else {
                        System.out.println("turned the gate off. anyone can now reach " + name + ".");
                    }
                }
                case "close" -> {
                    String name = a.positional(1);
                    if (name == null) {
                        throw new IllegalArgumentException("close needs a link name");
                    }
                    call(cfg, JsonObject.builder().put("cmd", "close").put("name", name).build(), false);
                    System.out.println("closed " + name);
                }
                default -> {
                    System.err.println("unknown command " + cmd);
                    System.err.print(USAGE);
                    System.exit(2);
                }
            }
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.exit(2);
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * {@code update [--download]}. In this process rather than through the daemon: a node that is
     * down is exactly when someone asks, and the check needs nothing the daemon holds.
     *
     * <p>Which release is current is GitHub's word -- {@code releases/latest}, unsigned -- and the
     * output says so. {@code --download} stops at a verified file on disk and the command that
     * installs it (ARCHITECTURE.md §9.4): what is in the release is checked against the
     * maintainer's signature, which is the part of installing by hand that goes wrong quietly --
     * picking the right target, and checking a checksum in a way that can report success for
     * having checked nothing. What it deliberately leaves is the step that needs a privilege this
     * process does not have.
     */
    private static void update(Args a) throws Exception {
        Updates.Result r = Updates.check(Version.string());
        if (r.error() != null) {
            // No answer -- GitHub unreachable, or a `dev` build with nothing to compare -- is an
            // error like every other command's: stderr, exit 1, so a script can tell it from "up to
            // date". Not a refusal of anything: nothing was checked, so nothing failed a check.
            throw new IOException(r.line());
        }
        System.out.println(r.line());
        if (!a.flag("download") || !r.newer()) {
            if (r.newer()) {
                System.out.println("that it is the newest is GitHub's word; `update --download` checks what"
                    + " is in it against the maintainer's signature.");
            }
            return; // nothing to fetch: there is no newer release, or nobody asked for it
        }
        boolean temp = !a.has("dir");
        Path dir = temp ? Files.createTempDirectory("jailscale-update") : Path.of(a.get("dir"));
        Updates.Downloaded d;
        try {
            d = Updates.fetch(r.running(), r.tag(), dir);
        } catch (Exception e) {
            // A temp directory made here is removed here on failure: fetch leaves nothing in it,
            // and one empty jailscale-updateNNNN per failed attempt is not "nothing left behind".
            if (temp) {
                try {
                    Files.deleteIfExists(dir);
                } catch (IOException _) {
                    // the download's own reason is the one to report
                }
            }
            throw e;
        }
        System.out.printf("downloaded  %s  %.1f MiB%n", d.asset(), d.bytes() / (1024.0 * 1024.0));
        System.out.println("verified    sha256 " + d.sha256());
        System.out.println("            against a " + Updates.MANIFEST + " for " + r.tag()
            + " signed by release key " + d.key());
        System.out.println("            (that " + r.tag() + " is the newest release is GitHub's word;"
            + " what is in it is the signature's)");
        System.out.println();
        System.out.println("install it with:");
        System.out.println("  " + Updates.installCommand(d.file(), Updates.self(), Updates.windows()));
        System.out.println();
        System.out.println("a daemon that is already running keeps the binary it started with until it restarts.");
    }

    private static void runDaemon(NodeConfig cfg) throws Exception {
        // Before anything is opened: a second daemon on this directory would share the MachineKey
        // and the state file with the first (ARCHITECTURE.md §9.4). The lock is held for the life
        // of the process and released by the kernel when it ends.
        DaemonLock lock = DaemonLock.acquire(cfg);
        Daemon d = new Daemon(cfg);
        d.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                d.close();
                lock.close();
            } catch (IOException _) {
                // exiting
            }
        }));
        Thread.currentThread().join();
    }

    private static void up(NodeConfig cfg, Args a) throws Exception {
        if (a.has("auth-key")) {
            // Args keeps any --flag value it is handed, so without this the flag would parse, be
            // ignored, and the join would proceed as a knock (#251).
            throw new IllegalArgumentException("--auth-key was removed; join with --invite <link> or --code XXXX-XXXX");
        }
        JsonObject.Builder b = JsonObject.builder().put("cmd", "up")
            .put("invite", a.get("invite")).put("hub", a.get("hub")).put("port", a.integer("port", 443))
            .put("code", a.get("code")).put("user", a.get("user"))
            .put("hubKey", a.get("hub-key")).put("tlsInsecure", a.flag("tls-insecure")).put("caFile", a.get("ca-file"))
            .put("addr", a.get("hub-addr")).put("connections", a.has("connections") ? Integer.valueOf(a.integer("connections", 1)) : null);
        JsonObject r = call(cfg, b.build(), true);
        String status = r.optString("status", "");
        switch (status) {
            case "approved" -> System.out.println("joined as node " + r.lng("nodeId") + " (" + r.string("user") + ")");
            case "connected" -> System.out.println("connected as node " + r.lng("nodeId") + " (" + r.string("user") + ")");
            case "pending" -> System.out.println("waiting for admin approval. Ask the hub admin to run:\n"
                + "  jailhub node approve " + r.string("machineKey"));
            default -> System.out.println(r);
        }
    }

    private static void open(NodeConfig cfg, Args a) throws Exception {
        String port = a.positional(1);
        if (port == null) {
            throw new IllegalArgumentException("open needs a local port");
        }
        JsonObject.Builder b = JsonObject.builder().put("cmd", "open").put("port", Integer.parseInt(port))
            .put("host", a.get("host", "127.0.0.1")).put("name", a.get("name")).put("gate", a.flag("gate"));
        if (a.has("proxy-protocol")) {
            b.put("proxyProtocol", a.flag("proxy-protocol"));
        }
        JsonObject r = call(cfg, b.build(), false);
        String url = r.string("url");
        String visit = r.optString("visitUrl", null);
        System.out.println(url + "  ->  " + r.string("local") + (visit != null ? "        (gate on)" : ""));
        if (visit != null) {
            System.out.println("visit link: " + visit);
        }
    }

    private static void ls(NodeConfig cfg) throws Exception {
        JsonObject r = call(cfg, JsonObject.builder().put("cmd", "ls").build(), false);
        java.util.List<Object> links = r.array("links");
        if (links.isEmpty()) {
            System.out.println("no open links. open one with: jailscale open <port>");
            return;
        }
        for (Object o : links) {
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> m = (java.util.Map<String, Object>) o;
            String warn = m.get("certExpiresAt") instanceof Long exp
                ? certNote(exp, System.currentTimeMillis())
                : "";
            System.out.printf("%-8s %-40s -> %-22s %s%s%n", m.get("name"), m.get("url"), m.get("local"),
                Boolean.TRUE.equals(m.get("open")) ? "open" : "offline", warn);
        }
    }

    /**
     * What {@code ls} adds after a link whose certificate is running out, and "" while there is
     * nothing to say. The threshold is the daemon's ({@link Daemon#CERT_WARN_MS}) so the table and
     * the log do not tell two stories, and an expired certificate is named as expired: "expires"
     * next to a date in the past reads as a formatting bug rather than as a site already down.
     */
    static String certNote(long expiresAt, long now) {
        if (expiresAt <= 0) {
            return ""; // no certificate on this link, or none loaded yet
        }
        if (expiresAt <= now) {
            return "  (cert EXPIRED " + new java.util.Date(expiresAt) + ")";
        }
        return expiresAt - now < Daemon.CERT_WARN_MS ? "  (cert expires " + new java.util.Date(expiresAt) + ")" : "";
    }

    private static void invite(NodeConfig cfg, Args a) throws Exception {
        JsonObject.Builder b = JsonObject.builder().put("cmd", "invite").put("user", a.get("user"))
            .put("uses", a.integer("uses", 0)).put("self", a.flag("self"));
        if (a.has("ttl")) {
            b.put("ttl", a.seconds("ttl", 0));
        }
        JsonObject r = call(cfg, b.build(), false);
        String url = r.string("url");
        System.out.println("created an invite.");
        System.out.println("  link:  " + url);
        if (r.has("code")) {
            System.out.println("  code:  " + r.string("code") + "                             <- for reading out over the phone (10 min)");
        }
        System.out.println("the other side runs: jailscale up --invite " + url);
    }

    /**
     * Where this process keeps its files and which socket it speaks on. {@code --home} alone puts
     * the socket inside that directory, which is what a test wants; {@code --socket} names it
     * separately, which is what the CLI passes to the daemon it spawns, because the two do not
     * agree on their own -- {@link NodeConfig#defaultSocketPath} prefers {@code XDG_RUNTIME_DIR}
     * and a bare {@code --home} cannot know that.
     */
    static NodeConfig configOf(Args a) {
        if (!a.has("home")) {
            return NodeConfig.defaults();
        }
        Path home = Path.of(a.get("home"));
        return a.has("socket") ? new NodeConfig(home, Path.of(a.get("socket")), NodeConfig.Tuning.defaults()) : NodeConfig.in(home);
    }

    /** Sends a request to the daemon, starting it if needed. Progress lines are printed as they arrive. */
    private static JsonObject call(NodeConfig config, JsonObject req, boolean startDaemon) throws Exception {
        NodeConfig cfg = config;
        if (!Ipc.isAlive(cfg.socketPath())) {
            // Where the socket is depends on the environment that asks -- XDG_RUNTIME_DIR is set in
            // a login session and not in cron -- so before concluding that nothing is running, ask
            // the daemon that is running where it put its socket (§9.4).
            NodeConfig recorded = runningElsewhere(cfg);
            if (recorded != null) {
                cfg = recorded;
            } else if (!startDaemon) {
                throw new IOException("daemon is not running (start with 'jailscale up' or 'jailscale daemon')");
            } else {
                spawnDaemon(cfg);
            }
        }
        JsonObject[] last = new JsonObject[1];
        Ipc.stream(cfg.socketPath(), req, line -> {
            if (line.has("msg")) {
                System.out.println(line.string("msg"));
            }
            last[0] = line;
        });
        JsonObject r = last[0];
        if (!r.optBool("ok", false)) {
            throw new IOException(r.optString("error", "failed"));
        }
        return r;
    }

    /**
     * The socket of a daemon that is running but listening somewhere this process would not have
     * looked, taken from the lock file it holds. Null unless something is answering there, so a
     * file left by a daemon that has since died sends nobody anywhere.
     */
    private static NodeConfig runningElsewhere(NodeConfig cfg) {
        JsonObject holder = DaemonLock.holder(cfg);
        if (holder == null) {
            return null;
        }
        String socket = holder.optString("socket", null);
        if (socket == null || socket.equals(cfg.socketPath().toAbsolutePath().toString())) {
            return null;
        }
        Path path = Path.of(socket);
        return Ipc.isAlive(path) ? new NodeConfig(cfg.configDir(), path, cfg.tuning()) : null;
    }

    private static void print(JsonObject r) {
        System.out.println(r);
    }

    /**
     * Starts {@code <this binary> daemon} detached, logging to the config directory. The command
     * comes from {@link DaemonCommand}, which is also what an operator's unit runs: the two used to
     * be built separately and had drifted apart.
     */
    private static void spawnDaemon(NodeConfig cfg) throws IOException, InterruptedException {
        Files.createDirectories(cfg.configDir());
        if (ProcessHandle.current().info().command().isEmpty()) {
            throw new IOException("cannot determine own executable to start the daemon");
        }
        List<String> cmd = DaemonCommand.of(cfg);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        pb.redirectOutput(ProcessBuilder.Redirect.appendTo(cfg.daemonLog().toFile()));
        Process p = pb.start();
        p.getOutputStream().close(); // the daemon never reads stdin
        long deadline = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < deadline) {
            if (Ipc.isAlive(cfg.socketPath())) {
                return;
            }
            Thread.sleep(100);
        }
        // Say what the daemon said. A bad JAILSCALE_DAEMON_OPTS is refused by the runtime before
        // anything of ours runs, and "daemon did not start" on its own sends the reader to a log to
        // find a one-line answer.
        String why = "";
        try {
            List<String> log = Files.readAllLines(cfg.daemonLog());
            for (int i = log.size() - 1; i >= 0 && i >= log.size() - 5; i--) {
                if (!log.get(i).isBlank()) {
                    why = ": " + log.get(i).strip();
                    break;
                }
            }
        } catch (IOException _) {
            // no log to quote
        }
        throw new IOException("daemon did not start" + why + " (see " + cfg.daemonLog() + ")");
    }

}
