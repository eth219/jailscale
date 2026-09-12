package io.jailscale.node;

import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Args;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Entry point of the {@code jailscale} binary: a CLI that talks to the resident daemon over IPC. */
public final class Main {

    private static final String USAGE = """
        jailscale up --invite https://hub.example.com/join/TOKEN [--user NAME]
        jailscale up --hub HOST [--code XXXX-XXXX | --auth-key jk_... ] [--user NAME]
                     [--hub-key hkey:... [--tls-insecure]] [--ca-file PEM] [--port 443] [--hub-addr IP] [--connections 1..4]
        jailscale open PORT [--name NAME] [--host 127.0.0.1] [--gate] [--proxy-protocol]
        jailscale open PORT --tcp | --udp [--port HUBPORT]     raw port, no TLS (ARCHITECTURE.md §8.4)
        jailscale open PORT --domain app.example.com [--acme-email E] [--acme-staging | --acme-directory URL]
                                                              your own domain, CNAME'd to the hub (ARCHITECTURE.md §8.3)
        jailscale gate NAME [--new-link [--ttl 24h] | --off]
        jailscale ls | close NAME
        jailscale status | down | leave | netcheck | admin | daemon
        jailscale verify                                     check that this node, not the hub, terminates the TLS for its names
        jailscale service install | uninstall | status       keep the daemon running across logins (launchd/systemd/schtasks)
        jailscale invite [--user NAME] [--uses N] [--ttl 24h] [--self]
        jailscale update                                     say whether a newer release is out; never installs it
        jailscale version
        """;

    private Main() {}

    public static void main(String[] argv) {
        Args a;
        try {
            a = Args.parse(argv, "debug", "self", "tls-insecure", "foreground", "help", "gate", "new-link", "off", "tcp", "udp", "acme-staging", "proxy-protocol");
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
            System.exit(cmd == null ? 2 : 0);
            return;
        }
        NodeConfig cfg = a.has("home") ? NodeConfig.in(Path.of(a.get("home"))) : NodeConfig.defaults();
        try {
            switch (cmd) {
                case "version" -> System.out.println("jailscale " + Version.string());
                case "update" -> {
                    // In this process rather than through the daemon: a node that is down is exactly
                    // when someone asks, and the check needs nothing the daemon holds.
                    Updates.Result r = Updates.check(Version.string());
                    if (r.error() != null) {
                        throw new IOException(r.line()); // like every other command: stderr, exit 1
                    }
                    System.out.println(r.line());
                }
                case "service" -> Service.run(a.positional(1) == null ? "status" : a.positional(1), cfg);
                case "daemon" -> runDaemon(cfg);
                case "up" -> up(cfg, a);
                case "status" -> print(call(cfg, JsonObject.builder().put("cmd", "status").build(), false));
                case "down", "leave", "netcheck", "verify" -> print(call(cfg, JsonObject.builder().put("cmd", cmd).build(), false));
                case "invite" -> invite(cfg, a);
                case "open" -> open(cfg, a);
                case "ls" -> ls(cfg);
                case "admin" -> {
                    JsonObject r = call(cfg, JsonObject.builder().put("cmd", "admin").build(), false);
                    String url = r.string("url");
                    System.out.println("admin page (open it within 60 seconds): " + url);
                    openBrowser(url);
                }
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
                        System.out.println("visit link: " + v + (copyToClipboard(v) ? "        (copied to clipboard)" : ""));
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

    private static void runDaemon(NodeConfig cfg) throws Exception {
        Daemon d = new Daemon(cfg);
        d.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                d.close();
            } catch (IOException ignored) {
                // exiting
            }
        }));
        Thread.currentThread().join();
    }

    private static void up(NodeConfig cfg, Args a) throws Exception {
        JsonObject.Builder b = JsonObject.builder().put("cmd", "up")
            .put("invite", a.get("invite")).put("hub", a.get("hub")).put("port", a.integer("port", 443))
            .put("code", a.get("code")).put("authKey", a.get("auth-key")).put("user", a.get("user"))
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
        if (a.flag("tcp") && a.flag("udp")) {
            throw new IllegalArgumentException("--tcp and --udp are exclusive");
        }
        String kind = a.flag("tcp") ? "tcp" : a.flag("udp") ? "udp" : "https";
        JsonObject.Builder b = JsonObject.builder().put("cmd", "open").put("port", Integer.parseInt(port))
            .put("host", a.get("host", "127.0.0.1")).put("name", a.get("name")).put("kind", kind).put("gate", a.flag("gate"));
        if (a.has("port")) {
            b.put("hubPort", a.integer("port", 0));
        }
        if (a.has("proxy-protocol")) {
            b.put("proxyProtocol", a.flag("proxy-protocol"));
        }
        if (a.has("domain")) {
            b.put("domain", a.get("domain"));
            if (a.has("acme-directory")) {
                b.put("acmeDirectory", a.get("acme-directory"));
            } else if (a.flag("acme-staging")) {
                b.put("acmeDirectory", "https://acme-staging-v02.api.letsencrypt.org/directory");
            }
            if (a.has("acme-email")) {
                b.put("acmeEmail", a.get("acme-email"));
            }
            System.out.println(a.get("domain") + ": checking the certificate… (the first ACME issuance takes tens of seconds)");
        }
        JsonObject r = call(cfg, b.build(), false);
        String url = r.string("url");
        if (!kind.equals("https")) {
            System.out.println(url + "  ->  " + r.string("local"));
            System.out.println("(hub port " + r.integer("hubPort") + ". the hub can see any plaintext protocol the app does not encrypt itself; "
                + "with SSH, WireGuard or a DB with TLS on, the hub sees only ciphertext)");
            return;
        }
        String visit = r.optString("visitUrl", null);
        String copied = visit != null ? visit : url;
        System.out.println(url + "  ->  " + r.string("local") + (visit != null ? "        (gate on)" : ""));
        if (visit != null) {
            System.out.println("visit link: " + visit);
        }
        if (copyToClipboard(copied)) {
            System.out.println("(" + (visit != null ? "visit link" : "link") + " copied to clipboard)");
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
        System.out.println("  link:  " + url + (copyToClipboard(url) ? "        <- copied to clipboard" : ""));
        if (r.has("code")) {
            System.out.println("  code:  " + r.string("code") + "                             <- for reading out over the phone (10 min)");
        }
        System.out.println("the other side runs: jailscale up --invite " + url);
    }

    /** Sends a request to the daemon, starting it if needed. Progress lines are printed as they arrive. */
    private static JsonObject call(NodeConfig cfg, JsonObject req, boolean startDaemon) throws Exception {
        if (!Ipc.isAlive(cfg.socketPath())) {
            if (!startDaemon) {
                throw new IOException("daemon is not running (start with 'jailscale up' or 'jailscale daemon')");
            }
            spawnDaemon(cfg);
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

    private static void print(JsonObject r) {
        System.out.println(r);
    }

    /** Starts {@code <this binary> daemon} detached, logging to the config directory. */
    private static void spawnDaemon(NodeConfig cfg) throws IOException, InterruptedException {
        Files.createDirectories(cfg.configDir());
        List<String> cmd = new ArrayList<>();
        String self = ProcessHandle.current().info().command().orElse(null);
        if (self == null) {
            throw new IOException("cannot determine own executable to start the daemon");
        }
        cmd.add(self);
        if (self.endsWith("java") || self.endsWith("java.exe")) {
            // Running from the fallback JAR under a JVM.
            cmd.add("-cp");
            cmd.add(System.getProperty("java.class.path"));
            cmd.add(Main.class.getName());
        }
        cmd.add("daemon");
        cmd.add("--home");
        cmd.add(cfg.configDir().toString());
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
        throw new IOException("daemon did not start; see " + cfg.daemonLog());
    }

    /** Opens a URL in the user's browser without AWT (ARCHITECTURE.md §3.1). */
    static void openBrowser(String url) {
        List<String> cmd = switch (HubLink.osName()) {
            case "macos" -> List.of("open", url);
            case "windows" -> List.of("rundll32", "url.dll,FileProtocolHandler", url);
            default -> List.of("xdg-open", url);
        };
        try {
            new ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        } catch (IOException e) {
            // headless: the URL is printed anyway
        }
    }

    private static boolean copyToClipboard(String text) {
        String os = HubLink.osName();
        List<String> cmd = switch (os) {
            case "macos" -> List.of("pbcopy");
            case "linux" -> List.of("xclip", "-selection", "clipboard");
            case "windows" -> List.of("clip.exe");
            default -> null;
        };
        if (cmd == null) {
            return false;
        }
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            try (var out = p.getOutputStream()) {
                out.write(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            return p.waitFor() == 0;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }
}
