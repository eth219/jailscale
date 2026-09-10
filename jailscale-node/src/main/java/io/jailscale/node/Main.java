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
                     [--hub-key hkey:... [--tls-insecure]] [--ca-file PEM] [--port 443] [--hub-addr IP]
        jailscale open PORT [--name NAME] [--host 127.0.0.1]
        jailscale ls | close NAME
        jailscale status | down | leave | netcheck | daemon
        jailscale invite [--user NAME] [--uses N] [--ttl 24h] [--self]
        jailscale version
        """;

    private Main() {}

    public static void main(String[] argv) {
        Args a;
        try {
            a = Args.parse(argv, "debug", "self", "tls-insecure", "foreground", "help");
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
                case "daemon" -> runDaemon(cfg);
                case "up" -> up(cfg, a);
                case "status" -> print(call(cfg, JsonObject.builder().put("cmd", "status").build(), false));
                case "down", "leave", "netcheck" -> print(call(cfg, JsonObject.builder().put("cmd", cmd).build(), false));
                case "invite" -> invite(cfg, a);
                case "open" -> open(cfg, a);
                case "ls" -> ls(cfg);
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
            .put("addr", a.get("hub-addr"));
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
        JsonObject r = call(cfg, JsonObject.builder().put("cmd", "open").put("port", Integer.parseInt(port))
            .put("host", a.get("host", "127.0.0.1")).put("name", a.get("name")).put("kind", "https").build(), false);
        String url = r.string("url");
        System.out.println(url + "  ->  " + r.string("local") + (copyToClipboard(url) ? "        (링크가 클립보드에 복사됨)" : ""));
    }

    private static void ls(NodeConfig cfg) throws Exception {
        JsonObject r = call(cfg, JsonObject.builder().put("cmd", "ls").build(), false);
        java.util.List<Object> links = r.array("links");
        if (links.isEmpty()) {
            System.out.println("열린 링크가 없습니다. jailscale open <port> 로 여세요.");
            return;
        }
        for (Object o : links) {
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> m = (java.util.Map<String, Object>) o;
            System.out.printf("%-8s %-40s -> %-22s %s%n", m.get("name"), m.get("url"), m.get("local"),
                Boolean.TRUE.equals(m.get("open")) ? "open" : "offline");
        }
    }

    private static void invite(NodeConfig cfg, Args a) throws Exception {
        JsonObject.Builder b = JsonObject.builder().put("cmd", "invite").put("user", a.get("user"))
            .put("uses", a.integer("uses", 0)).put("self", a.flag("self"));
        if (a.has("ttl")) {
            b.put("ttl", a.seconds("ttl", 0));
        }
        JsonObject r = call(cfg, b.build(), false);
        String url = r.string("url");
        System.out.println("초대를 만들었습니다.");
        System.out.println("  링크:  " + url + (copyToClipboard(url) ? "        <- 클립보드에 복사됨" : ""));
        if (r.has("code")) {
            System.out.println("  코드:  " + r.string("code") + "                             <- 전화로 불러줄 때 (10분)");
        }
        System.out.println("상대는: jailscale up --invite " + url);
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
