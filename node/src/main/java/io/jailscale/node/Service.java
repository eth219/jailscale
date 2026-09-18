package io.jailscale.node;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code jailscale service install|uninstall|status} (ARCHITECTURE.md §9.4): keep the daemon running
 * across logins and reboots with what the OS already has. launchd agent on macOS, systemd user
 * unit on Linux, a logon scheduled task on Windows. No third-party service wrapper.
 */
final class Service {

    private static final String LABEL = "io.jailscale.node";

    private Service() {}

    /**
     * The command that starts the daemon: the native binary, or the JVM and this classpath for the
     * fallback JAR. The one place that decides this -- {@code Main.spawnDaemon} used to build its
     * own version, which had drifted into using {@code -cp} where this used {@code -jar} and a
     * relative home where this used an absolute one, so a daemon started by the CLI and one started
     * by the installed unit were launched two different ways. Both paths are passed and both are
     * absolute: whoever launches the daemon decides where it listens, so the CLI and the daemon
     * cannot disagree about it.
     */
    static List<String> daemonCommand(NodeConfig cfg) {
        return daemonCommand(cfg, System.getenv("JAILSCALE_DAEMON_OPTS"));
    }

    /**
     * As above, with the runtime options taken as an argument so a test can supply them.
     *
     * <p>{@code JAILSCALE_DAEMON_OPTS} is a way in for the options the native runtime reads before
     * {@code main} does, {@code -XX:MaxHeapSize=} to lift the ceiling the build set (§14) being the
     * one in use. It is a measurement and diagnosis hatch rather than a product surface, which is
     * why it is an environment variable and not a flag on {@code up}: nothing measured so far asks
     * for a different ceiling. They go straight after the executable, which is where both a native
     * image and a JVM look, and whatever is set when {@code service install} runs is what the unit
     * carries from then on.
     */
    static List<String> daemonCommand(NodeConfig cfg, String opts) {
        List<String> cmd = new ArrayList<>();
        String exe = ProcessHandle.current().info().command().orElse("jailscale");
        String base = Path.of(exe).getFileName().toString().toLowerCase(java.util.Locale.ROOT);
        cmd.add(exe);
        // Straight after the executable, which is the only place both kinds of runtime look: a
        // native image parses -XX: before main sees the arguments, and a JVM only accepts them
        // before -cp and the main class.
        if (opts != null && !opts.isBlank()) {
            for (String opt : opts.trim().split("\\s+")) {
                cmd.add(opt);
            }
        }
        if (base.equals("java") || base.equals("java.exe")) {
            // Every entry absolute: a unit's ExecStart runs from a working directory of systemd's
            // choosing, not from wherever the CLI happened to be.
            StringBuilder cp = new StringBuilder();
            for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
                cp.append(cp.length() == 0 ? "" : File.pathSeparator).append(Path.of(entry).toAbsolutePath());
            }
            cmd.add("-cp");
            cmd.add(cp.toString());
            cmd.add(Main.class.getName());
        }
        cmd.add("daemon");
        cmd.add("--home");
        cmd.add(cfg.configDir().toAbsolutePath().toString());
        // And the socket, which is not always inside that directory: where XDG_RUNTIME_DIR is set,
        // which is every systemd login session, the CLI looks for it in /run/user/<uid>. Passing
        // only the home let the daemon bind the other one, and the CLI then waited five seconds for
        // a socket nobody was listening on and left the daemon it had just started behind.
        cmd.add("--socket");
        cmd.add(cfg.socketPath().toAbsolutePath().toString());
        return cmd;
    }

    static void run(String action, NodeConfig cfg) throws IOException, InterruptedException {
        switch (HubLink.osName()) {
            case "macos" -> launchd(action, cfg);
            case "windows" -> windows(action, cfg);
            default -> systemd(action, cfg);
        }
    }

    // --- macOS: launchd user agent ---------------------------------------------------------------

    private static void launchd(String action, NodeConfig cfg) throws IOException, InterruptedException {
        Path plist = Path.of(System.getProperty("user.home"), "Library", "LaunchAgents", LABEL + ".plist");
        String domain = "gui/" + uid();
        switch (action) {
            case "install" -> {
                Files.createDirectories(plist.getParent());
                StringBuilder args = new StringBuilder();
                for (String c : daemonCommand(cfg)) {
                    args.append("      <string>").append(xml(c)).append("</string>\n");
                }
                Files.writeString(plist, """
                    <?xml version="1.0" encoding="UTF-8"?>
                    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                    <plist version="1.0">
                    <dict>
                      <key>Label</key><string>%s</string>
                      <key>ProgramArguments</key>
                      <array>
                    %s  </array>
                      <key>RunAtLoad</key><true/>
                      <key>KeepAlive</key><true/>
                      <key>ProcessType</key><string>Background</string>
                      <key>StandardOutPath</key><string>%s</string>
                      <key>StandardErrorPath</key><string>%s</string>
                    </dict>
                    </plist>
                    """.formatted(LABEL, args, xml(cfg.daemonLog().toString()), xml(cfg.daemonLog().toString())));
                exec("launchctl", "bootout", domain + "/" + LABEL); // replace a previous registration, if any
                if (exec("launchctl", "bootstrap", domain, plist.toString()) != 0) {
                    exec("launchctl", "load", "-w", plist.toString()); // older launchctl
                }
                System.out.println("installed the launchd agent: " + plist);
                System.out.println("the jailscale daemon now starts at every login. to undo: jailscale service uninstall");
            }
            case "uninstall" -> {
                exec("launchctl", "bootout", domain + "/" + LABEL);
                Files.deleteIfExists(plist);
                System.out.println("removed the launchd agent.");
            }
            case "status" -> {
                boolean loaded = exec("launchctl", "print", domain + "/" + LABEL) == 0;
                System.out.println(Files.exists(plist) ? (loaded ? "installed, running (" + plist + ")" : "installed, not loaded (" + plist + ")") : "not installed");
            }
            default -> throw new IllegalArgumentException("service install | uninstall | status");
        }
    }

    // --- Linux: systemd user unit ---------------------------------------------------------------

    private static void systemd(String action, NodeConfig cfg) throws IOException, InterruptedException {
        boolean root = "0".equals(uid());
        Path unit = root ? Path.of("/etc/systemd/system/jailscale.service")
            : Path.of(System.getProperty("user.home"), ".config", "systemd", "user", "jailscale.service");
        String[] ctl = root ? new String[] {"systemctl"} : new String[] {"systemctl", "--user"};
        switch (action) {
            case "install" -> {
                Files.createDirectories(unit.getParent());
                StringBuilder exec = new StringBuilder();
                for (String c : daemonCommand(cfg)) {
                    exec.append(exec.length() == 0 ? "" : " ").append(unitQuote(c));
                }
                Files.writeString(unit, """
                    [Unit]
                    Description=jailscale node daemon
                    After=network-online.target
                    Wants=network-online.target

                    [Service]
                    ExecStart=%s
                    Restart=always
                    RestartSec=2s

                    [Install]
                    WantedBy=%s
                    """.formatted(exec, root ? "multi-user.target" : "default.target"));
                exec(cat(ctl, "daemon-reload"));
                int rc = exec(cat(ctl, "enable", "--now", "jailscale"));
                System.out.println("installed the systemd unit: " + unit + (rc == 0 ? "" : " (systemctl failed " + rc + ")"));
                if (!root) {
                    System.out.println("to keep it running after you log out: loginctl enable-linger " + System.getProperty("user.name"));
                }
            }
            case "uninstall" -> {
                exec(cat(ctl, "disable", "--now", "jailscale"));
                Files.deleteIfExists(unit);
                exec(cat(ctl, "daemon-reload"));
                System.out.println("removed the systemd unit.");
            }
            case "status" -> {
                if (!Files.exists(unit)) {
                    System.out.println("not installed");
                } else {
                    exec(cat(ctl, "--no-pager", "status", "jailscale"));
                }
            }
            default -> throw new IllegalArgumentException("service install | uninstall | status");
        }
    }

    // --- Windows: scheduled task at logon --------------------------------------------------------

    private static void windows(String action, NodeConfig cfg) throws IOException, InterruptedException {
        switch (action) {
            case "install" -> {
                StringBuilder tr = new StringBuilder();
                for (String c : daemonCommand(cfg)) {
                    tr.append(tr.length() == 0 ? "" : " ").append(c.contains(" ") ? "\\\"" + c + "\\\"" : c);
                }
                int rc = exec("schtasks", "/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED", "/TN", "jailscale", "/TR", tr.toString());
                if (rc == 0) {
                    exec("schtasks", "/Run", "/TN", "jailscale");
                    System.out.println("installed the task 'jailscale', which runs at logon.");
                } else {
                    System.out.println("schtasks failed (" + rc + ")");
                }
            }
            case "uninstall" -> {
                exec("schtasks", "/End", "/TN", "jailscale");
                exec("schtasks", "/Delete", "/F", "/TN", "jailscale");
                System.out.println("removed the task 'jailscale'.");
            }
            case "status" -> exec("schtasks", "/Query", "/TN", "jailscale");
            default -> throw new IllegalArgumentException("service install | uninstall | status");
        }
    }

    // --- helpers -------------------------------------------------------------------------------

    private static int exec(String... cmd) throws IOException, InterruptedException {
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
            p.getOutputStream().close();
            return p.waitFor();
        } catch (IOException e) {
            return 127;
        }
    }

    private static String[] cat(String[] head, String... tail) {
        String[] out = new String[head.length + tail.length];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(tail, 0, out, head.length, tail.length);
        return out;
    }

    private static String uid() {
        try {
            Process p = new ProcessBuilder("id", "-u").redirectErrorStream(true).start();
            p.getOutputStream().close();
            String s = new String(p.getInputStream().readAllBytes(), StandardCharsets.US_ASCII).trim();
            p.waitFor();
            return s.isEmpty() ? "501" : s;
        } catch (IOException | InterruptedException e) {
            return "501";
        }
    }

    private static String xml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String unitQuote(String s) {
        return s.contains(" ") || s.contains("\"") ? "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"" : s;
    }
}
