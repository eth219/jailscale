package io.jailscale.node;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code jailscale service install|uninstall|status} (DESIGN.md §10.5): keep the daemon running
 * across logins and reboots with what the OS already has. launchd agent on macOS, systemd user
 * unit on Linux, a logon scheduled task on Windows. No third-party service wrapper.
 */
final class Service {

    private static final String LABEL = "io.jailscale.node";

    private Service() {}

    /** The command that starts the daemon: the native binary, or {@code java -jar} for the fallback JAR. */
    static List<String> daemonCommand(NodeConfig cfg) {
        List<String> cmd = new ArrayList<>();
        String exe = ProcessHandle.current().info().command().orElse("jailscale");
        String base = Path.of(exe).getFileName().toString().toLowerCase(java.util.Locale.ROOT);
        if (base.equals("java") || base.equals("java.exe")) {
            cmd.add(exe);
            cmd.add("-jar");
            cmd.add(Path.of(System.getProperty("java.class.path")).toAbsolutePath().toString());
        } else {
            cmd.add(exe);
        }
        cmd.add("daemon");
        cmd.add("--home");
        cmd.add(cfg.configDir().toAbsolutePath().toString());
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
                System.out.println("launchd 에이전트를 등록했습니다: " + plist);
                System.out.println("로그인할 때마다 jailscale 데몬이 뜹니다. 해제: jailscale service uninstall");
            }
            case "uninstall" -> {
                exec("launchctl", "bootout", domain + "/" + LABEL);
                Files.deleteIfExists(plist);
                System.out.println("launchd 에이전트를 제거했습니다.");
            }
            case "status" -> {
                boolean loaded = exec("launchctl", "print", domain + "/" + LABEL) == 0;
                System.out.println(Files.exists(plist) ? (loaded ? "등록됨, 실행 중 (" + plist + ")" : "등록됨, 로드 안 됨 (" + plist + ")") : "등록 안 됨");
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
                System.out.println("systemd 유닛을 등록했습니다: " + unit + (rc == 0 ? "" : " (systemctl 실패 " + rc + ")"));
                if (!root) {
                    System.out.println("로그아웃해도 살리려면: loginctl enable-linger " + System.getProperty("user.name"));
                }
            }
            case "uninstall" -> {
                exec(cat(ctl, "disable", "--now", "jailscale"));
                Files.deleteIfExists(unit);
                exec(cat(ctl, "daemon-reload"));
                System.out.println("systemd 유닛을 제거했습니다.");
            }
            case "status" -> {
                if (!Files.exists(unit)) {
                    System.out.println("등록 안 됨");
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
                    System.out.println("로그온 시 실행되는 작업 'jailscale'을 등록했습니다.");
                } else {
                    System.out.println("schtasks 실패 (" + rc + ")");
                }
            }
            case "uninstall" -> {
                exec("schtasks", "/End", "/TN", "jailscale");
                exec("schtasks", "/Delete", "/F", "/TN", "jailscale");
                System.out.println("작업 'jailscale'을 제거했습니다.");
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
