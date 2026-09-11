package io.jailscale.hub;

import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Args;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.nio.file.Path;

/** Entry point of the {@code jailhub} binary: {@code serve}, or an admin command over IPC. */
public final class Main {

    private static final String USAGE = """
        jailhub serve --base-url https://hub.example.com
                      [--listen 0.0.0.0:443] [--state DIR] [--registration invite|open]
                      [--invite-policy members|admins] [--knock on|off] [--dns-suffix HOST] [--debug]
                      certificate: built-in ACME (dns-01 via the hub's own DNS on --dns-listen 0.0.0.0:53)
                        [--acme-email you@example.com] [--acme-staging | --acme-directory URL] [--no-selfcheck]
                      or your own files: --tls-cert FILE --tls-key FILE
                      [--port-range 10000-10999 | none]  ports for raw tcp/udp links (DESIGN.md §9.5)
                      [--http-listen 0.0.0.0:80 | none]  acme-challenge relay for user domains (DESIGN.md §9.4)
                      [--proxy-protocol [--trusted-proxy CIDR,...]]  behind nginx stream / HAProxy (DESIGN.md §9.6)
                      [--takeover]  replace a running jailhub without dropping nodes (DESIGN.md §7.7)
        jailhub status
        jailhub node list | approve <node> [--user NAME] | deny <node> | remove <node> | rename <node> --user NAME
        jailhub user list | remove <user>
        jailhub domain list | release <domain>
        jailhub invite create [--user NAME] [--uses N] [--ttl 24h] [--admin] | list | revoke <id>
        jailhub authkey create (--owner USER | --tag TAG) [--uses N] [--ttl 7d] | list | revoke <id>
        jailhub admin add <user> | remove <user> | login-link
        jailhub key rotate [--grace 30d]
        jailhub setting invitePolicy members|admins | registration invite|open | knock on|off
        Admin commands talk to the running server through <state>/jailhub.sock (--state or $JAILHUB_STATE).
        """;

    private Main() {}

    public static void main(String[] argv) {
        Args a;
        try {
            a = Args.parse(argv, "debug", "admin", "help", "acme-staging", "no-selfcheck", "takeover");
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
        try {
            if (cmd.equals("serve")) {
                serve(a);
            } else if (cmd.equals("version")) {
                System.out.println("jailhub " + Hub.version());
            } else {
                admin(a);
            }
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.err.print(USAGE);
            System.exit(2);
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void serve(Args a) throws Exception {
        HubConfig cfg = HubConfig.fromArgs(a);
        Hub hub = new Hub(cfg, a.flag("takeover"));
        hub.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                hub.close();
            } catch (IOException ignored) {
                // exiting
            }
        }, "shutdown"));
        Thread.currentThread().join();
    }

    private static void admin(Args a) throws IOException {
        Path sock = HubConfig.stateDir(a.get("state")).resolve("jailhub.sock");
        if (!Ipc.isAlive(sock)) {
            throw new IOException("jailhub serve is not running (no socket at " + sock + ")");
        }
        JsonObject req = AdminIpc.requestFor(a);
        AdminIpc.printReply(Ipc.call(sock, req));
    }
}
