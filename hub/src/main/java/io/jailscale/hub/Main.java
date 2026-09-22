package io.jailscale.hub;

import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Args;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.nio.file.Path;

/** Entry point of the {@code jailhub} binary: {@code serve}, or an admin command over IPC. */
public final class Main {

    /**
     * What the binary can be told to do. Package-private so {@link io.jailscale.hub.AdminCommandTest}
     * can hold it against the commands that are actually routed -- the three {@code name} ones were
     * implemented, documented in ARCHITECTURE.md 11.4 and missing from here, which is how an admin
     * looking for the way to take a claimed name back found nothing.
     */
    static final String USAGE = """
        jailhub serve --base-url https://hub.example.com
                      [--listen 0.0.0.0:443] [--state DIR] [--registration invite|open]
                      [--invite-policy members|admins] [--knock on|off] [--dns-suffix HOST] [--debug]
                      certificate: built-in ACME (dns-01 via the hub's own DNS on --dns-listen 0.0.0.0:53)
                        [--acme-email you@example.com] [--acme-staging | --acme-directory URL]
                        [--no-selfcheck]  do not hold issuance on the dns-01 check
                        [--no-address-check]  do not report whether the name points here (ARCHITECTURE.md §7.2)
                      or your own files: --tls-cert FILE --tls-key FILE
                      [--takeover]  replace a running jailhub without dropping nodes (ARCHITECTURE.md §13)
                      [--peer https://primary.example.com [--peer-ca FILE] [--peer-addr IP]]  run as that hub's standby (ARCHITECTURE.md §13.1)
                      [--advertise IP]  answer this address for the hub's name; default: found from the ns1/ns2 glue (ARCHITECTURE.md §13.3)
        jailhub status
        jailhub promote     make this standby the primary (ARCHITECTURE.md §13.1)
        jailhub address check     ask now whether this hub's name points here (ARCHITECTURE.md §7.2)
        jailhub availability reset     start the uptime record over from now (ARCHITECTURE.md §13.2)
        jailhub node list | approve <node> [--user NAME] | deny <node> | remove <node> | rename <node> --user NAME
        jailhub user list | remove <user>
        jailhub name list | reassign <name> --user NAME | release <name>
        jailhub ban list | add <ip|cidr> [--reason R] | remove <ip|cidr>
        jailhub invite create [--user NAME] [--uses N] [--ttl 24h] [--admin] | list | revoke <id>
        jailhub admin add <user> | remove <user>
        jailhub key rotate [--grace 30d]
        jailhub setting invitePolicy members|admins | registration invite|open | knock on|off | autoPromote on|off
        jailhub setting operator "NAME" | contact https://...|mailto:... | terms https://...
                                            who runs this hub, shown on its page; empty clears (#99)
        Admin commands talk to the running server through <state>/jailhub.sock (--state or $JAILHUB_STATE).
        """;

    private Main() {}

    /**
     * Options that take no value. Every option this binary reads with {@code flag()} has to be
     * here: {@link Args#parse} reads the next word as the value of anything else, so
     * `--no-address-check serve` would lose the subcommand and leave the check on, and an option
     * with no next word at all is refused as needing a value. One of these was missing once and
     * survived on the old parser's guess, which is why the list is written down rather than
     * inferred.
     */
    static final String[] FLAGS = {"debug", "admin", "help", "acme-staging", "no-selfcheck", "no-address-check",
        "takeover"};

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
            // As in the node's Main, and it was wrong here in the same way: asking for help
            // succeeds, and only a bare invocation with nothing to do is an error.
            System.exit(a.flag("help") ? 0 : 2);
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
            } catch (IOException _) {
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
