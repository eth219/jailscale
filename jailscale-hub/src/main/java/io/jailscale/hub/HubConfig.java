package io.jailscale.hub;

import io.jailscale.proto.util.Args;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;

/** Everything {@code jailhub serve} needs, parsed from the command line (DESIGN.md §6.3, §11.4). */
public record HubConfig(
    URI baseUrl,
    Path stateDir,
    String listenHost,
    int listenPort,
    Path tlsCert,
    Path tlsKey,
    boolean registrationOpen,
    String invitePolicy,
    boolean knock,
    String dnsSuffix) {

    public static final String POLICY_MEMBERS = "members";
    public static final String POLICY_ADMINS = "admins";

    public String hostname() {
        return baseUrl.getHost();
    }

    public static HubConfig fromArgs(Args a) {
        URI base = URI.create(a.require("base-url"));
        if (base.getHost() == null || !"https".equals(base.getScheme())) {
            throw new IllegalArgumentException("--base-url must be https://<host>");
        }
        String listen = a.get("listen", "0.0.0.0:443");
        int colon = listen.lastIndexOf(':');
        if (colon < 0) {
            throw new IllegalArgumentException("--listen must be host:port");
        }
        String policy = a.get("invite-policy", POLICY_MEMBERS);
        if (!policy.equals(POLICY_MEMBERS) && !policy.equals(POLICY_ADMINS)) {
            throw new IllegalArgumentException("--invite-policy must be members or admins");
        }
        String cert = a.get("tls-cert");
        String key = a.get("tls-key");
        if (cert == null || key == null) {
            // Built-in ACME arrives in M2 (DESIGN.md §6.3); until then a certificate is required.
            throw new IllegalArgumentException("--tls-cert and --tls-key are required (built-in ACME is not implemented yet)");
        }
        return new HubConfig(
            base,
            stateDir(a.get("state")),
            listen.substring(0, colon),
            Integer.parseInt(listen.substring(colon + 1)),
            Path.of(cert),
            Path.of(key),
            "open".equals(a.get("registration", "invite")),
            policy,
            !"off".equals(a.get("knock", "on")),
            a.get("dns-suffix", base.getHost()));
    }

    /** {@code --state}, else {@code $JAILHUB_STATE}, else /var/lib/jailhub if writable, else ~/.local/share/jailhub. */
    public static Path stateDir(String explicit) {
        if (explicit != null) {
            return Path.of(explicit);
        }
        String env = System.getenv("JAILHUB_STATE");
        if (env != null && !env.isBlank()) {
            return Path.of(env);
        }
        Path system = Path.of("/var/lib/jailhub");
        if (Files.isDirectory(system) && Files.isWritable(system)) {
            return system;
        }
        return Path.of(System.getProperty("user.home"), ".local", "share", "jailhub");
    }

    public Path socketPath() {
        return stateDir.resolve("jailhub.sock");
    }
}
