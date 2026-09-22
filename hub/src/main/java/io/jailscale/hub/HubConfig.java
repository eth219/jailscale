package io.jailscale.hub;

import io.jailscale.proto.util.Args;
import java.net.URI;
import java.util.List;
import java.nio.file.Files;
import java.nio.file.Path;

/** Everything {@code jailhub serve} needs, parsed from the command line (ARCHITECTURE.md §7, §10). */
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
    String dnsSuffix,
    URI acmeDirectory,
    String acmeEmail,
    String dnsListenHost,
    int dnsListenPort,
    boolean selfCheck,     // dns-01 self-check: holds issuance until it passes (§7.2)
    boolean addressCheck,  // address check: holds nothing, only reports (§7.2)
    String advertise,  // the public address this hub answers for itself in DNS (§7.1); null = find it from the glue
    Tuning tuning) {   // the timings a test moves; see Tuning below

    /**
     * Not null. The scheduled task that reads these has no top-level catch and
     * {@code ScheduledExecutorService} cancels a repeating task on the first uncaught throw with
     * nothing logged, so a null here is a hub whose rate-limiter never prunes.
     * The canonical constructor is public and takes 18 positional arguments, which is exactly the
     * shape that gets one more by accident.
     */
    public HubConfig {
        java.util.Objects.requireNonNull(tuning, "tuning");
    }

    /**
     * The timings a test shortens and an operator does not, in one place so that adding one is not
     * a new signature (#61).
     *
     * <p>These were {@code static volatile} fields on {@link Hub} and {@link RateLimiter}, set in a
     * {@code @BeforeEach} and put back in an {@code @AfterEach}. That worked, and it worked only
     * because surefire here runs one test at a time: two tests wanting different timings at once
     * would have read each other's. It also meant a restore that was forgotten leaked into every
     * later test in the JVM, and nothing would have said so.
     *
     * <p>The alternative considered and rejected was a constructor parameter per knob, which is
     * what the node side had: two knobs there cost four {@code Daemon} signatures and four
     * {@code Visitors} ones, and a third would have cost two more. A record costs none, and it is
     * the seam an operator-facing flag would need anyway if one of these ever becomes one.
     *
     * <p>Nothing on the command line reaches these. The defaults are the only values anything has
     * measured, and a knob with no use is a surface to support.
     */
    public record Tuning(
        long rateLimitPruneMs) {    // RateLimiter: the floor between two scans of the bucket map

        public static Tuning defaults() {
            return new Tuning(RateLimiter.DEFAULT_PRUNE_MS);
        }

        public Tuning rateLimitPruneMs(long v) {
            return new Tuning(v);
        }
    }

    /** ARCHITECTURE.md §7.2: whether the address check runs at all. Off in the test constructor below. */
    public HubConfig withAddressCheck(boolean on) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, on, advertise, tuning);
    }

    /** ARCHITECTURE.md §13.3: answer this address for the hub's own name instead of finding it from the glue. */
    public HubConfig withAdvertise(String address) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, addressCheck, address, tuning);
    }

    public HubConfig withPortRange(int lo, int hi) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, addressCheck,             advertise, tuning);
    }

    public static final String POLICY_MEMBERS = "members";
    public static final String POLICY_ADMINS = "admins";
    public static final URI LETS_ENCRYPT = URI.create("https://acme-v02.api.letsencrypt.org/directory");
    public static final URI LETS_ENCRYPT_STAGING = URI.create("https://acme-staging-v02.api.letsencrypt.org/directory");

    /** True when the hub obtains its own certificate (no --tls-cert). */
    public boolean acme() {
        return tlsCert == null;
    }

    /** Test/simple constructor: files, no ACME. */
    public static HubConfig withCert(URI baseUrl, Path stateDir, String listenHost, int listenPort, Path cert, Path key,
        boolean registrationOpen, String invitePolicy, boolean knock, String dnsSuffix) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, cert, key, registrationOpen, invitePolicy, knock,
            dnsSuffix, null, null, "127.0.0.1", 0, false, false, null, Tuning.defaults());
    }

    /** The same configuration with different timings; how a test reaches {@link Tuning}. */
    public HubConfig withTuning(Tuning t) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, addressCheck, advertise, t);
    }

    public String hostname() {
        return baseUrl.getHost();
    }

    /**
     * The host half of a {@code host:port} flag, refusing an IPv6 address that is not bracketed.
     *
     * <p>An IPv6 literal has colons of its own, so the last colon is the port separator only when
     * the address is in brackets. Without this, {@code --listen ::443} parses as the host {@code :}
     * and port 443, binds nothing, and fails later with {@code SocketException: Unresolved
     * address} -- a sentence that says nothing about brackets, which is the whole of what is wrong
     * (#63). Four flags parse this way and all four had it.
     */
    private static String hostOf(String flag, String value, int colon) {
        int close = value.indexOf(']');
        if (value.startsWith("[")) {
            // The colon that matters is the one after the bracket. `--listen [::]` on its own has
            // colons and no port, and the last of them is inside the address: without this it
            // would be refused for the one thing it got right.
            if (close < 0 || colon < close) {
                throw new IllegalArgumentException(flag + " must be [address]:port for an IPv6 address");
            }
            return value.substring(0, colon);
        }
        String host = value.substring(0, colon);
        if (host.indexOf(':') >= 0) {
            throw new IllegalArgumentException(flag + " needs an IPv6 address in brackets, as in "
                + flag + " [::]:443 for every address or " + flag + " [2001:db8::1]:443 for one");
        }
        return host;
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
        String listenHost = hostOf("--listen", listen, colon);
        String policy = a.get("invite-policy", POLICY_MEMBERS);
        if (!policy.equals(POLICY_MEMBERS) && !policy.equals(POLICY_ADMINS)) {
            throw new IllegalArgumentException("--invite-policy must be members or admins");
        }
        // Checked the same way --invite-policy is, and for the same reason: the readers ask
        // `"open".equals(...)` and `"off".equals(...)`, so a typo here does not fail, it quietly
        // selects the other setting -- `--registration opne` would leave registration closed and
        // `--knock of` would leave knocking on, both while the operator believes otherwise.
        String registration = a.get("registration", "invite");
        if (!registration.equals("invite") && !registration.equals("open")) {
            throw new IllegalArgumentException("--registration must be invite or open");
        }
        String knock = a.get("knock", "on");
        if (!knock.equals("on") && !knock.equals("off")) {
            throw new IllegalArgumentException("--knock must be on or off");
        }
        String cert = a.get("tls-cert");
        String key = a.get("tls-key");
        if ((cert == null) != (key == null)) {
            throw new IllegalArgumentException("--tls-cert and --tls-key go together");
        }
        URI acme = a.has("acme-directory") ? URI.create(a.get("acme-directory"))
            : a.flag("acme-staging") ? LETS_ENCRYPT_STAGING : LETS_ENCRYPT;
        String dnsListen = a.get("dns-listen", "0.0.0.0:53");
        int dc = dnsListen.lastIndexOf(':');
        if (dc < 0) {
            throw new IllegalArgumentException("--dns-listen must be host:port");
        }
        return new HubConfig(
            base,
            stateDir(a.get("state")),
            listenHost,
            Integer.parseInt(listen.substring(colon + 1)),
            cert == null ? null : Path.of(cert),
            key == null ? null : Path.of(key),
            registration.equals("open"),
            policy,
            !knock.equals("off"),
            a.get("dns-suffix", base.getHost()),
            acme,
            a.get("acme-email"),
            hostOf("--dns-listen", dnsListen, dc),
            Integer.parseInt(dnsListen.substring(dc + 1)),
            !a.flag("no-selfcheck"),
            !a.flag("no-address-check"),
            a.get("advertise"),
            Tuning.defaults());
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
