package io.jailscale.hub;

import io.jailscale.proto.net.Cidr;
import io.jailscale.proto.util.Args;
import java.net.InetAddress;
import java.net.URI;
import java.util.ArrayList;
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
    int portRangeLo,
    int portRangeHi,
    String httpListenHost,
    int httpListenPort,
    String metricsListenHost,  // /metrics on a listener of its own, loopback by default (§6.3)
    int metricsListenPort,
    Path userDomainCa,
    boolean proxyProtocol,
    List<String> trustedProxies,
    URI peer,       // the primary this hub follows as a standby, or null when it is the primary (§13.1)
    Path peerCa,    // tests and private CAs: trust this PEM when dialling the primary
    String peerAddr,    // dial this address instead of resolving the primary's name (tests, split horizon)
    String advertise,  // the public address this hub answers for itself in DNS (§13.3); null = find it from the glue
    Tuning tuning) {   // the timings a test moves; see Tuning below

    /**
     * Not null. The scheduled task that reads these has no top-level catch and
     * {@code ScheduledExecutorService} cancels a repeating task on the first uncaught throw with
     * nothing logged, so a null here is a hub that starts, serves, and silently never promotes.
     * The canonical constructor is public and takes 29 positional arguments, four of them trailing
     * nulls, which is exactly the shape that gets one more by accident.
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
        long promoteAfterMs,        // §13.5: how long the primary must be unreachable before a standby considers promoting
        long witnessWindowMs,       // §13.5: how long to wait for a witness to answer
        long autoPromoteIntervalMs, // §13.5: the floor between two automatic promotions
        long rateLimitPruneMs) {    // RateLimiter: the floor between two scans of the bucket map

        public static Tuning defaults() {
            return new Tuning(30_000, 10_000, 10 * 60_000, RateLimiter.DEFAULT_PRUNE_MS);
        }

        public Tuning promoteAfterMs(long v) {
            return new Tuning(v, witnessWindowMs, autoPromoteIntervalMs, rateLimitPruneMs);
        }

        public Tuning witnessWindowMs(long v) {
            return new Tuning(promoteAfterMs, v, autoPromoteIntervalMs, rateLimitPruneMs);
        }

        public Tuning autoPromoteIntervalMs(long v) {
            return new Tuning(promoteAfterMs, witnessWindowMs, v, rateLimitPruneMs);
        }

        public Tuning rateLimitPruneMs(long v) {
            return new Tuning(promoteAfterMs, witnessWindowMs, autoPromoteIntervalMs, v);
        }
    }

    /** ARCHITECTURE.md §8.5: behind nginx stream / HAProxy sending PROXY headers. */
    public HubConfig withProxyProtocol(boolean on, List<String> trusted) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, addressCheck, portRangeLo, portRangeHi, httpListenHost,
            httpListenPort, metricsListenHost, metricsListenPort, userDomainCa, on, trusted, peer, peerCa, peerAddr, advertise, tuning);
    }

    /** True when port 80 is served, the precondition for user domains (ARCHITECTURE.md §8.3). */
    public boolean hasHttp() {
        return httpListenHost != null && httpListenPort >= 0;
    }

    public HubConfig withHttp(String host, int port) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, addressCheck, portRangeLo, portRangeHi, host, port, metricsListenHost, metricsListenPort, userDomainCa,
            proxyProtocol, trustedProxies, peer, peerCa, peerAddr, advertise, tuning);
    }

    /** True when {@code /metrics} is served at all (ARCHITECTURE.md §6.3). */
    public boolean hasMetrics() {
        return metricsListenHost != null && metricsListenPort >= 0;
    }

    public HubConfig withMetrics(String host, int port) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, addressCheck, portRangeLo, portRangeHi,
            httpListenHost, httpListenPort, host, port, userDomainCa, proxyProtocol, trustedProxies, peer, peerCa, peerAddr, advertise, tuning);
    }

    /** Tests and private CAs: trust this PEM instead of the platform roots when verifying user-domain certificates. */
    public HubConfig withUserDomainCa(Path caPem) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, addressCheck, portRangeLo, portRangeHi, httpListenHost,
            httpListenPort, metricsListenHost, metricsListenPort, caPem, proxyProtocol, trustedProxies, peer, peerCa, peerAddr, advertise, tuning);
    }

    /** ARCHITECTURE.md §13.1: follow {@code primary} as a standby, trusting {@code ca} for its TLS (null: platform roots). */
    public HubConfig withPeer(URI primary, Path ca, String addr) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, addressCheck, portRangeLo, portRangeHi, httpListenHost,
            httpListenPort, metricsListenHost, metricsListenPort, userDomainCa, proxyProtocol, trustedProxies, primary, ca, addr, advertise, tuning);
    }

    /** ARCHITECTURE.md §7.2: whether the address check runs at all. Off in the test constructor below. */
    public HubConfig withAddressCheck(boolean on) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, on, portRangeLo, portRangeHi, httpListenHost,
            httpListenPort, metricsListenHost, metricsListenPort, userDomainCa, proxyProtocol, trustedProxies, peer, peerCa, peerAddr, advertise, tuning);
    }

    /** ARCHITECTURE.md §13.3: answer this address for the hub's own name instead of finding it from the glue. */
    public HubConfig withAdvertise(String address) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, addressCheck, portRangeLo, portRangeHi, httpListenHost,
            httpListenPort, metricsListenHost, metricsListenPort, userDomainCa, proxyProtocol, trustedProxies, peer, peerCa, peerAddr, address, tuning);
    }

    /** True when this hub follows a primary rather than being one (ARCHITECTURE.md §13.1). */
    public boolean standby() {
        return peer != null;
    }

    public static final int DEFAULT_PORT_LO = 10000;
    public static final int DEFAULT_PORT_HI = 10999;

    /** True when raw TCP/UDP publishing is enabled (ARCHITECTURE.md §8.4). */
    public boolean hasPortRange() {
        return portRangeLo > 0 && portRangeHi >= portRangeLo;
    }

    public HubConfig withPortRange(int lo, int hi) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, addressCheck, lo, hi, httpListenHost, httpListenPort, metricsListenHost, metricsListenPort, userDomainCa,
            proxyProtocol, trustedProxies, peer, peerCa, peerAddr, advertise, tuning);
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
            dnsSuffix, null, null, "127.0.0.1", 0, false, false, 0, 0, null, -1, null, -1, null, false, List.of(), null, null, null, null,
            Tuning.defaults());
    }

    /** The same configuration with different timings; how a test reaches {@link Tuning}. */
    public HubConfig withTuning(Tuning t) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, addressCheck, portRangeLo, portRangeHi, httpListenHost,
            httpListenPort, metricsListenHost, metricsListenPort, userDomainCa, proxyProtocol, trustedProxies, peer, peerCa, peerAddr, advertise, t);
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
        String range = a.get("port-range", DEFAULT_PORT_LO + "-" + DEFAULT_PORT_HI);
        int lo = 0;
        int hi = 0;
        if (!range.equals("none")) {
            int dash = range.indexOf('-');
            if (dash < 0) {
                throw new IllegalArgumentException("--port-range must be lo-hi or none");
            }
            lo = Integer.parseInt(range.substring(0, dash));
            hi = Integer.parseInt(range.substring(dash + 1));
            if (lo < 1024 || hi > 65535 || hi < lo) {
                throw new IllegalArgumentException("--port-range must be within 1024-65535 and lo <= hi");
            }
        }
        String httpListen = a.get("http-listen", "0.0.0.0:80");
        String httpHost = null;
        int httpPort = -1;
        if (!httpListen.equals("none")) {
            int hc = httpListen.lastIndexOf(':');
            if (hc < 0) {
                throw new IllegalArgumentException("--http-listen must be host:port or none");
            }
            httpHost = hostOf("--http-listen", httpListen, hc);
            httpPort = Integer.parseInt(httpListen.substring(hc + 1));
        }
        // Loopback by default and not on 443 at all: the hub's own name is the public internet,
        // so where this listens is the whole of the access control (§6.3). `none` turns it off.
        String metricsListen = a.get("metrics-listen", "127.0.0.1:9090");
        String metricsHost = null;
        int metricsPort = -1;
        if (!metricsListen.equals("none")) {
            int mc = metricsListen.lastIndexOf(':');
            if (mc < 0) {
                throw new IllegalArgumentException("--metrics-listen must be host:port or none");
            }
            metricsHost = hostOf("--metrics-listen", metricsListen, mc);
            metricsPort = Integer.parseInt(metricsListen.substring(mc + 1));
        }
        boolean proxyProtocol = a.flag("proxy-protocol");
        List<String> trusted = new ArrayList<>();
        if (a.has("trusted-proxy")) {
            for (String c : a.get("trusted-proxy").split(",")) {
                if (!c.isBlank()) {
                    Cidr.parse(c.trim());
                    trusted.add(c.trim());
                }
            }
        }
        if (proxyProtocol && trusted.isEmpty()) {
            boolean loopback;
            try {
                loopback = InetAddress.getByName(listenHost).isLoopbackAddress();
            } catch (java.net.UnknownHostException e) {
                loopback = false;
            }
            if (!loopback) {
                throw new IllegalArgumentException("--proxy-protocol needs --listen on loopback or --trusted-proxy <cidr>[,<cidr>]; "
                    + "otherwise anyone could forge visitor addresses");
            }
        }
        String dnsListen = a.get("dns-listen", "0.0.0.0:53");
        int dc = dnsListen.lastIndexOf(':');
        if (dc < 0) {
            throw new IllegalArgumentException("--dns-listen must be host:port");
        }
        URI peer = null;
        if (a.has("peer")) {
            peer = URI.create(a.get("peer"));
            if (peer.getHost() == null || !"https".equals(peer.getScheme())) {
                throw new IllegalArgumentException("--peer must be https://<host> (the primary's base URL)");
            }
            // The same name as --base-url is the normal case, not a mistake: a standby serves the
            // primary's name once promoted, and until then that name resolves to the primary. The
            // first standby deployed was refused here for exactly that configuration.
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
            lo,
            hi,
            httpHost,
            httpPort,
            metricsHost,
            metricsPort,
            null,
            proxyProtocol,
            List.copyOf(trusted),
            peer,
            a.has("peer-ca") ? Path.of(a.get("peer-ca")) : null,
            a.get("peer-addr"),
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
