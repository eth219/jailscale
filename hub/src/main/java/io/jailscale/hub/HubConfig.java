package io.jailscale.hub;

import io.jailscale.proto.net.Cidr;
import io.jailscale.proto.util.Args;
import java.net.InetAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
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
    String dnsSuffix,
    URI acmeDirectory,
    String acmeEmail,
    String dnsListenHost,
    int dnsListenPort,
    boolean selfCheck,
    int portRangeLo,
    int portRangeHi,
    String httpListenHost,
    int httpListenPort,
    Path userDomainCa,
    boolean proxyProtocol,
    List<String> trustedProxies) {

    /** DESIGN.md §9.6: behind nginx stream / HAProxy sending PROXY headers. */
    public HubConfig withProxyProtocol(boolean on, List<String> trusted) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, portRangeLo, portRangeHi, httpListenHost,
            httpListenPort, userDomainCa, on, trusted);
    }

    /** True when port 80 is served, the precondition for user domains (DESIGN.md §9.4). */
    public boolean hasHttp() {
        return httpListenHost != null && httpListenPort >= 0;
    }

    public HubConfig withHttp(String host, int port) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, portRangeLo, portRangeHi, host, port, userDomainCa,
            proxyProtocol, trustedProxies);
    }

    /** Tests and private CAs: trust this PEM instead of the platform roots when verifying user-domain certificates. */
    public HubConfig withUserDomainCa(Path caPem) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, portRangeLo, portRangeHi, httpListenHost,
            httpListenPort, caPem, proxyProtocol, trustedProxies);
    }

    public static final int DEFAULT_PORT_LO = 10000;
    public static final int DEFAULT_PORT_HI = 10999;

    /** True when raw TCP/UDP publishing is enabled (DESIGN.md §9.5). */
    public boolean hasPortRange() {
        return portRangeLo > 0 && portRangeHi >= portRangeLo;
    }

    public HubConfig withPortRange(int lo, int hi) {
        return new HubConfig(baseUrl, stateDir, listenHost, listenPort, tlsCert, tlsKey, registrationOpen, invitePolicy, knock,
            dnsSuffix, acmeDirectory, acmeEmail, dnsListenHost, dnsListenPort, selfCheck, lo, hi, httpListenHost, httpListenPort, userDomainCa,
            proxyProtocol, trustedProxies);
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
            dnsSuffix, null, null, "127.0.0.1", 0, false, 0, 0, null, -1, null, false, List.of());
    }

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
            httpHost = httpListen.substring(0, hc);
            httpPort = Integer.parseInt(httpListen.substring(hc + 1));
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
                loopback = InetAddress.getByName(listen.substring(0, colon)).isLoopbackAddress();
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
        return new HubConfig(
            base,
            stateDir(a.get("state")),
            listen.substring(0, colon),
            Integer.parseInt(listen.substring(colon + 1)),
            cert == null ? null : Path.of(cert),
            key == null ? null : Path.of(key),
            "open".equals(a.get("registration", "invite")),
            policy,
            !"off".equals(a.get("knock", "on")),
            a.get("dns-suffix", base.getHost()),
            acme,
            a.get("acme-email"),
            dnsListen.substring(0, dc),
            Integer.parseInt(dnsListen.substring(dc + 1)),
            !a.flag("no-selfcheck"),
            lo,
            hi,
            httpHost,
            httpPort,
            null,
            proxyProtocol,
            List.copyOf(trusted));
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
