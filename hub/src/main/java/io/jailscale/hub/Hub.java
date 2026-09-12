package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import io.jailscale.proto.net.Cidr;
import io.jailscale.proto.net.ProxyProtocol;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;

/** The jailhub process: keys, store, TLS listener, node sessions, admin IPC (ARCHITECTURE.md §2). */
public final class Hub implements AutoCloseable {

    private static final Log LOG = Log.get("hub");
    static final int KEEPALIVE_SECONDS = 25;

    private final HubConfig config;
    private final Store store;
    private final HubKeys keys;
    /** When a node from a public address last arrived by this hub's own name; 0 until one has. */
    private volatile long reachedFromOutsideAt;
    private final Registry registry = new Registry(this);
    static final long DRAIN_TIMEOUT_MS = 60_000;
    private volatile boolean handingOff;
    private final Registrar registrar;
    private final Bans bans;
    private final Invites invites;
    private final HttpFront front;
    private final HubTls tls;
    private final Links links;
    private final RawPorts rawPorts;
    private final Challenges challenges;
    private HttpChallengeFront http;
    private final SniRouter router;
    private final AdminWeb adminWeb;
    private io.jailscale.hub.dns.DnsResponder dns;
    private AcmeManager acme;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private ServerSocket listener;
    private Ipc.Server ipc;
    private ScheduledExecutorService timer;
    private volatile boolean running;

    public Hub(HubConfig config) throws IOException, GeneralSecurityException {
        this(config, false);
    }

    /**
     * With {@code takeover}, a running server in the same state directory is asked to hand off
     * first (ARCHITECTURE.md §13); without it, a held lock is an error.
     */
    public Hub(HubConfig config, boolean takeover) throws IOException, GeneralSecurityException {
        this.config = config;
        java.nio.file.Files.createDirectories(config.stateDir());
        this.lockChannel = FileChannel.open(config.stateDir().resolve("jailhub.lock"),
            StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock l = tryLock(lockChannel);
        if (l == null && takeover && Ipc.isAlive(config.socketPath())) {
            LOG.info("asking the running jailhub to hand off");
            io.jailscale.proto.json.JsonObject r = Ipc.call(config.socketPath(), io.jailscale.proto.json.JsonObject.builder().put("cmd", "handoff").build());
            if (!r.optBool("ok", false)) {
                lockChannel.close();
                throw new IOException("hand-off refused: " + r.optString("error", "?"));
            }
            long deadline = System.currentTimeMillis() + 10_000;
            while (l == null && System.currentTimeMillis() < deadline) {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    break;
                }
                l = tryLock(lockChannel);
            }
        }
        this.lock = l;
        if (lock == null) {
            lockChannel.close();
            throw new IOException("another jailhub serve holds " + config.stateDir() + (takeover ? "" : " (use --takeover)"));
        }
        this.store = new Store(config.stateDir());
        this.keys = new HubKeys(config.stateDir());
        this.bans = new Bans(store);
        this.registrar = new Registrar(config, store, bans);
        this.invites = new Invites(config, store);
        this.front = new HttpFront(this);
        this.tls = new HubTls(config.hostname());
        this.rawPorts = new RawPorts(this);
        this.challenges = new Challenges();
        try {
            this.links = new Links(config, store, rawPorts, new DomainVerifier(config.userDomainCa()), registry);
        } catch (GeneralSecurityException e) {
            throw new IOException("trust store: " + e.getMessage(), e);
        }
        this.router = new SniRouter(this);
        this.adminWeb = new AdminWeb(this);
        // Flags seed the runtime settings once; afterwards /admin and `jailhub setting` own them.
        if (!store.hasSetting(Store.SETTING_INVITE_POLICY)) {
            store.setSetting(Store.SETTING_INVITE_POLICY, config.invitePolicy());
        }
        if (!store.hasSetting(Store.SETTING_REGISTRATION)) {
            store.setSetting(Store.SETTING_REGISTRATION, config.registrationOpen() ? "open" : "invite");
        }
        if (!store.hasSetting(Store.SETTING_KNOCK)) {
            store.setSetting(Store.SETTING_KNOCK, config.knock() ? "on" : "off");
        }
    }

    /** Like tryLock, but a lock held by this same JVM (tests) also reads as "held". */
    private static FileLock tryLock(FileChannel ch) throws IOException {
        try {
            return ch.tryLock();
        } catch (java.nio.channels.OverlappingFileLockException e) {
            return null;
        }
    }

    public void start() throws IOException, GeneralSecurityException {
        promoteRotationIfDue();
        if (config.acme()) {
            dns = new io.jailscale.hub.dns.DnsResponder(config.hostname());
            dns.start(config.dnsListenHost(), config.dnsListenPort());
            acme = new AcmeManager(config, tls, dns, () -> {
                for (NodeGroup g : registry.all()) {
                    NodeSession p = g.primary();
                    if (p != null) {
                        p.certChanged();
                    }
                }
            });
            try {
                acme.start(); // blocks until a certificate is installed
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted while obtaining a certificate");
            }
        } else {
            tls.load(config.tlsCert(), config.tlsKey());
        }
        listener = new ServerSocket();
        listener.setReuseAddress(true);
        listener.bind(new InetSocketAddress(config.listenHost(), config.listenPort()), 1024); // capped by somaxconn
        running = true;
        Thread.ofPlatform().name("accept").daemon(false).start(this::acceptLoop);
        if (config.acme() && config.selfCheck()) {
            // After the listener is up, or the one connection that proves the records reach this
            // process would arrive with nothing to answer it. Off the startup path: the answer is a
            // diagnosis for the operator, never a reason to refuse to serve.
            Thread.ofVirtual().name("address-check").start(() -> Reachability.report(config, keys));
        }
        if (config.hasHttp()) {
            try {
                http = new HttpChallengeFront(this, config.httpListenHost(), config.httpListenPort());
            } catch (IOException e) {
                LOG.warn("port {} unavailable ({}); user domains are disabled until it is", config.httpListenPort(), e.getMessage());
            }
        }

        ipc = Ipc.serve(config.socketPath(), new AdminIpc(this));
        timer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "timer");
            t.setDaemon(true);
            return t;
        });
        timer.scheduleAtFixedRate(this::tick, KEEPALIVE_SECONDS, KEEPALIVE_SECONDS, TimeUnit.SECONDS);

        LOG.info("jailhub {} listening on {}:{} for {} (hub key {})", version(), config.listenHost(), port(),
            config.hostname(), keys.publicText());
        if (!store.hasAnyAdmin()) {
            Invites.Created c = invites.create(null, 1, 24 * 3600, "bootstrap", true);
            LOG.info("no admin yet. First invite (24h, 1 use); whoever joins with it becomes admin:");
            System.out.println();
            System.out.println("  jailscale up --invite " + c.url());
            System.out.println("  (or: jailscale up --hub " + config.hostname() + " --code " + c.code() + ", valid 10 minutes)");
            System.out.println();
        }
    }

    /** Actual port, useful when configured with 0. */
    public int port() {
        return listener.getLocalPort();
    }

    private void acceptLoop() {
        while (running) {
            Socket s;
            try {
                s = listener.accept();
            } catch (IOException e) {
                if (running) {
                    LOG.warn("accept failed: {}", e.getMessage());
                }
                continue;
            }
            Thread.ofVirtual().name("conn-" + s.getInetAddress().getHostAddress()).start(() -> router.serve(s));
        }
    }

    private void tick() {
        try {
            promoteRotationIfDue();
        } catch (RuntimeException | IOException e) {
            LOG.warn("timer", e);
        }
    }

    /** Starts (or extends) a key rotation with the given grace period; returns activation time (ms). */
    synchronized long rotateKey(long graceSeconds) throws IOException {
        String next = keys.beginRotation();
        long activatesAt = System.currentTimeMillis() + graceSeconds * 1000;
        store.setHubKeyRotation(next, activatesAt);
        Message.HubKeyRotation m = new Message.HubKeyRotation(next, activatesAt / 1000);
        for (NodeGroup g : registry.all()) {
            try {
                g.send(m);
            } catch (IOException e) {
                g.goodbyeAll(Message.Goodbye.SHUTDOWN);
            }
        }
        LOG.info("hub key rotation announced to {} nodes, activates at {}", registry.size(), activatesAt);
        return activatesAt;
    }

    synchronized void promoteRotationIfDue() throws IOException {
        long at = store.hubKeyActivatesAt();
        if (store.nextHubKey() != null && at > 0 && System.currentTimeMillis() >= at) {
            keys.completeRotation();
            store.clearHubKeyRotation();
        }
    }

    HubConfig config() {
        return config;
    }

    Store store() {
        return store;
    }

    /**
     * A node says in its {@code Hello} which name it resolved to get here (§7.2). A handshake that
     * completed against the pinned hub key proves that <i>the node's resolver</i> sends that name
     * here -- which is only evidence about the public address record when the node is somewhere
     * the public records are all it could have used. A node on this host or its LAN may have got
     * the name from {@code /etc/hosts} or a split-horizon resolver, so only arrivals from a public
     * address count, and even then it is one node's view: the part of the address check this host
     * cannot answer about itself from behind a translated address, not more. Only this hub's own
     * name is considered: the value comes off the wire, so it is compared against what we already
     * know rather than stored and shown back.
     */
    void reachedBy(String name, String remoteIp) {
        if (name == null || !name.equalsIgnoreCase(config.hostname()) || !isPublicAddress(remoteIp)) {
            return;
        }
        boolean first = reachedFromOutsideAt == 0;
        reachedFromOutsideAt = System.currentTimeMillis();
        if (first) {
            LOG.info("a node at {} resolved {} and arrived here: from where it stands, the address record points"
                + " at this hub", remoteIp, config.hostname());
        }
    }

    /** When a node from a public address last arrived by this hub's own name; 0 until one has. */
    long reachedFromOutsideAt() {
        return reachedFromOutsideAt;
    }

    /**
     * Whether {@code ip} is one only the public internet could have handed us: not loopback, not a
     * private or link-local range, not the unspecified address. A resolver on such a host cannot
     * have been told about the name by this machine's own configuration.
     */
    static boolean isPublicAddress(String ip) {
        if (ip == null) {
            return false;
        }
        InetAddress a;
        try {
            a = InetAddress.getByName(ip);
        } catch (java.net.UnknownHostException e) {
            return false;
        }
        if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress() || a.isSiteLocalAddress()
            || a.isMulticastAddress()) {
            return false;
        }
        byte[] b = a.getAddress();
        if (b.length == 16 && (b[0] & 0xfe) == 0xfc) {
            return false; // fc00::/7, unique local: isSiteLocalAddress only knows the deprecated fec0::/10
        }
        if (b.length == 4 && (b[0] & 0xff) == 100 && (b[1] & 0xc0) == 0x40) {
            return false; // 100.64.0.0/10, carrier-grade NAT: a LAN behind an ISP, not the internet
        }
        return true;
    }

    HubKeys keys() {
        return keys;
    }

    Registry registry() {
        return registry;
    }

    Bans bans() {
        return bans;
    }

    Registrar registrar() {
        return registrar;
    }

    Invites invites() {
        return invites;
    }

    HubTls tls() {
        return tls;
    }

    Links links() {
        return links;
    }

    HttpFront front() {
        return front;
    }

    AdminWeb adminWeb() {
        return adminWeb;
    }

    Challenges challenges() {
        return challenges;
    }

    private volatile List<Cidr> trustedProxies;

    /**
     * ARCHITECTURE.md §8.5: with --proxy-protocol, connections from a trusted proxy start with a PROXY
     * header naming the real visitor. Returns it, or null when the feature is off. Untrusted
     * peers are refused outright (they must not be able to forge addresses).
     */
    ProxyProtocol.Header readProxyHeader(Socket s) throws IOException {
        if (!config.proxyProtocol()) {
            return null;
        }
        List<Cidr> trusted = trustedProxies;
        if (trusted == null) {
            trusted = new ArrayList<>();
            for (String c : config.trustedProxies()) {
                trusted.add(Cidr.parse(c));
            }
            trustedProxies = trusted;
        }
        InetAddress peer = s.getInetAddress();
        if (!peer.isLoopbackAddress() && !Cidr.anyContains(trusted, peer)) {
            throw new IOException("PROXY protocol from untrusted peer " + peer.getHostAddress());
        }
        return ProxyProtocol.read(s.getInputStream());
    }

    /** The plain HTTP port, or -1 when port 80 is not served. */
    int httpPort() {
        return http == null ? -1 : http.port();
    }

    static String version() {
        String v = Hub.class.getPackage() == null ? null : Hub.class.getPackage().getImplementationVersion();
        return v == null ? "dev" : v;
    }

    boolean isHandingOff() {
        return handingOff;
    }

    /**
     * Hand-off to a new process (ARCHITECTURE.md §13): stop accepting, persist and release the state,
     * then ask nodes to reconnect while keeping their current streams. Returns once the new
     * process may take the lock; this process exits when drained (or after a minute).
     */
    synchronized void handoff() throws IOException {
        if (handingOff) {
            return;
        }
        handingOff = true;
        running = false;
        LOG.info("hand-off requested: releasing listener and state");
        if (listener != null) {
            listener.close();
        }
        rawPorts.close();
        if (http != null) {
            http.close();
        }
        if (acme != null) {
            acme.close();
        }
        if (dns != null) {
            dns.close();
        }
        if (timer != null) {
            timer.shutdownNow();
        }
        store.close();
        lock.release();
        lockChannel.close();
        registry.drainAll();
        Thread.ofVirtual().name("handoff-ipc").start(() -> {
            try {
                Thread.sleep(300); // let the hand-off reply go out first
                if (ipc != null) {
                    ipc.close();
                    ipc = null;
                }
            } catch (IOException | InterruptedException ignored) {
                // exiting
            }
        });
        Thread.ofVirtual().name("handoff-exit").start(() -> {
            long deadline = System.currentTimeMillis() + DRAIN_TIMEOUT_MS;
            while (registry.liveSessions() > 0 && System.currentTimeMillis() < deadline) {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    break;
                }
            }
            LOG.info("drained, exiting");
            if (exitOnDrain) {
                System.exit(0);
            }
        });
    }

    /** Whether hand-off should end the process (true for the binary, false in tests). */
    volatile boolean exitOnDrain = true;

    /** Test hook: the DNS responder's port (0 if certificates come from files). */
    public int dnsPort() {
        return dns == null ? 0 : dns.port();
    }

    @Override
    public void close() throws IOException {
        running = false;
        if (timer != null) {
            timer.shutdownNow();
        }
        if (handingOff) {
            registry.closeAll(Message.Goodbye.SHUTDOWN);
            return;
        }
        if (acme != null) {
            acme.close();
        }
        if (dns != null) {
            dns.close();
        }
        registry.closeAll(Message.Goodbye.SHUTDOWN);
        rawPorts.close();
        if (http != null) {
            http.close();
        }
        if (listener != null) {
            listener.close();
        }
        if (ipc != null) {
            ipc.close();
        }
        store.close();
        lock.release();
        lockChannel.close();
        LOG.info("stopped");
    }

    /** For tests and tooling. */
    public Path stateDir() {
        return config.stateDir();
    }
}
