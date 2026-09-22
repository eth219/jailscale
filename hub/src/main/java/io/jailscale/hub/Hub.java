package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.mux.FlowBudget;
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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.List;
import java.util.Map;

/** The jailhub process: keys, store, TLS listener, node sessions, admin IPC (ARCHITECTURE.md §2). */
public final class Hub implements AutoCloseable {

    private static final Log LOG = Log.get("hub");
    static final int KEEPALIVE_SECONDS = 25;

    private final HubConfig config;
    private final Store store;
    private final HubKeys keys;
    /** When a node from a public address last arrived by this hub's own name; 0 until one has. */
    private volatile long reachedFromOutsideAt;
    /** The address of that node, so the verdict can say who answered the question from outside. */
    private volatile String reachedFromOutsideIp;
    /** What the address check concluded, folded with the outside view (§7.2); null until it has run. */
    private volatile Reachability.Status addressStatus;
    private volatile Thread addressCheckThread;
    /** One run of the address check at a time; the hourly pass and the command both take it. */
    private final Object addressCheckLock = new Object();
    /** Whether the glue lookup has completed once, which is when this hub knows its place in a delegation. */
    private volatile boolean glueLookedUp;
    /**
     * What one run of the address check answers. Replaceable so a test can drive the verdict, the
     * clock and every surface that carries them without dialling a public resolver from a build.
     */
    volatile java.util.function.Supplier<Reachability.Result> addressProbe;
    private final Registry registry = new Registry(this);
    /**
     * One receive budget for every node session at once (§5.3). Shared and not per session: the
     * heap it protects is one pool, so a per-session limit would multiply by however many nodes
     * happen to be connected, which is the arithmetic that made a global bound necessary.
     */
    private final FlowBudget flowBudget = FlowBudget.ofHeap();
    static final long DRAIN_TIMEOUT_MS = 60_000;
    private final Registrar registrar;
    private final Bans bans;
    private final Invites invites;
    private final HttpFront front;
    private final HubTls tls;
    private final Links links;
    private final SniRouter router;
    private io.jailscale.hub.dns.DnsResponder dns;
    private AcmeManager acme;
    /** The public address this hub answers for itself (§7.1); null until known. */
    private volatile String advertised;
    /** See {@link #listenOn}. */
    private ServerSocket preBound;
    /** The name servers the parent delegates to, label to address; empty until looked up or when not delegated. */
    private volatile Map<String, String> nameServers = Map.of();
    /** Whether port 53 could be bound: the DNS answers exist only when it could. */
    private volatile boolean dnsUp;
    private volatile boolean stopped;
    private volatile Thread advertiseThread;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private ServerSocket listener;
    private Ipc.Server ipc;
    private ScheduledExecutorService timer;
    private volatile boolean running;

    public Hub(HubConfig config) throws IOException, GeneralSecurityException {
        Resources.markStarted(System.currentTimeMillis());
        this.config = config;
        java.nio.file.Files.createDirectories(config.stateDir());
        this.lockChannel = FileChannel.open(config.stateDir().resolve("jailhub.lock"),
            StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock l = tryLock(lockChannel);
        this.lock = l;
        if (lock == null) {
            lockChannel.close();
            throw new IOException("another jailhub serve holds " + config.stateDir());
        }
        this.store = new Store(config.stateDir());
        this.keys = new HubKeys(config.stateDir());
        this.bans = new Bans(store);
        this.registrar = new Registrar(config, store, bans);
        this.invites = new Invites(config, store);
        this.front = new HttpFront(this);
        this.tls = new HubTls(config.hostname());
        this.links = new Links(config, store, registry);
        this.router = new SniRouter(this);
        // Flags seed the runtime settings once; afterwards `jailhub setting` owns them.
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
        advertised = config.advertise();
        startDns();
        if (config.acme()) {
            startAcme(); // blocks until a certificate is installed
        } else {
            tls.load(config.tlsCert(), config.tlsKey());
        }
        if (preBound != null) {
            listener = preBound;
            preBound = null;
        } else {
            listener = new ServerSocket();
            listener.setReuseAddress(true);
            listener.bind(new InetSocketAddress(config.listenHost(), config.listenPort()), 1024); // capped by somaxconn
        }
        running = true;
        Thread.ofPlatform().name("accept").daemon(false).start(this::acceptLoop);
        startPrimaryFronts();
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

    /**
     * The hub's authoritative DNS (§7.1), whichever way the certificate comes: an operator with
     * their own files may still delegate the subdomain and let this answer it. Port 53 not
     * bindable is fatal only where issuance needs it -- a hub obtaining its own certificate --
     * and a warning everywhere else.
     */
    private void startDns() throws IOException {
        dns = new io.jailscale.hub.dns.DnsResponder(config.hostname());
        dns.setZone(new io.jailscale.hub.dns.DnsResponder.Zone() {
            // One hub, so the zone has one answer: the apex, the wildcard and every published
            // name all resolve to this host (§7.1).
            @Override public List<String> serving() {
                return advertised == null ? List.of() : List.of(advertised);
            }

            @Override public Map<String, String> nameServers() { return nameServers; }
        });
        try {
            dns.start(config.dnsListenHost(), config.dnsListenPort());
            dnsUp = true;
        } catch (IOException e) {
            if (config.acme()) {
                throw e;
            }
            LOG.warn("port {} unavailable ({}); this hub answers no DNS, so the subdomain cannot be delegated to it",
                config.dnsListenPort(), e.getMessage());
        }
        if (dnsUp && config.addressCheck()) {
            // Off the startup path, and under the same switch as the address check: both ask the
            // public resolvers about this hub's own name, and a test hub has no name they know.
            advertiseThread = Thread.ofVirtual().name("advertise").start(this::findAddresses);
        }
    }

    /**
     * Serve on {@code socket} instead of binding one at {@link #start}. For tests, and the reason
     * is a race they could not otherwise avoid (#196).
     *
     * <p>A test needs a port nothing else will take. It asked {@code TestPorts} for a number, which
     * binds a socket to find a free one and closes it again — and between that close and this hub's
     * bind the number is held by nothing. Anything in the same JVM asking the kernel for port 0 can
     * be handed it, and a running hub asks twice: the DNS pair and the plain-HTTP front. Four
     * times in two days a hub lost that race, three of them here in {@code start}.
     *
     * <p>Given a socket that is already bound, the number is never unheld and the race has nowhere
     * to happen. This hub owns the socket from here: {@link #close} closes it whether or not
     * {@code start} was ever called.
     *
     * <p>{@code SO_REUSEADDR} is not a difference: the JDK turns it on when the socket is created,
     * before the bind, so a socket from {@code TestPorts.listen} carries it already — measured, on
     * this JDK, rather than assumed. It would not matter either way. What that option buys is on
     * the <em>next</em> bind of the number, and a hub that binds for itself still sets it
     * explicitly.
     *
     * @throws IllegalArgumentException if the socket is not bound, or is bound to a different port
     *     than the configuration says — a test disagreeing with itself about its own port is the
     *     kind of thing that reads as this race and is not.
     */
    void listenOn(ServerSocket socket) {
        if (!socket.isBound()) {
            throw new IllegalArgumentException("listenOn needs a bound socket");
        }
        // The two state errors are easier to make than the port one and were the two not checked:
        // twice leaks the first socket for the life of the JVM, and after start attaches a socket
        // this hub will never serve on and closes at close(). Both were silent.
        if (preBound != null || listener != null) {
            throw new IllegalStateException("this hub already has a listener");
        }
        if (config.listenPort() != 0 && socket.getLocalPort() != config.listenPort()) {
            throw new IllegalArgumentException("the socket is on port " + socket.getLocalPort()
                + " and the configuration says " + config.listenPort());
        }
        // The address, for the same reason as the port: TestPorts binds the loopback the JVM
        // prefers, which is ::1 under -Djava.net.preferIPv6Addresses, while every caller's
        // configuration says 127.0.0.1 and every caller dials it.
        String bound = ((java.net.InetSocketAddress) socket.getLocalSocketAddress()).getAddress().getHostAddress();
        if (!bound.equals(config.listenHost())) {
            throw new IllegalArgumentException("the socket is on " + bound
                + " and the configuration says " + config.listenHost());
        }
        preBound = socket;
    }

    /** The public address this hub answers for itself, or null while unknown. */
    String advertisedAddress() {
        return advertised;
    }

    /** The name servers the parent delegates to, as last looked up. */
    Map<String, String> nameServers() {
        return nameServers;
    }

    /**
     * One pass an hour on the calling thread, until the hub stops or the thread is interrupted.
     * While {@code ready} says no it looks again in a minute instead of passing, and a pass that
     * throws is logged and tried again in a minute. Both hourly loops run on this, so the cadence,
     * the retry and the way out live in one place.
     */
    private void hourly(String what, java.util.function.BooleanSupplier ready, Runnable pass) {
        while (!stopped) {
            try {
                if (!ready.getAsBoolean()) {
                    Thread.sleep(60_000);
                    continue;
                }
                pass.run();
                Thread.sleep(3600_000);
            } catch (InterruptedException e) {
                return;
            } catch (RuntimeException e) {
                LOG.warn("{}: {}", what, e.toString());
                try {
                    Thread.sleep(60_000);
                } catch (InterruptedException ie) {
                    return;
                }
            }
        }
    }

    /** Ends the hourly loops: each returns from whatever sleep it is in. */
    private void stopLoops() {
        for (Thread t : new Thread[] {advertiseThread, addressCheckThread}) {
            if (t != null) {
                t.interrupt();
            }
        }
    }

    /** Looks up the glue and, unless told, which of it is this host; again every hour. */
    private void findAddresses() {
        hourly("finding this hub's address", () -> true, this::lookUpGlue);
    }

    private void lookUpGlue() {
        Map<String, String> glue = Advertise.glue(config.hostname());
        nameServers = glue;
        if (config.advertise() == null) {
            String me = glue.isEmpty() ? null : Advertise.whoAmI(glue, config.hostname(), 53, dns.selfToken());
            if (me != null && !me.equals(advertised)) {
                LOG.info("this hub is {} in the delegation of {} ({})", me, config.hostname(), glue);
            } else if (me == null && advertised == null) {
                LOG.info("{} is not delegated to this hub ({}); the name is answered at the parent, as with three records",
                    config.hostname(), glue.isEmpty() ? "no ns1/ns2 glue" : "glue " + glue + ", none answering with our token");
            }
            if (me != null) {
                advertised = me;
            }
        }
        glueLookedUp = true;
    }

    /**
     * Asks the address question again on a cadence, for as long as this hub is the primary (§7.2).
     * Once at startup was one answer about a world that changes afterwards -- a proxy switched on
     * in front of the name, an edited A record -- and the log line it wrote was gone by the time
     * anyone wanted it. What it costs to repeat is a handful of DNS queries and, where this host
     * can reach its own public address at all, one TLS handshake an hour.
     */
    private void addressCheckLoop() {
        hourly("address check", () -> addressCheckBlocker() == null, this::checkAddress);
    }

    /**
     * Why the address check does not run here right now, or null when it does (§7.2). One answer
     * for the hourly loop, which waits on it, and for {@code jailhub address check}, which refuses
     * with it: a command allowed where the loop declines would either record a verdict nothing
     * refreshes or, on a delegated hub still finding its own address, file a fault about records
     * this hub is not yet answering.
     */
    String addressCheckBlocker() {
        if (!config.addressCheck()) {
            return "the address check is off (--no-address-check)";
        }
        if (dnsUp && config.advertise() == null && advertised == null && (!glueLookedUp || !nameServers.isEmpty())) {
            // The check asks the world what this hub's name resolves to, and with the hubs answering
            // their own DNS that is this hub's own answer: not before it knows what to answer. With
            // the three records at the parent (§7.1) the lookup finds no ns1/ns2 glue and there is
            // nothing more to wait for; with a delegation there is, until this host's place in it
            // is found or --advertise says.
            return "this hub does not yet know what it answers for its own name; the glue lookup runs within a minute"
                + " of start and every hour after";
        }
        return null;
    }

    /** Whether the hourly loop is running, which is what makes a verdict's age mean anything. */
    boolean addressCheckRunning() {
        return addressCheckThread != null;
    }

    /**
     * Runs the check now and records what it found. The hourly pass and {@code jailhub address
     * check} both come here, so an operator who has just edited a record gets the same verdict the
     * page will carry rather than a second opinion printed on a terminal.
     */
    Reachability.Status checkAddress() {
        java.util.function.Supplier<Reachability.Result> probe = addressProbe;
        synchronized (addressCheckLock) {
            // One run at a time. The hourly pass and the command can otherwise overlap, and with a
            // run lasting as long as its resolver timeouts the older of two could finish last and
            // stand as the newer verdict. Waiting is what the operator who just edited a record
            // wants anyway: the run they get starts after their edit.
            long at = System.currentTimeMillis();
            return recordAddressCheck(probe == null ? Reachability.check(config, keys) : probe.get(), at);
        }
    }

    /** Folds one run, made at {@code at}, into the kept verdict and says so when it moved. */
    private Reachability.Status recordAddressCheck(Reachability.Result r, long at) {
        Reachability.Status previous;
        Reachability.Status now;
        synchronized (this) {
            previous = addressStatus;
            now = Reachability.fold(previous, r, at, reachedFromOutsideAt, reachedFromOutsideIp, System.currentTimeMillis());
            addressStatus = now;
        }
        // Outside the monitor: a log line is I/O, and the handshake that folds an arrival in
        // (reachedBy) should not hold a demotion behind it.
        Reachability.report(config.hostname(), previous, now);
        return now;
    }

    /** What the address check concluded (§7.2), or null where it has not run or is turned off. */
    Reachability.Status addressStatus() {
        return addressStatus;
    }

    /** ACME on the DNS responder already running: blocks until a certificate is installed. Primary only. */
    private void startAcme() throws IOException, GeneralSecurityException {
        if (!dnsUp) {
            throw new IOException("port " + config.dnsListenPort() + " is not bound, and dns-01 issuance needs it");
        }
        acme = new AcmeManager(config, tls, dns, () -> {
            for (NodeGroup g : registry.all()) {
                NodeSession p = g.primary();
                if (p != null) {
                    p.certChanged();
                }
            }
        });
        try {
            acme.start();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while obtaining a certificate");
        }
    }

    /** What this hub serves besides 443: the address check (§7.2). */
    private void startPrimaryFronts() {
        if (config.acme() && config.addressCheck() && addressCheckThread == null) {
            // After the listener is up, or the one connection that proves the records reach this
            // process would arrive with nothing to answer it. Off the startup path: the answer is a
            // diagnosis for the operator, never a reason to refuse to serve. Deliberately not tied
            // to --no-selfcheck: that flag exists because the dns-01 check holds issuance until it
            // passes, and nothing here can hold anything.
            addressCheckThread = Thread.ofVirtual().name("address-check").start(this::addressCheckLoop);
        }
    }

    /** The dns-01 values this hub is answering right now; empty when no issuance is under way. */
    List<String> dnsTxt() {
        return dns == null ? List.of() : dns.txt();
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
        // The address first: the timestamp is what makes the pair visible to the check's own
        // thread, and between the two writes it would read a fresh arrival with no address.
        reachedFromOutsideIp = remoteIp;
        reachedFromOutsideAt = System.currentTimeMillis();
        if (first) {
            LOG.info("a node at {} resolved {} and arrived here: from where it stands, the address record points"
                + " at this hub", remoteIp, config.hostname());
        }
        // Fold it into the standing verdict now rather than at the next pass: this is the view that
        // answers the case a host behind a translated address cannot answer about itself, and an
        // operator watching an inconclusive verdict is watching for exactly this to arrive. Only
        // over that verdict, since it is the one an arrival can move (Reachability.fold); every
        // other reads the timestamp above at its next pass, and a reconnect storm should not queue
        // each handshake on this hub's monitor for nothing.
        Reachability.Status s = addressStatus;
        if (s != null && Reachability.INCONCLUSIVE.equals(s.verdict())) {
            recordAddressCheck(s.run(), s.at());
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

    FlowBudget flowBudget() {
        return flowBudget;
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

    SniRouter router() {
        return router;
    }

    static String version() {
        String v = Hub.class.getPackage() == null ? null : Hub.class.getPackage().getImplementationVersion();
        return v == null ? "dev" : v;
    }

    /** The DNS responder's port, or 0 when port 53 could not be bound. */
    public int dnsPort() {
        return dnsUp ? dns.port() : 0;
    }

    /** The responder itself (tests). */
    io.jailscale.hub.dns.DnsResponder dns() {
        return dns;
    }

    @Override
    public void close() throws IOException {
        running = false;
        stopped = true;
        if (preBound != null) {   // listenOn, and then never started
            preBound.close();
            preBound = null;
        }
        stopLoops();
        if (timer != null) {
            timer.shutdownNow();
        }
        if (acme != null) {
            acme.close();
        }
        if (dns != null) {
            dns.close();
        }
        registry.closeAll(Message.Goodbye.SHUTDOWN);
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
