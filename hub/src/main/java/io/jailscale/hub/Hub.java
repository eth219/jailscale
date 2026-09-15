package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.mux.FlowBudget;
import io.jailscale.proto.util.Clock;
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
    private volatile boolean handingOff;
    private final Registrar registrar;
    private final Bans bans;
    private final Invites invites;
    private final HttpFront front;
    private final HubTls tls;
    private final Links links;
    private final RawPorts rawPorts;
    private final Challenges challenges;
    private volatile HttpChallengeFront http;
    private MetricsFront metrics;
    private final SniRouter router;
    private final AdminWeb adminWeb;
    private io.jailscale.hub.dns.DnsResponder dns;
    private AcmeManager acme;
    private final Availability availability;
    private final Peers peers = new Peers(this);
    private final Role roleFile;
    /** Set while this hub follows a primary (ARCHITECTURE.md §13.1); cleared by {@link #promote}, set by {@link #demote}. */
    private volatile boolean standby;
    /** §13.5: when the channel to the primary was last seen up, or 0 while it is; the watch reads it. */
    private volatile long primaryLostAt;
    private volatile long lastAutoPromoteAt;
    /** Nonces out to witnesses right now, and whether a valid answer came back for the round. */
    private final java.util.Set<String> probeNonces = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private volatile boolean primaryProven;
    /** §13.5 timings; tests shorten them. */
    static volatile long promoteAfterMs = 30_000;
    static volatile long witnessWindowMs = 10_000;
    static volatile long autoPromoteIntervalMs = 10 * 60_000;
    private volatile PeerClient peerClient;
    /** The public address this hub answers for itself (§13.3); null until known. */
    private volatile String advertised;
    /**
     * What nodes dial to reach this host as a relay (§13.4), when it is not the advertised
     * address on 443. Tests, where two hubs share a loopback address and differ by port.
     */
    volatile String relayEndpointOverride;
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
        this(config, false);
    }

    /**
     * With {@code takeover}, a running server in the same state directory is asked to hand off
     * first (ARCHITECTURE.md §13); without it, a held lock is an error.
     */
    public Hub(HubConfig config, boolean takeover) throws IOException, GeneralSecurityException {
        Resources.markStarted(System.currentTimeMillis());
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
        this.roleFile = new Role(config.stateDir(), config.standby());
        this.standby = !roleFile.isPrimary();
        if (standby && !HubKeys.exists(config.stateDir())) {
            // Generating one would make a hub that cannot authenticate to its primary and never
            // says why: the handshake just fails. The missing file is the whole problem.
            lock.release();
            lockChannel.close();
            throw new IOException("a standby needs the primary's hub key: copy " + config.peer().getHost()
                + "'s hub.key into " + config.stateDir() + " and start again");
        }
        this.availability = new Availability(config.stateDir(), System.currentTimeMillis());
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
        this.links.standby(() -> standby);
        this.router = new SniRouter(this);
        this.adminWeb = new AdminWeb(this);
        // Flags seed the runtime settings once; afterwards /admin and `jailhub setting` own them.
        // Not on a standby: its settings are the primary's, and arrive with the snapshot.
        if (!standby && !store.hasSetting(Store.SETTING_INVITE_POLICY)) {
            store.setSetting(Store.SETTING_INVITE_POLICY, config.invitePolicy());
        }
        if (!standby && !store.hasSetting(Store.SETTING_REGISTRATION)) {
            store.setSetting(Store.SETTING_REGISTRATION, config.registrationOpen() ? "open" : "invite");
        }
        if (!standby && !store.hasSetting(Store.SETTING_KNOCK)) {
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
        if (standby) {
            // Own files if given, so 443 can open at once; otherwise the certificate is the
            // primary's and arrives over the channel, and this blocks for it the way ACME does.
            if (!config.acme()) {
                tls.load(config.tlsCert(), config.tlsKey());
            }
            if (config.peer() == null) {
                throw new IOException("this hub's role file says standby, but no --peer names the primary to follow");
            }
            peerClient = new PeerClient(this, config.peer(), config.peerCa(), config.peerAddr());
            peerClient.start();
            if (!tls.isLoaded()) {
                LOG.info("standby of {}: waiting for its certificate", config.peer().getHost());
            }
            try {
                while (!tls.isLoaded()) {
                    Thread.sleep(100);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted while waiting for the primary's certificate");
            }
        } else if (config.acme()) {
            startAcme(); // blocks until a certificate is installed
        } else {
            tls.load(config.tlsCert(), config.tlsKey());
        }
        if (!standby && config.peer() != null) {
            // A primary that names a peer (§13.5): the units are the same on both hosts, and this
            // one dials the other only to find out whether it is a primary that outranks this one.
            peerClient = new PeerClient(this, config.peer(), config.peerCa(), config.peerAddr());
            peerClient.start();
        }
        listener = new ServerSocket();
        listener.setReuseAddress(true);
        listener.bind(new InetSocketAddress(config.listenHost(), config.listenPort()), 1024); // capped by somaxconn
        running = true;
        Thread.ofPlatform().name("accept").daemon(false).start(this::acceptLoop);
        if (!standby) {
            startPrimaryFronts();
        }
        if (config.hasMetrics()) {
            // Warn and serve on, as port 80 does: a hub that cannot be scraped is still a hub that
            // routes, and refusing to start would make the monitoring an outage of its own.
            try {
                metrics = new MetricsFront(this, config.metricsListenHost(), config.metricsListenPort());
            } catch (IOException e) {
                LOG.warn("metrics port {} unavailable ({}); /metrics is not served", config.metricsListenPort(), e.getMessage());
            }
        }

        ipc = Ipc.serve(config.socketPath(), new AdminIpc(this));
        timer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "timer");
            t.setDaemon(true);
            return t;
        });
        timer.scheduleAtFixedRate(this::tick, KEEPALIVE_SECONDS, KEEPALIVE_SECONDS, TimeUnit.SECONDS);
        timer.scheduleAtFixedRate(() -> availability.stamp(System.currentTimeMillis()),
            Availability.STAMP_EVERY_MS, Availability.STAMP_EVERY_MS, TimeUnit.MILLISECONDS);
        timer.scheduleAtFixedRate(this::watchPrimary, 1000, 1000, TimeUnit.MILLISECONDS);

        LOG.info("jailhub {} listening on {}:{} for {} (hub key {}){}", version(), config.listenHost(), port(),
            config.hostname(), keys.publicText(), standby ? ", standby of " + config.peer().getHost() : "");
        if (!standby && !store.hasAnyAdmin()) {
            Invites.Created c = invites.create(null, 1, 24 * 3600, "bootstrap", true);
            LOG.info("no admin yet. First invite (24h, 1 use); whoever joins with it becomes admin:");
            System.out.println();
            System.out.println("  jailscale up --invite " + c.url());
            System.out.println("  (or: jailscale up --hub " + config.hostname() + " --code " + c.code() + ", valid 10 minutes)");
            System.out.println();
        }
    }

    /**
     * The hub's authoritative DNS (§7.1, §13.3), on both roles and whichever way the certificate
     * comes: a standby answers as the second name server, and an operator with their own files may
     * still delegate the subdomain. Port 53 not bindable is fatal only where issuance needs it --
     * a primary obtaining its own certificate -- and a warning everywhere else.
     */
    private void startDns() throws IOException {
        dns = new io.jailscale.hub.dns.DnsResponder(config.hostname());
        dns.setZone(new io.jailscale.hub.dns.DnsResponder.Zone() {
            @Override public List<String> serving() { return Hub.this.serving(); }
            @Override public List<String> control() { return Hub.this.control(); }
            @Override public List<String> forName(String label) { return Hub.this.hostsForName(label); }
            @Override public Map<String, String> nameServers() { return nameServers; }
        });
        dns.onTxtChanged(peers::challengeChanged);
        try {
            dns.start(config.dnsListenHost(), config.dnsListenPort());
            dnsUp = true;
        } catch (IOException e) {
            if (config.acme() && !standby) {
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
     * The hosts serving this hub's names right now (§13.3, §13.4): this host, and every peer whose
     * hub-to-hub channel is up. A standby serves too -- it holds the store and the key -- so a
     * name resolves to both hosts, and a visitor who reaches either is served.
     */
    List<String> serving() {
        List<String> out = new ArrayList<>(2);
        if (advertised != null) {
            out.add(advertised);
        }
        for (String a : peerAddresses()) {
            if (!out.contains(a)) {
                out.add(a);
            }
        }
        return out;
    }

    /**
     * Where the apex points (§13.4): the control plane, which is the primary alone. A node's
     * control connection, a join, an admin page all write, and only the primary writes; a
     * standby that answered the apex with itself would take control connections it must refuse.
     */
    List<String> control() {
        if (!standby) {
            return advertised == null ? List.of() : List.of(advertised);
        }
        PeerClient pc = peerClient;
        String primary = pc == null ? null : pc.primaryAddress();
        return pc != null && pc.isConnected() && primary != null ? List.of(hostOf(primary)) : List.of();
    }

    /**
     * The hosts a published name resolves to (§13.4): those its node is attached to, here or on a
     * peer; the whole serving set when it is attached nowhere or the name is nobody's, so that a
     * visitor still reaches a host that can say "not open".
     */
    List<String> hostsForName(String label) {
        Store.NameRec rec = store.name(label);
        if (rec == null || rec.mkey() == null) {
            return serving();
        }
        List<String> out = new ArrayList<>(2);
        if (advertised != null && registry.get(rec.mkey()) != null) {
            out.add(advertised);
        }
        for (Map.Entry<String, java.util.Set<String>> e : peerNodes().entrySet()) {
            if (e.getValue().contains(rec.mkey()) && !out.contains(e.getKey())) {
                out.add(e.getKey());
            }
        }
        return out.isEmpty() ? serving() : out;
    }

    /** The addresses of the peers whose channel is up right now, IPv4 only, no port. */
    private List<String> peerAddresses() {
        List<String> out = new ArrayList<>(2);
        if (!standby) {
            for (Peers.Session s : peers.all()) {
                if (s.address() != null) {
                    out.add(hostOf(s.address()));
                }
            }
        } else {
            PeerClient pc = peerClient;
            if (pc != null && pc.isConnected() && pc.primaryAddress() != null) {
                out.add(hostOf(pc.primaryAddress()));
            }
        }
        return out;
    }

    /** The nodes attached to each peer, keyed by the peer's address (§13.4). */
    private Map<String, java.util.Set<String>> peerNodes() {
        Map<String, java.util.Set<String>> out = new java.util.LinkedHashMap<>();
        if (!standby) {
            for (Peers.Session s : peers.all()) {
                if (s.address() != null) {
                    out.put(hostOf(s.address()), s.nodes());
                }
            }
        } else {
            PeerClient pc = peerClient;
            if (pc != null && pc.isConnected() && pc.primaryAddress() != null) {
                out.put(hostOf(pc.primaryAddress()), pc.primaryNodes());
            }
        }
        return out;
    }

    /** {@code address} or {@code address:port} to the address alone. */
    static String hostOf(String endpoint) {
        int c = endpoint.lastIndexOf(':');
        return c > 0 && endpoint.indexOf(':') == c ? endpoint.substring(0, c) : endpoint;
    }

    /**
     * What a node is told to open relay connections to (§13.4): every serving host as
     * {@code address[:port]}, this one included -- the node leaves out the one its control
     * connection already reached. The port rides along only when it is not 443, which is a test.
     */
    List<String> relaysForNodes() {
        List<String> out = new ArrayList<>(2);
        String self = relayEndpoint();
        if (self != null) {
            out.add(self);
        }
        if (!standby) {
            for (Peers.Session s : peers.all()) {
                if (s.endpoint() != null && !out.contains(s.endpoint())) {
                    out.add(s.endpoint());
                }
            }
        } else {
            PeerClient pc = peerClient;
            if (pc != null && pc.isConnected() && pc.primaryEndpoint() != null && !out.contains(pc.primaryEndpoint())) {
                out.add(pc.primaryEndpoint());
            }
        }
        return out;
    }

    /** What a node dials to reach this host as a relay: the advertised address, with the port when it is not 443. */
    String relayEndpoint() {
        if (relayEndpointOverride != null) {
            return relayEndpointOverride;
        }
        if (advertised == null) {
            return null;
        }
        int p = listener == null ? config.listenPort() : port();
        return p == 443 ? advertised : advertised + ":" + p;
    }

    /** The set of attached nodes changed: tell the peer, so its per-name answers follow (§13.4). */
    void nodesChanged() {
        List<String> keys = registry.machineKeys();
        Message m = new Message.PeerNodes(keys);
        peers.send(m);
        PeerClient pc = peerClient;
        if (pc != null) {
            pc.send(m);
        }
    }

    /** The relay set changed (a peer came or went): every node's control connection is told (§13.4). */
    void relaysChanged() {
        if (stopped) {
            // A hub going down closes its peer sessions on the way, and the list without them is
            // not news a node should act on: the nodes keep their relay connections to the hosts
            // that are still up, which is the whole point of having them. A crashed hub says
            // nothing; a closed one must not say more.
            return;
        }
        List<String> relays = relaysForNodes();
        Message m = new Message.RelaysChanged(relays);
        for (NodeGroup g : registry.all()) {
            NodeSession p = g.primary();
            if (p != null && p.conn() == 0 && !p.isRelay()) {
                try {
                    p.send(m);
                } catch (IOException e) {
                    LOG.debug("node {}: could not send the relay list: {}", g.machineKey(), e.getMessage());
                }
            }
        }
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
        if (standby) {
            // Stood down (§13.5): the records being checked are the primary's, and a standby that
            // kept checking would find the primary's key at the shared address and call it a fault.
            // The primary is named only when there is one to name: a hub that stood down by epoch
            // rather than by --peer has no peer in its configuration.
            String primary = config.peer() == null ? null : config.peer().getHost();
            return "this hub is a standby; the records to check are the primary's" + (primary == null ? "" : " (" + primary + ")");
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
     * page and the metrics will carry rather than a second opinion printed on a terminal.
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
            if (standby) {
                // Stood down while this run was in flight, which takes long enough to be overtaken:
                // a resolver that does not answer costs five seconds and the dial another. The flag
                // is read here, under the monitor demote() holds, because the loop's own test of it
                // happened before the run started. The answer is a primary's about records that are
                // no longer this hub's, so it goes back to whoever asked and is kept nowhere.
                return now;
            }
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
            peers.certChanged();
        });
        try {
            acme.start();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while obtaining a certificate");
        }
    }

    /**
     * What only a primary serves besides 443: the address check, and port 80 for user domains.
     * A standby has no nodes to relay challenges for and its address records are not the ones
     * being checked.
     */
    private void startPrimaryFronts() {
        if (config.acme() && config.addressCheck() && addressCheckThread == null) {
            // After the listener is up, or the one connection that proves the records reach this
            // process would arrive with nothing to answer it. Off the startup path: the answer is a
            // diagnosis for the operator, never a reason to refuse to serve. Deliberately not tied
            // to --no-selfcheck: that flag exists because the dns-01 check holds issuance until it
            // passes, and nothing here can hold anything. Promotion comes back through here (§13.1)
            // and demote() ends the loop, so a hub that takes over starts a fresh one that checks
            // at once; the null check is for the ordinary case of starting as the primary.
            addressCheckThread = Thread.ofVirtual().name("address-check").start(this::addressCheckLoop);
        }
        if (config.hasHttp() && http == null) {
            try {
                http = new HttpChallengeFront(this, config.httpListenHost(), config.httpListenPort());
            } catch (IOException e) {
                LOG.warn("port {} unavailable ({}); user domains are disabled until it is", config.httpListenPort(), e.getMessage());
            }
        }
    }

    /**
     * Makes this standby the primary (ARCHITECTURE.md §13.1, §13.5): stops following, takes the
     * next epoch, and starts what a primary runs and a standby does not -- issuance, port 80.
     * With the subdomain delegated to both hubs the name follows on its own (§13.3); with three
     * records at the parent the operator moves them. An old primary that returns and meets this
     * one stands down by epoch (§13.5).
     */
    synchronized void promote() throws IOException {
        promote("by the operator");
    }

    private synchronized void promote(String why) throws IOException {
        if (!standby) {
            throw new IOException("this hub is already the primary");
        }
        String primary = config.peer().getHost();
        boolean synced = peerClient != null && peerClient.isSynced();
        roleFile.promote();
        standby = false;
        primaryLostAt = 0;
        PeerClient old = peerClient;
        peerClient = null;
        if (old != null) {
            old.close();
        }
        LOG.warn("promoted {}: this hub is now the primary at epoch {}{}. {} stands down by epoch when it returns",
            why, roleFile.epoch(), synced ? "" : " (it was NOT in sync with " + primary + " at the time)", primary);
        relaysChanged();
        Thread.ofVirtual().name("promote").start(() -> {
            try {
                if (config.acme()) {
                    startAcme();
                }
                startPrimaryFronts();
            } catch (IOException | GeneralSecurityException e) {
                LOG.error("after promotion: {}", e.getMessage());
            }
            if (config.peer() != null) {
                PeerClient pc = new PeerClient(this, config.peer(), config.peerCa(), config.peerAddr());
                peerClient = pc;
                pc.start();
            }
        });
    }

    /**
     * Stands down before a primary that outranks this one (§13.5): this hub becomes its standby.
     * Nodes on the control connection are told to go, issuance and port 80 stop, and the peer
     * client that found the other primary keeps its connection and follows from here on.
     */
    synchronized void demote(long theirEpoch, String theirHost) throws IOException {
        if (standby) {
            return;
        }
        roleFile.demote(theirEpoch);
        standby = true;
        // Along with acme and port 80 below: the address check is a primary's (§7.2), and the
        // verdict this hub reached as one stops being about anything the moment it stands down.
        // The loop is ended rather than parked, so a promotion (§13.1) starts a fresh one that
        // checks at once instead of finding this one asleep for the rest of its hour.
        addressStatus = null;
        Thread checking = addressCheckThread;
        if (checking != null) {
            checking.interrupt();
            addressCheckThread = null;
        }
        primaryLostAt = 0;
        LOG.warn("standing down: {} is the primary at epoch {}, this hub was one at a lower epoch and is now its standby",
            theirHost, theirEpoch);
        if (acme != null) {
            acme.close();
            acme = null;
        }
        if (http != null) {
            http.close();
            http = null;
        }
        peers.closeAll();
        registry.closeAll("standby");
        relaysChanged();
    }

    Role roleFile() {
        return roleFile;
    }

    /** The current epoch (§13.5): rises by one on every promotion. */
    long epoch() {
        return roleFile.epoch();
    }

    /** §13.5: whether a standby may promote itself; off by default where registration is open. */
    boolean autoPromote() {
        String dflt = "open".equals(store.setting(Store.SETTING_REGISTRATION, "invite")) ? "off" : "on";
        return "on".equals(store.setting(Store.SETTING_AUTO_PROMOTE, dflt));
    }

    /** The private half of the hub key, the secret the liveness proof (§13.5) is made under. */
    byte[] livenessSecret() {
        return keys.current().privateKey();
    }

    /**
     * §13.5, on the standby, once a second: notice the channel to the primary down, and after
     * {@link #promoteAfterMs} ask every witness whether the primary can be reached; when none can
     * within {@link #witnessWindowMs}, promote. A witness is a node attached here by a relay
     * connection, approved, one per user. With no witness the decision stays a person's.
     */
    private void watchPrimary() {
        if (!standby || stopped) {
            return;
        }
        PeerClient pc = peerClient;
        // Monotonic: these two windows are pure differences of local readings, and the misfire this
        // avoids is a split brain. A wall clock stepped back by an NTP correction freezes
        // `now - primaryLostAt` for the width of the step and delays promotion past the availability
        // budget; stepped forward it satisfies both windows at once and fires a witness round early.
        long now = Clock.millis();
        if (pc != null && pc.isConnected()) {
            primaryLostAt = 0;
            probeNonces.clear();
            return;
        }
        if (primaryLostAt == 0) {
            primaryLostAt = now;
            return;
        }
        if (now - primaryLostAt < promoteAfterMs || !probeNonces.isEmpty() || !autoPromote()
            || now - lastAutoPromoteAt < autoPromoteIntervalMs) {
            return;
        }
        // One round: a nonce to every witness, then a window to answer in.
        List<NodeGroup> witnesses = new ArrayList<>();
        java.util.Set<String> users = new java.util.HashSet<>();
        for (NodeGroup g : registry.all()) {
            Store.NodeRec n = store.node(g.machineKey());
            if (n != null && users.add(n.user())) {
                witnesses.add(g);
            }
        }
        if (witnesses.isEmpty()) {
            LOG.warn("primary unreachable for {} s and no node attached here to ask; promotion stays with the operator",
                (now - primaryLostAt) / 1000);
            primaryLostAt = now; // ask again after another interval
            return;
        }
        primaryProven = false;
        for (NodeGroup g : witnesses) {
            NodeSession s = g.primary();
            if (s == null) {
                continue;
            }
            byte[] nonce = Liveness.nonce();
            probeNonces.add(java.util.HexFormat.of().formatHex(nonce));
            try {
                s.send(new Message.PeerProbe(nonce));
            } catch (IOException e) {
                LOG.debug("witness {}: {}", g.machineKey(), e.getMessage());
            }
        }
        int asked = probeNonces.size();
        Thread.ofVirtual().name("witness-round").start(() -> {
            try {
                Thread.sleep(witnessWindowMs);
            } catch (InterruptedException e) {
                return;
            }
            probeNonces.clear();
            PeerClient now2 = peerClient;
            if (!standby || (now2 != null && now2.isConnected())) {
                return;
            }
            if (primaryProven) {
                LOG.warn("primary unreachable from here but reachable from a node: a partition, not a death; not promoting");
                primaryLostAt = Clock.millis();
                return;
            }
            try {
                lastAutoPromoteAt = Clock.millis();
                promote("automatically: " + asked + " witness(es) asked, none could reach the primary");
            } catch (IOException e) {
                LOG.error("automatic promotion failed: {}", e.getMessage());
            }
        });
    }

    /** A node brought back the primary's answer to one of this standby's probes (§13.5). */
    void probeAnswered(Message.PeerProbeAnswer a) {
        String key = java.util.HexFormat.of().formatHex(a.nonce());
        if (!probeNonces.contains(key)) {
            return;
        }
        if (Liveness.verify(livenessSecret(), a.nonce(), a.epoch(), a.mac())) {
            primaryProven = true;
        } else {
            LOG.warn("a witness brought back a liveness answer that does not verify; ignored");
        }
    }

    /** A standby installed a certificate from its primary: nodes on it, if any, get the public half. */
    void certificateArrived() {
        for (NodeGroup g : registry.all()) {
            NodeSession p = g.primary();
            if (p != null) {
                p.certChanged();
            }
        }
    }

    /** The dns-01 values this hub is answering right now; empty when no issuance is under way. */
    List<String> dnsTxt() {
        return dns == null ? List.of() : dns.txt();
    }

    /** The primary's current dns-01 values, to answer with here too (§13.3). Standby only. */
    void challengeFromPrimary(List<String> txt) {
        if (standby && dns != null) {
            dns.setTxt(txt);
        }
    }

    /** "primary" or "standby" (ARCHITECTURE.md §13.1). */
    String role() {
        return standby ? "standby" : "primary";
    }

    boolean isStandby() {
        return standby;
    }

    Peers peers() {
        return peers;
    }

    /** Null unless this hub is a standby. */
    PeerClient peerClient() {
        return peerClient;
    }

    Availability availability() {
        return availability;
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
        peers.hubKeyChanged();
        return activatesAt;
    }

    synchronized void promoteRotationIfDue() throws IOException {
        if (standby) {
            return; // the primary completes it and sends the key (§13.1)
        }
        long at = store.hubKeyActivatesAt();
        if (store.nextHubKey() != null && at > 0 && System.currentTimeMillis() >= at) {
            keys.completeRotation();
            store.clearHubKeyRotation();
            peers.hubKeyChanged();
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
        if (s != null && !standby && Reachability.INCONCLUSIVE.equals(s.verdict())) {
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
        stopped = true;
        stopLoops();
        LOG.info("hand-off requested: releasing listener and state");
        if (listener != null) {
            listener.close();
        }
        rawPorts.close();
        if (http != null) {
            http.close();
        }
        if (metrics != null) {
            metrics.close();
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
        if (peerClient != null) {
            peerClient.close();
        }
        peers.closeAll(); // they reconnect to the new process and start from its snapshot
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

    /** The DNS responder's port, or 0 when port 53 could not be bound. */
    public int dnsPort() {
        return dnsUp ? dns.port() : 0;
    }

    /** The responder itself (tests). */
    io.jailscale.hub.dns.DnsResponder dns() {
        return dns;
    }

    /** The port {@code /metrics} is on, or 0 when it is not served. */
    public int metricsPort() {
        return metrics == null ? 0 : metrics.port();
    }

    @Override
    public void close() throws IOException {
        running = false;
        stopped = true;
        stopLoops();
        if (timer != null) {
            timer.shutdownNow();
        }
        if (handingOff) {
            registry.closeAll(Message.Goodbye.SHUTDOWN);
            return;
        }
        if (peerClient != null) {
            peerClient.close();
        }
        peers.closeAll();
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
        if (metrics != null) {
            metrics.close();
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
