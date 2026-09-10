package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.tls.Tls;
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
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

/** The jailhub process: keys, store, TLS listener, node sessions, admin IPC (DESIGN.md §2). */
public final class Hub implements AutoCloseable {

    private static final Log LOG = Log.get("hub");
    static final int KEEPALIVE_SECONDS = 25;

    private final HubConfig config;
    private final Store store;
    private final HubKeys keys;
    private final Registry registry = new Registry();
    private final Registrar registrar;
    private final Invites invites;
    private final HttpFront front;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private SSLServerSocket listener;
    private Ipc.Server ipc;
    private ScheduledExecutorService timer;
    private volatile boolean running;

    public Hub(HubConfig config) throws IOException, GeneralSecurityException {
        this.config = config;
        java.nio.file.Files.createDirectories(config.stateDir());
        this.lockChannel = FileChannel.open(config.stateDir().resolve("jailhub.lock"),
            StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        this.lock = lockChannel.tryLock();
        if (lock == null) {
            lockChannel.close();
            throw new IOException("another jailhub serve holds " + config.stateDir());
        }
        this.store = new Store(config.stateDir());
        this.keys = new HubKeys(config.stateDir());
        this.registrar = new Registrar(config, store);
        this.invites = new Invites(config, store);
        this.front = new HttpFront(this);
    }

    public void start() throws IOException, GeneralSecurityException {
        promoteRotationIfDue();
        SSLContext ctx = Tls.serverContext(config.tlsCert(), config.tlsKey());
        listener = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket();
        listener.setReuseAddress(true);
        listener.bind(new InetSocketAddress(config.listenHost(), config.listenPort()), 128);
        Tls.configureServer(listener);
        running = true;
        Thread.ofPlatform().name("accept").daemon(false).start(this::acceptLoop);

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
            Thread.ofVirtual().name("conn-" + s.getInetAddress().getHostAddress()).start(() -> front.serve(s));
        }
    }

    private void tick() {
        try {
            for (NodeSession s : registry.all()) {
                s.sendKeepalive();
            }
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
        for (NodeSession s : registry.all()) {
            try {
                s.send(m);
            } catch (IOException e) {
                s.close();
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

    HubKeys keys() {
        return keys;
    }

    Registry registry() {
        return registry;
    }

    Registrar registrar() {
        return registrar;
    }

    Invites invites() {
        return invites;
    }

    static String version() {
        String v = Hub.class.getPackage() == null ? null : Hub.class.getPackage().getImplementationVersion();
        return v == null ? "dev" : v;
    }

    @Override
    public void close() throws IOException {
        running = false;
        if (timer != null) {
            timer.shutdownNow();
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
