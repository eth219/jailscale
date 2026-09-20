package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.util.Clock;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The two-hub path (ARCHITECTURE.md §13), kept out of {@link Hub} so that a reader following the
 * single-hub path does not step over it. Two things live here because they are the same thing seen
 * from two sides:
 *
 * <ul>
 *   <li><b>Which hub this is, and how that changes.</b> The role file, the standby flag, the peer
 *       client that follows a primary, {@link #promote} and {@link #demote}, and the watch that
 *       promotes automatically when witnesses agree the primary is gone (§13.5).</li>
 *   <li><b>What follows from it.</b> {@link #serving}, {@link #control}, {@link #hostsForName} and
 *       {@link #relaysForNodes} -- the answers DNS and the control channel give about where this
 *       hub's names live (§13.3, §13.4). A primary and a standby answer these differently, and
 *       both answers read the same role flag and peer client as the block above.</li>
 * </ul>
 *
 * <p><b>The monitor is {@link Hub}'s, not this object's.</b> {@link #promote} and {@link #demote}
 * are called only from {@code Hub}'s {@code synchronized} methods of the same name, and they must
 * stay that way: {@code Hub} holds that one monitor across the role change, the key rotation
 * ({@code rotateKey}, {@code promoteRotationIfDue}), the hand-off, and the fold of an address-check
 * run -- which reads the standby flag under it precisely so that a run in flight when this hub
 * stands down is discarded rather than kept as a primary's verdict. Giving this class a monitor of
 * its own would leave all four of those free to interleave with a promotion. Nothing here
 * synchronizes, and that is deliberate.
 *
 * <p>{@link #promote} and {@link #demote} open with {@code assert Thread.holdsLock(hub)}, because
 * without it the rule above is a paragraph rather than a check: the {@code synchronized} keyword
 * that used to enforce it now sits one file away, and no test fails if it is dropped. Surefire runs
 * with assertions on, so that assert is what fails instead.
 */
final class Standby {

    // The "hub" tag and not one of this class's own: these lines were emitted by Hub before the
    // move, and an operator grepping their journal for them should not have to know that.
    private static final Log LOG = Log.get("hub");

    private final Hub hub;
    private final HubConfig config;
    private final Role roleFile;

    /** Set while this hub follows a primary (§13.1); cleared by {@link #promote}, set by {@link #demote}. */
    private volatile boolean standby;
    /** §13.5: when the channel to the primary was last seen up, or 0 while it is; the watch reads it. */
    private volatile long primaryLostAt;
    /**
     * When this hub last promoted itself, and zero for never -- which is not a reading. {@link Clock}
     * has no defined origin, so {@code now - 0} is however long that clock has been running, which
     * where it counts from boot is the host's uptime; compared against the interval below it
     * suppressed automatic promotion for the first ten minutes of it. That is the case this exists
     * for -- the machines come back together and the primary does not -- so the sentinel is read as
     * the sentinel, the rule {@code Throttle} states for the same arithmetic.
     */
    private volatile long lastAutoPromoteAt;
    /** Nonces out to witnesses right now, and whether a valid answer came back for the round. */
    private final Set<String> probeNonces = ConcurrentHashMap.newKeySet();
    private volatile boolean primaryProven;
    private volatile PeerClient peerClient;

    Standby(Hub hub, HubConfig config) throws IOException {
        this.hub = hub;
        this.config = config;
        this.roleFile = new Role(config.stateDir(), config.standby());
        this.standby = !roleFile.isPrimary();
    }

    boolean isStandby() {
        return standby;
    }

    Role roleFile() {
        return roleFile;
    }

    /** The current epoch (§13.5): rises by one on every promotion. */
    long epoch() {
        return roleFile.epoch();
    }

    /** Null unless this hub is following a primary, or is a primary that names a peer. */
    PeerClient peerClient() {
        return peerClient;
    }

    /** §13.5: whether a standby may promote itself; off by default where registration is open. */
    boolean autoPromote() {
        String dflt = "open".equals(hub.store().setting(Store.SETTING_REGISTRATION, "invite")) ? "off" : "on";
        return "on".equals(hub.store().setting(Store.SETTING_AUTO_PROMOTE, dflt));
    }

    /**
     * Opens the channel to the peer named by {@code --peer}, on either role.
     *
     * <p>Started through the local and not through the field, which is what the promotion path did
     * before this class existed. Reading {@code peerClient} back to call {@code start()} on it lets
     * a promotion that runs in between -- which sets the field to null -- turn this into a
     * NullPointerException on an unnamed virtual thread, where nothing would report it.
     */
    void startPeerClient() {
        PeerClient pc = new PeerClient(hub, config.peer(), config.peerCa(), config.peerAddr());
        peerClient = pc;
        pc.start();
    }

    void closePeerClient() {
        PeerClient pc = peerClient;
        if (pc != null) {
            pc.close();
        }
    }

    // --- where this hub's names live (§13.3, §13.4) -------------------------------------------

    /**
     * The hosts serving this hub's names right now (§13.3, §13.4): this host, and every peer whose
     * hub-to-hub channel is up. A standby serves too -- it holds the store and the key -- so a
     * name resolves to both hosts, and a visitor who reaches either is served.
     */
    List<String> serving() {
        List<String> out = new ArrayList<>(2);
        if (hub.advertisedAddress() != null) {
            out.add(hub.advertisedAddress());
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
     * control connection and a join both write, and only the primary writes; a standby that
     * answered the apex with itself would take control connections it must refuse.
     */
    List<String> control() {
        if (!standby) {
            return hub.advertisedAddress() == null ? List.of() : List.of(hub.advertisedAddress());
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
        Store.NameRec rec = hub.store().name(label);
        if (rec == null || rec.mkey() == null) {
            return serving();
        }
        List<String> out = new ArrayList<>(2);
        if (hub.advertisedAddress() != null && hub.registry().get(rec.mkey()) != null) {
            out.add(hub.advertisedAddress());
        }
        for (Map.Entry<String, Set<String>> e : peerNodes().entrySet()) {
            if (e.getValue().contains(rec.mkey()) && !out.contains(e.getKey())) {
                out.add(e.getKey());
            }
        }
        return out.isEmpty() ? serving() : out;
    }

    /**
     * What a node is told to open relay connections to (§13.4): every serving host as
     * {@code address[:port]}, this one included -- the node leaves out the one its control
     * connection already reached. The port rides along only when it is not 443, which is a test.
     */
    List<String> relaysForNodes() {
        List<String> out = new ArrayList<>(2);
        String self = hub.relayEndpoint();
        if (self != null) {
            out.add(self);
        }
        if (!standby) {
            for (Peers.Session s : hub.peers().all()) {
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

    /** The addresses of the peers whose channel is up right now, IPv4 only, no port. */
    private List<String> peerAddresses() {
        List<String> out = new ArrayList<>(2);
        if (!standby) {
            for (Peers.Session s : hub.peers().all()) {
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
    private Map<String, Set<String>> peerNodes() {
        Map<String, Set<String>> out = new LinkedHashMap<>();
        if (!standby) {
            for (Peers.Session s : hub.peers().all()) {
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

    // --- becoming, and ceasing to be, the primary (§13.1, §13.5) -------------------------------

    /**
     * Makes this standby the primary: stops following, takes the next epoch, and starts what a
     * primary runs and a standby does not -- issuance, port 80. With the subdomain delegated to
     * both hubs the name follows on its own (§13.3); with three records at the parent the operator
     * moves them. An old primary that returns and meets this one stands down by epoch (§13.5).
     *
     * <p>Called only under {@link Hub}'s monitor; see this class's note on it.
     */
    void promote(String why) throws IOException {
        assert Thread.holdsLock(hub) : "promote must hold the Hub monitor";
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
        hub.relaysChanged();
        Thread.ofVirtual().name("promote").start(() -> {
            try {
                hub.startPrimaryServices();
            } catch (IOException | GeneralSecurityException e) {
                LOG.error("after promotion: {}", e.getMessage());
            }
            if (config.peer() != null) {
                startPeerClient();
            }
        });
    }

    /**
     * Stands down before a primary that outranks this one (§13.5): this hub becomes its standby.
     * Nodes on the control connection are told to go, issuance and port 80 stop, and the peer
     * client that found the other primary keeps its connection and follows from here on.
     *
     * <p>Called only under {@link Hub}'s monitor; see this class's note on it.
     */
    void demote(long theirEpoch, String theirHost) throws IOException {
        assert Thread.holdsLock(hub) : "demote must hold the Hub monitor";
        if (standby) {
            return;
        }
        roleFile.demote(theirEpoch);
        standby = true;
        // Along with acme and port 80 below: the address check is a primary's (§7.2), and the
        // verdict this hub reached as one stops being about anything the moment it stands down.
        // The loop is ended rather than parked, so a promotion (§13.1) starts a fresh one that
        // checks at once instead of finding this one asleep for the rest of its hour.
        hub.stopAddressCheck();
        primaryLostAt = 0;
        LOG.warn("standing down: {} is the primary at epoch {}, this hub was one at a lower epoch and is now its standby",
            theirHost, theirEpoch);
        hub.stopIssuanceAndPort80();
        hub.peers().closeAll();
        hub.registry().closeAll("standby");
        hub.relaysChanged();
    }

    /**
     * §13.5, on the standby, once a second: notice the channel to the primary down, and after
     * {@link HubConfig.Tuning#promoteAfterMs} ask every witness whether the primary can be reached;
     * when none can within {@link HubConfig.Tuning#witnessWindowMs}, promote. A witness is a node
     * attached here by a relay connection, approved, one per user. With no witness the decision
     * stays a person's.
     */
    void watchPrimary() {
        if (!standby || hub.isStopped()) {
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
        if (now - primaryLostAt < config.tuning().promoteAfterMs() || !probeNonces.isEmpty() || !autoPromote()
            || (lastAutoPromoteAt != 0 && now - lastAutoPromoteAt < config.tuning().autoPromoteIntervalMs())) {
            return;
        }
        // One round: a nonce to every witness, then a window to answer in.
        List<NodeGroup> witnesses = new ArrayList<>();
        Set<String> users = new HashSet<>();
        for (NodeGroup g : hub.registry().all()) {
            Store.NodeRec n = hub.store().node(g.machineKey());
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
            probeNonces.add(HexFormat.of().formatHex(nonce));
            try {
                s.send(new Message.PeerProbe(nonce));
            } catch (IOException e) {
                LOG.debug("witness {}: {}", g.machineKey(), e.getMessage());
            }
        }
        int asked = probeNonces.size();
        Thread.ofVirtual().name("witness-round").start(() -> {
            try {
                Thread.sleep(config.tuning().witnessWindowMs());
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
                // Back through Hub, which is where the monitor this must hold lives.
                hub.promote("automatically: " + asked + " witness(es) asked, none could reach the primary");
            } catch (IOException e) {
                LOG.error("automatic promotion failed: {}", e.getMessage());
            }
        });
    }

    /** A node brought back the primary's answer to one of this standby's probes (§13.5). */
    void probeAnswered(Message.PeerProbeAnswer a) {
        String key = HexFormat.of().formatHex(a.nonce());
        if (!probeNonces.contains(key)) {
            return;
        }
        if (Liveness.verify(hub.livenessSecret(), a.nonce(), a.epoch(), a.mac())) {
            primaryProven = true;
        } else {
            LOG.warn("a witness brought back a liveness answer that does not verify; ignored");
        }
    }
}
