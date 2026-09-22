package io.jailscale.hub;

import io.jailscale.proto.json.Json;
import io.jailscale.proto.net.NetKey;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Hub state (ARCHITECTURE.md §6.2): in-memory maps, an append-only JSON Lines event log with fsync,
 * and a periodic snapshot that truncates the log. Only {@code jailhub serve} writes here.
 *
 * <p>All public methods are synchronized; the maps are small and the hot path is elsewhere.
 */
final class Store implements AutoCloseable {

    private static final Log LOG = Log.get("store");
    private static final int SNAPSHOT_EVERY = 1000;
    /** A node that never reconnects must not grow the state without bound. */
    static final int MAX_NOTICES_PER_NODE = 20;

    record NodeRec(long id, String mkey, String user, String hostname, String os, long createdAt) {}

    /** {@code user} null means the joiner names themself. {@code admin} marks the bootstrap invite. */
    record InviteRec(String id, String tokenHash, String codeHash, String user, int usesLeft, long expiresAt,
        long codeExpiresAt, String createdBy, boolean admin) {}

    record PendingRec(String mkey, String hostname, String os, String ip, String user, long at) {}

    /** A claimed name: who owns it and which node/local target last used it (ARCHITECTURE.md §8.2). */
    record NameRec(String name, String user, String mkey, String local, long at) {}

    /** A user domain proven by a node's own certificate (ARCHITECTURE.md §8.3). */
    record DomainRec(String domain, String user, String mkey, long at) {}

    /** An address or CIDR block barred from the control plane (ARCHITECTURE.md §11.5). */
    record BanRec(String cidr, String reason, long at) {}

    /**
     * A name a node lost while it was not listening (ARCHITECTURE.md §11.4). Kept until the node
     * reconnects and is told, so the notice survives the node being offline -- which is the
     * common case, since being offline is often why the name was reassigned.
     */
    record NoticeRec(String mkey, String linkId, String name, String reason, long at) {}

    private final Path dir;
    private final Path logPath;
    private final Path snapshotPath;
    private FileOutputStream log;
    private int eventsSinceSnapshot;
    /** Who is told about every event as it is appended: the sessions replicating this store (§13.1). */
    private final List<Consumer<JsonObject>> listeners = new CopyOnWriteArrayList<>();

    private long nextNodeId = 1;
    private final Map<String, NodeRec> nodesByKey = new LinkedHashMap<>();
    private final Map<String, InviteRec> invites = new LinkedHashMap<>();
    /** {@code authkey-created} events seen on load, for the one warning that says they were dropped. */
    private int authKeyEventsDropped;

    /** How many auth-key records this load dropped (#251); a test's view of the warning above. */
    int authKeyEventsDropped() {
        return authKeyEventsDropped;
    }
    private final Set<String> admins = new LinkedHashSet<>();
    private final Map<String, PendingRec> pending = new LinkedHashMap<>();
    private final Map<String, NameRec> names = new LinkedHashMap<>();
    private final Map<String, String> settings = new LinkedHashMap<>();
    private final Map<String, DomainRec> domains = new LinkedHashMap<>();
    /** mkey -> notices waiting for that node to reconnect. */
    private final Map<String, List<NoticeRec>> notices = new LinkedHashMap<>();
    /** cidr text -> ban. Small enough that a list scan per check is cheaper than an index. */
    private final Map<String, BanRec> bans = new LinkedHashMap<>();

    static final String SETTING_INVITE_POLICY = "invitePolicy";
    static final String SETTING_REGISTRATION = "registration";
    static final String SETTING_KNOCK = "knock";
    /** §13.5: whether a standby may promote itself when no node can reach the primary. */
    static final String SETTING_AUTO_PROMOTE = "autoPromote";
    /**
     * Who runs this hub, where to write to them, and what they allow (#99). Settings and not flags:
     * they are the kind that change while a hub is running -- a contact address outlives the
     * process that first printed it -- which is the line §6.3 already draws, and being in the store
     * means a standby serves the same answer without being configured twice. Empty is the default
     * and means the page says nothing at all, so a hub somebody runs for themselves is unchanged.
     */
    static final String SETTING_OPERATOR = "operator";
    static final String SETTING_CONTACT = "contact";
    static final String SETTING_TERMS = "terms";
    private String nextHubKey; // hkey: text of the next public key during rotation, or null
    private long hubKeyActivatesAt;

    /**
     * This store's position in its own log: every appended event carries the next one as {@code s},
     * and a snapshot records the last it folded in as {@code seq}. What it is for is that
     * {@link #snapshot} cannot install the snapshot and empty the log in one step, so a crash
     * between them leaves both — and replaying a log the snapshot already counts has to be a no-op.
     * Most events are {@code put}s and are; the arithmetic ones ({@code invite-used},
     * {@code notice-added}) are not, and this is what makes them so
     * ({@code StoreCrashTest}).
     *
     * <p>Local and monotonic. A standby stamps its own rather than the primary's, because the number
     * means a place in a particular file; adopting a lower one from elsewhere would let a later
     * append land under a line already written.
     */
    private long lastSeq;

    Store(Path dir) throws IOException {
        this.dir = dir;
        this.logPath = dir.resolve("state.jsonl");
        this.snapshotPath = dir.resolve("state.snapshot");
        Files.createDirectories(dir);
        load();
        log = new FileOutputStream(logPath.toFile(), true);
    }

    // --- queries -----------------------------------------------------------------------------

    synchronized NodeRec node(String mkey) {
        return nodesByKey.get(mkey);
    }

    synchronized List<NodeRec> nodes() {
        return new ArrayList<>(nodesByKey.values());
    }

    synchronized boolean isAdmin(String user) {
        return user != null && admins.contains(user);
    }

    synchronized Set<String> admins() {
        return new LinkedHashSet<>(admins);
    }

    synchronized boolean hasAnyAdmin() {
        return !admins.isEmpty();
    }

    synchronized List<InviteRec> invites() {
        return new ArrayList<>(invites.values());
    }

    synchronized List<PendingRec> pending() {
        return new ArrayList<>(pending.values());
    }

    synchronized PendingRec pending(String mkey) {
        return pending.get(mkey);
    }

    synchronized Set<String> users() {
        Set<String> u = new LinkedHashSet<>();
        for (NodeRec n : nodesByKey.values()) {
            u.add(n.user());
        }
        return u;
    }

    /**
     * Whether a user name already means someone here: a node's user, an admin, or the owner of a
     * name or domain. Ownership outlives a node (§8.2: releasing is the operator's act), so a
     * user whose machines are all gone still exists as far as identity goes, or a stranger could
     * join under that name and inherit what it owns.
     */
    synchronized boolean userExists(String user) {
        if (user == null) {
            return false;
        }
        if (admins.contains(user)) {
            return true;
        }
        for (NodeRec n : nodesByKey.values()) {
            if (n.user().equals(user)) {
                return true;
            }
        }
        for (NameRec n : names.values()) {
            if (n.user().equals(user)) {
                return true;
            }
        }
        for (DomainRec d : domains.values()) {
            if (d.user().equals(user)) {
                return true;
            }
        }
        return false;
    }

    synchronized String nextHubKey() {
        return nextHubKey;
    }

    synchronized String nameOwner(String name) {
        NameRec r = names.get(name);
        return r == null ? null : r.user();
    }

    /** The random name previously given to this node for this local target, or null. */
    synchronized String nameFor(String mkey, String local) {
        for (NameRec r : names.values()) {
            if (mkey.equals(r.mkey()) && local != null && local.equals(r.local())) {
                return r.name();
            }
        }
        return null;
    }

    synchronized NameRec name(String name) {
        return names.get(name);
    }

    synchronized List<NameRec> names() {
        return new ArrayList<>(names.values());
    }

    synchronized DomainRec domain(String domain) {
        return domains.get(domain);
    }

    synchronized List<DomainRec> domains() {
        return new ArrayList<>(domains.values());
    }

    synchronized void claimDomain(String domain, String user, String mkey) throws IOException {
        DomainRec r = domains.get(domain);
        if (r == null || !r.user().equals(user) || !r.mkey().equals(mkey)) {
            append(JsonObject.builder().put("e", "domain-claimed").put("domain", domain).put("user", user).put("mkey", mkey)
                .put("at", System.currentTimeMillis()));
        }
    }

    synchronized void releaseDomain(String domain) throws IOException {
        if (domains.containsKey(domain)) {
            append(JsonObject.builder().put("e", "domain-released").put("domain", domain));
        }
    }

    synchronized void claimName(String name, String user, String mkey, String local) throws IOException {
        append(JsonObject.builder().put("e", "name-claimed").put("name", name).put("user", user).put("mkey", mkey)
            .put("local", local).put("at", System.currentTimeMillis()));
    }

    synchronized void releaseName(String name) throws IOException {
        if (names.containsKey(name)) {
            append(JsonObject.builder().put("e", "name-released").put("name", name));
        }
    }

    synchronized List<BanRec> bans() {
        return List.copyOf(bans.values());
    }

    /** Bars an address or block. Overwrites an existing entry with the same text. */
    synchronized void addBan(String cidr, String reason) throws IOException {
        append(JsonObject.builder().put("e", "ban-added").put("cidr", cidr).put("reason", reason)
            .put("at", System.currentTimeMillis()));
    }

    synchronized void removeBan(String cidr) throws IOException {
        if (bans.containsKey(cidr)) {
            append(JsonObject.builder().put("e", "ban-removed").put("cidr", cidr));
        }
    }

    /** Notices waiting for this node, oldest first. Empty when there are none. */
    synchronized List<NoticeRec> notices(String mkey) {
        List<NoticeRec> l = notices.get(mkey);
        return l == null ? List.of() : List.copyOf(l);
    }

    synchronized int noticeCount() {
        int n = 0;
        for (List<NoticeRec> l : notices.values()) {
            n += l.size();
        }
        return n;
    }

    /** Remembers that {@code mkey} lost {@code name}, to tell it when it next connects. */
    synchronized void addNotice(String mkey, String linkId, String name, String reason) throws IOException {
        append(JsonObject.builder().put("e", "notice-added").put("mkey", mkey).put("linkId", linkId)
            .put("name", name).put("reason", reason).put("at", System.currentTimeMillis()));
    }

    /** Drops every notice for this node, after they have been delivered. */
    synchronized void clearNotices(String mkey) throws IOException {
        if (notices.containsKey(mkey)) {
            append(JsonObject.builder().put("e", "notices-cleared").put("mkey", mkey));
        }
    }

    synchronized void reassignName(String name, String user) throws IOException {
        NameRec r = names.get(name);
        if (r != null) {
            append(JsonObject.builder().put("e", "name-claimed").put("name", name).put("user", user).put("mkey", r.mkey())
                .put("local", r.local()).put("at", System.currentTimeMillis()));
        }
    }

    synchronized long hubKeyActivatesAt() {
        return hubKeyActivatesAt;
    }

    synchronized String setting(String key, String dflt) {
        return settings.getOrDefault(key, dflt);
    }

    synchronized boolean hasSetting(String key) {
        return settings.containsKey(key);
    }

    synchronized void setSetting(String key, String value) throws IOException {
        if (!value.equals(settings.get(key))) {
            append(JsonObject.builder().put("e", "setting").put("key", key).put("value", value));
        }
    }

    // --- mutations (each appends one event) --------------------------------------------------

    synchronized NodeRec registerNode(String mkey, String user, String hostname, String os) throws IOException {
        NodeRec existing = nodesByKey.get(mkey);
        if (existing != null) {
            return existing;
        }
        NodeRec n = new NodeRec(nextNodeId, mkey, user, hostname, os, System.currentTimeMillis());
        append(JsonObject.builder().put("e", "node-registered").put("id", n.id()).put("mkey", mkey)
            .put("user", user).put("hostname", hostname).put("os", os).put("at", n.createdAt()));
        return n;
    }

    synchronized void removeNode(String mkey) throws IOException {
        if (nodesByKey.containsKey(mkey)) {
            append(JsonObject.builder().put("e", "node-removed").put("mkey", mkey));
        }
    }

    synchronized void renameNode(String mkey, String user) throws IOException {
        if (nodesByKey.containsKey(mkey)) {
            append(JsonObject.builder().put("e", "node-renamed").put("mkey", mkey).put("user", user));
        }
    }

    synchronized void addAdmin(String user) throws IOException {
        if (!admins.contains(user)) {
            append(JsonObject.builder().put("e", "admin-added").put("user", user));
        }
    }

    synchronized void removeAdmin(String user) throws IOException {
        if (admins.contains(user)) {
            append(JsonObject.builder().put("e", "admin-removed").put("user", user));
        }
    }

    synchronized InviteRec createInvite(String token, String code, String user, int uses, long ttlSeconds,
        long codeTtlSeconds, String createdBy, boolean admin) throws IOException {
        long now = System.currentTimeMillis();
        InviteRec r = new InviteRec(Tokens.id("inv_"), Tokens.hash(token), code == null ? null : Tokens.hash(code),
            user, uses, now + ttlSeconds * 1000, code == null ? 0 : now + codeTtlSeconds * 1000, createdBy, admin);
        append(JsonObject.builder().put("e", "invite-created").put("id", r.id()).put("tokenHash", r.tokenHash())
            .put("codeHash", r.codeHash()).put("user", user).put("uses", uses).put("expiresAt", r.expiresAt())
            .put("codeExpiresAt", r.codeExpiresAt()).put("createdBy", createdBy).put("admin", admin));
        return r;
    }

    /** Consumes one use of the invite matching {@code token}; null if unknown, spent or expired. */
    synchronized InviteRec consumeInvite(String token) throws IOException {
        return consume(Tokens.hash(token), false);
    }

    /** Same for a short code (already normalised). */
    synchronized InviteRec consumeCode(String code) throws IOException {
        return consume(Tokens.hash(code), true);
    }

    private InviteRec consume(String hash, boolean byCode) throws IOException {
        long now = System.currentTimeMillis();
        for (InviteRec r : invites.values()) {
            boolean match = byCode ? hash.equals(r.codeHash()) : hash.equals(r.tokenHash());
            if (!match) {
                continue;
            }
            long exp = byCode ? Math.min(r.expiresAt(), r.codeExpiresAt()) : r.expiresAt();
            if (r.usesLeft() <= 0 || now > exp) {
                return null;
            }
            append(JsonObject.builder().put("e", "invite-used").put("id", r.id()));
            return r; // the pre-decrement record; usesLeft is informational to the caller
        }
        return null;
    }

    synchronized void revokeInvite(String id) throws IOException {
        if (invites.containsKey(id)) {
            append(JsonObject.builder().put("e", "invite-revoked").put("id", id));
        }
    }

    synchronized void addPending(String mkey, String hostname, String os, String ip, String user) throws IOException {
        append(JsonObject.builder().put("e", "pending-added").put("mkey", mkey).put("hostname", hostname)
            .put("os", os).put("ip", ip).put("user", user).put("at", System.currentTimeMillis()));
    }

    synchronized void clearPending(String mkey) throws IOException {
        if (pending.containsKey(mkey)) {
            append(JsonObject.builder().put("e", "pending-cleared").put("mkey", mkey));
        }
    }

    synchronized void setHubKeyRotation(String nextHubKeyText, long activatesAt) throws IOException {
        append(JsonObject.builder().put("e", "hubkey-rotation").put("next", nextHubKeyText).put("activatesAt", activatesAt));
    }

    synchronized void clearHubKeyRotation() throws IOException {
        if (nextHubKey != null) {
            append(JsonObject.builder().put("e", "hubkey-rotated"));
        }
    }

    synchronized int pendingCountFrom(String ip) {
        if (ip == null) {
            return 0;
        }
        // Per network, as the other bounds of §11.5 are: in v6 an address costs nothing, so counted
        // per address this bound is five knocks times as many addresses as a /64 holds -- and a
        // knock is the one of those bounds whose overflow is written to disk and outlives the
        // process. The stored ip stays the address, which is what an operator is shown.
        String key = NetKey.of(ip);
        int n = 0;
        for (PendingRec p : pending.values()) {
            // The cheap test first: for a v4 record the key IS the address, so the whole v4 case
            // never parses anything. Without it every knock re-parsed every stored address inside
            // this monitor -- the scan-on-every-call shape RateLimiter had just been cured of, on a
            // map an unauthenticated caller grows and nothing prunes.
            if (p.ip() != null && (key.equals(p.ip()) || key.equals(NetKey.of(p.ip())))) {
                n++;
            }
        }
        return n;
    }

    // --- persistence -------------------------------------------------------------------------

    private void append(JsonObject.Builder b) throws IOException {
        append(b.build());
    }

    private void append(JsonObject ev) throws IOException {
        // Stamped as it goes to disk and not before, so the event the listeners forward to a
        // standby (§13.1) is the same bytes it has always been: a sequence number is this store's
        // position in this store's log, and the standby stamps its own when it appends it there.
        Map<String, Object> stamped = new LinkedHashMap<>(ev.asMap());
        stamped.put("s", ++lastSeq);
        byte[] line = Json.writeUtf8(stamped);
        log.write(line);
        log.write('\n');
        log.flush();
        log.getFD().sync();
        apply(ev);
        for (Consumer<JsonObject> l : listeners) {
            l.accept(ev);
        }
        if (++eventsSinceSnapshot >= SNAPSHOT_EVERY) {
            snapshot();
        }
    }

    // --- replication (ARCHITECTURE.md §13.1) ---------------------------------------------------

    /**
     * Starts telling {@code listener} about every event from here on and returns the state as it
     * stands at that moment, as snapshot JSON. The two happen under one lock so that nothing is
     * appended between the snapshot being taken and the listener being registered: a standby that
     * replays the snapshot and then the events sees exactly what this store saw.
     */
    synchronized String subscribe(Consumer<JsonObject> listener) {
        listeners.add(listener);
        return snapshotJson();
    }

    synchronized void unsubscribe(Consumer<JsonObject> listener) {
        listeners.remove(listener);
    }

    /** An event replicated from the primary: written to this log and applied, as if appended here. */
    synchronized void applyReplicated(JsonObject ev) throws IOException {
        append(ev);
    }

    /**
     * What this store held that the primary's state does not, and is about to lose
     * (ARCHITECTURE.md §13.5). Counts for everything, names for the things a person holds.
     */
    record Superseded(List<String> nodes, List<String> names, List<String> domains,
        int credentials, Path kept) {
        // `kept`: where the copy of what went is, or null when there is no copy -- nothing was lost,
        // or the write failed. Nothing may send an operator to a path that was not written.

        boolean any() {
            return !nodes.isEmpty() || !names.isEmpty() || !domains.isEmpty() || credentials > 0;
        }

        /** How many of each are named before the line gives up and quotes a count instead. */
        private static final int SHOWN = 20;

        /**
         * Only what there is, and never more than {@link #SHOWN} of it: this is written on the one
         * path taken while a hub is recovering from a partition, and a host whose state has fully
         * diverged would otherwise put every name it holds into a single line -- thousands of them,
         * built inside the store's monitor. What is cut is not lost; {@link #kept} names the file
         * that has all of it.
         */
        @Override
        public String toString() {
            StringBuilder b = new StringBuilder();
            append(b, "nodes", nodes);
            append(b, "names", names);
            append(b, "domains", domains);
            if (credentials > 0) {
                b.append(b.length() == 0 ? "" : ", ").append(credentials).append(" unused invites");
            }
            return b.length() == 0 ? "nothing" : b.toString();
        }

        private static void append(StringBuilder b, String what, List<?> items) {
            if (items.isEmpty()) {
                return;
            }
            b.append(b.length() == 0 ? "" : ", ").append(what).append(' ')
                .append(items.size() <= SHOWN ? items.toString()
                    : items.subList(0, SHOWN) + " and " + (items.size() - SHOWN) + " more");
        }
    }

    /**
     * Throws away everything held and replaces it with {@code snapshotJson} from the primary,
     * persisting it as this store's own snapshot and truncating the log. The version check is the
     * one {@link #load} makes: a standby running an older binary than its primary must stop rather
     * than replay state it cannot read.
     *
     * <p><b>Whatever this host held and the primary does not is gone, and that is the whole of the
     * reconciliation (§13.5).</b> There is no merge here and there cannot be a cheap one: the two
     * stores share no lineage a write can be placed in, so nothing can say whether a name this host
     * holds is one the other has never seen or one it deliberately released. The primary's state
     * wins entire, which is what a lease with an epoch buys and the whole of what it buys.
     *
     * <p>What that costs is normally nothing -- a standby's state came from this same primary -- and
     * it is not nothing after a partition in which this host was itself a primary: a node that joined
     * here, or a name claimed here, exists nowhere afterwards, and the node finds out by being an
     * unknown machine key the next time it connects. So it is <b>reported and kept</b> rather than
     * silently dropped: the returned record names what went, and the state as it stood is written to
     * {@code state.superseded.snapshot} beside the live one, from which an operator can read the
     * records back. That file is overwritten by the next one, so it is a recovery for the event that
     * has just been logged and not an archive.
     */
    synchronized Superseded replaceWith(String snapshotJson) throws IOException {
        JsonObject s = Json.parseObject(snapshotJson);
        checkVersion(s, "the primary's state");
        Superseded lost = supersededBy(s);
        nodesByKey.clear();
        invites.clear();
        admins.clear();
        pending.clear();
        names.clear();
        settings.clear();
        domains.clear();
        notices.clear();
        bans.clear();
        nextHubKey = null;
        hubKeyActivatesAt = 0;
        nextNodeId = 1;
        loadSnapshot(s);
        snapshot();
        return lost;
    }

    /**
     * What the incoming state does not have, worked out before anything is cleared. The copy is
     * written first, so a hub that dies during the replacement has still kept what it was about to
     * drop; when nothing would be dropped, nothing is written and no file is left to mislead.
     */
    private Superseded supersededBy(JsonObject incoming) {
        Store theirs = new Store();
        theirs.loadSnapshot(incoming);
        // By record and not by key. A key comparison only sees what vanished, so a name released
        // here and re-claimed by somebody else, a port reassigned, a domain taken over or a node
        // re-approved under another user all came out as "nothing lost" -- the record changed
        // owner, and the owner is the whole of what these hold.
        // By owner, not by whole record and not by key alone. A key comparison sees only what
        // vanished, so a name released here and re-claimed by somebody else -- or a port reassigned,
        // a domain taken over, a node re-approved under another user -- read as "nothing lost", and
        // the owner is the whole of what these records hold. Whole-record equality is the other
        // error: NodeRec carries an id counted per store and every one of these carries a local
        // timestamp, so two stores that agree completely would differ in all of them.
        List<String> lostNodes = new ArrayList<>();
        for (NodeRec n : nodesByKey.values()) {
            NodeRec t = theirs.nodesByKey.get(n.mkey());
            if (t == null || !t.user().equals(n.user())) {
                lostNodes.add(n.user() + "/" + n.hostname());
            }
        }
        List<String> lostNames = new ArrayList<>();
        for (NameRec r : names.values()) {
            NameRec t = theirs.names.get(r.name());
            if (t == null || !t.user().equals(r.user())) {
                lostNames.add(r.name());
            }
        }
        List<String> lostDomains = new ArrayList<>();
        for (DomainRec r : domains.values()) {
            DomainRec t = theirs.domains.get(r.domain());
            if (t == null || !t.user().equals(r.user())) {
                lostDomains.add(r.domain());
            }
        }
        int credentials = 0;
        for (String id : invites.keySet()) {
            credentials += theirs.invites.containsKey(id) ? 0 : 1;
        }
        // And the collections replaceWith clears that nothing compared: an admin added and a CIDR
        // banned on the losing side of a partition are rights granted and rights taken away, which
        // is the last thing that should go without a word.
        List<String> lostAdmins = new ArrayList<>(admins);
        lostAdmins.removeAll(theirs.admins);
        for (String a : lostAdmins) {
            lostNodes.add("admin " + a);
        }
        for (BanRec b : bans.values()) {
            if (!theirs.bans.containsKey(b.cidr())) {
                lostNames.add("ban " + b.cidr());
            }
        }
        for (Map.Entry<String, String> e : settings.entrySet()) {
            if (!e.getValue().equals(theirs.settings.get(e.getKey()))) {
                lostNames.add("setting " + e.getKey());
            }
        }
        if (nextHubKey != null && !nextHubKey.equals(theirs.nextHubKey())) {
            lostNames.add("hub-key rotation");
        }
        Path keptAt = dir.resolve("state.superseded.snapshot");
        Superseded lost = new Superseded(lostNodes, lostNames, lostDomains, credentials, null);
        if (!lost.any()) {
            // Nothing to keep, so nothing may be left lying at that path: a copy from an earlier
            // hand-off beside a fresh state.snapshot reads as "what this host just lost".
            try {
                Files.deleteIfExists(keptAt);
            } catch (IOException e) {
                LOG.debug("could not remove a stale {}: {}", keptAt, e.toString());
            }
            return lost;
        }
        try {
            // Through a temporary and renamed, as snapshot() does and for the same reason: written
            // in place, a kill part-way leaves a truncated file where the previous incident's good
            // copy used to be, so the crash this exists to survive is the crash that destroys it.
            Path tmp = dir.resolve("state.superseded.tmp");
            Files.writeString(tmp, snapshotJson(), StandardCharsets.UTF_8);
            try (FileOutputStream fo = new FileOutputStream(tmp.toFile(), true)) {
                fo.getFD().sync();
            }
            Files.move(tmp, keptAt, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            syncDir();
        } catch (IOException e) {
            // Best effort, for the reason syncDir() gives: this file exists to be read by a person,
            // and a state directory that is full or read-only must not be able to stop a standby
            // following its primary. `kept` is null from here, because a path that was not written
            // is worse than no path: a copy from an earlier hand-off may be sitting at it, and
            // whoever the line below sends there would read another incident's losses as this one's.
            LOG.warn("could not keep the superseded state at {}: {}", keptAt, e.toString());
            return lost;
        }
        return new Superseded(lostNodes, lostNames, lostDomains, credentials, keptAt);
    }

    /** An empty store with no directory behind it: somewhere to replay another's snapshot and compare. */
    private Store() {
        this.dir = null;
        this.logPath = null;
        this.snapshotPath = null;
    }

    private void checkVersion(JsonObject s, String what) throws IOException {
        long v = s.has("v") ? s.lng("v") : STATE_VERSION;
        if (v > STATE_VERSION) {
            throw new IOException(what + " is state version " + v + ", this jailhub understands "
                + STATE_VERSION + ". Run a newer jailhub, or restore the state directory from before the upgrade.");
        }
    }

    private void loadSnapshot(JsonObject s) {
        nextNodeId = s.lng("nextNodeId");
        for (Object o : s.array("events")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) o;
            apply(JsonObject.of(m));
        }
    }

    private void apply(JsonObject ev) {
        String e = ev.string("e");
        switch (e) {
            case "node-registered" -> {
                NodeRec n = new NodeRec(ev.lng("id"), ev.string("mkey"), ev.string("user"), ev.optString("hostname", ""),
                    ev.optString("os", ""), ev.lng("at"));
                nodesByKey.put(n.mkey(), n);
                nextNodeId = Math.max(nextNodeId, n.id() + 1);
                pending.remove(n.mkey());
            }
            case "node-removed" -> nodesByKey.remove(ev.string("mkey"));
            case "node-renamed" -> {
                NodeRec n = nodesByKey.get(ev.string("mkey"));
                if (n != null) {
                    nodesByKey.put(n.mkey(), new NodeRec(n.id(), n.mkey(), ev.string("user"), n.hostname(), n.os(), n.createdAt()));
                }
            }
            case "admin-added" -> admins.add(ev.string("user"));
            case "admin-removed" -> admins.remove(ev.string("user"));
            case "invite-created" -> invites.put(ev.string("id"), new InviteRec(ev.string("id"), ev.string("tokenHash"),
                ev.optString("codeHash", null), ev.optString("user", null), ev.integer("uses"), ev.lng("expiresAt"),
                ev.has("codeExpiresAt") ? ev.lng("codeExpiresAt") : 0, ev.optString("createdBy", null), ev.optBool("admin", false)));
            case "invite-used" -> {
                InviteRec r = invites.get(ev.string("id"));
                if (r != null) {
                    InviteRec u = new InviteRec(r.id(), r.tokenHash(), r.codeHash(), r.user(), r.usesLeft() - 1, r.expiresAt(),
                        r.codeExpiresAt(), r.createdBy(), r.admin());
                    if (u.usesLeft() <= 0) {
                        invites.remove(r.id());
                    } else {
                        invites.put(r.id(), u);
                    }
                }
            }
            case "invite-revoked" -> invites.remove(ev.string("id"));
            // Auth-keys were removed (#251). A log written before that carries their events; they
            // are not unknown, so they are counted rather than warned about one by one, and load()
            // says once what was dropped, because the next snapshot this binary writes will not
            // carry them and a rollback would find them gone.
            case "authkey-created" -> authKeyEventsDropped++;
            case "authkey-used", "authkey-revoked" -> { }
            case "pending-added" -> pending.put(ev.string("mkey"), new PendingRec(ev.string("mkey"), ev.optString("hostname", ""),
                ev.optString("os", ""), ev.optString("ip", null), ev.optString("user", null), ev.lng("at")));
            case "pending-cleared" -> pending.remove(ev.string("mkey"));
            case "name-claimed" -> names.put(ev.string("name"), new NameRec(ev.string("name"), ev.string("user"),
                ev.optString("mkey", null), ev.optString("local", null), ev.lng("at")));
            case "name-released" -> names.remove(ev.string("name"));
            case "setting" -> settings.put(ev.string("key"), ev.string("value"));
            // Raw TCP and UDP ports were removed (§8.4). A log written by an older hub still has
            // these in it, and dropping them on read is what lets that hub's state load at all --
            // an unknown event is a refusal below, which would make the upgrade a manual edit.
            case "port-assigned", "port-released" -> { }
            case "domain-claimed" -> domains.put(ev.string("domain"), new DomainRec(ev.string("domain"), ev.string("user"),
                ev.string("mkey"), ev.lng("at")));
            case "domain-released" -> domains.remove(ev.string("domain"));
            case "notice-added" -> {
                List<NoticeRec> l = notices.computeIfAbsent(ev.string("mkey"), k -> new ArrayList<>());
                NoticeRec r = new NoticeRec(ev.string("mkey"), ev.optString("linkId", null), ev.string("name"),
                    ev.string("reason"), ev.lng("at"));
                if (l.size() >= MAX_NOTICES_PER_NODE) {
                    l.remove(0); // a node that never comes back must not grow the state without bound
                }
                l.add(r);
            }
            case "notices-cleared" -> notices.remove(ev.string("mkey"));
            case "ban-added" -> bans.put(ev.string("cidr"),
                new BanRec(ev.string("cidr"), ev.optString("reason", null), ev.lng("at")));
            case "ban-removed" -> bans.remove(ev.string("cidr"));
            case "hubkey-rotation" -> {
                nextHubKey = ev.string("next");
                hubKeyActivatesAt = ev.lng("activatesAt");
            }
            case "hubkey-rotated" -> {
                nextHubKey = null;
                hubKeyActivatesAt = 0;
            }
            default -> LOG.warn("unknown event '{}' ignored", e);
        }
    }

    /**
     * The state format this binary understands. Snapshots have always carried it; nothing read it
     * back, so an older binary would have replayed a newer snapshot as if it were its own and
     * quietly dropped whatever it did not recognise. Refuse instead: a hub that cannot read its
     * state should say so, not start with a subset of it.
     *
     * <p>Adding a field or a new event within a version stays compatible in both directions --
     * {@link #apply} already ignores an unknown event with a warning. Bump this only when an old
     * binary would get the meaning of existing data wrong.
     *
     * <p><b>{@link #lastSeq}'s {@code s} and {@code seq} were added without a bump, and the rule
     * above is why.</b> An older binary ignores both and replays the whole log, which is what it
     * does with its own state today: it re-applies events a snapshot already holds in the window
     * this exists to close. That is the defect being fixed, not a new misreading of these bytes, so
     * a rollback is no worse off than it was -- and it is only reachable in the same crash window.
     * The other direction is a state written before the fields existed, where a missing {@code seq}
     * reads as zero, nothing is skipped, and the behaviour is exactly the old one until the first
     * snapshot this binary writes.
     */
    static final long STATE_VERSION = 1;

    private void load() throws IOException {
        long foldedThrough = 0;
        if (Files.exists(snapshotPath)) {
            JsonObject s = Json.parseObject(Files.readString(snapshotPath, StandardCharsets.UTF_8));
            checkVersion(s, snapshotPath.toString());
            loadSnapshot(s);
            foldedThrough = s.has("seq") ? s.lng("seq") : 0;
            // And carry on from there rather than from zero. Read here and not in loadSnapshot,
            // which a standby shares (§13.1): the number is a place in *this* log, so a standby
            // adopting the primary's would start writing lines under ones it has already written.
            lastSeq = foldedThrough;
        }
        if (Files.exists(logPath)) {
            int n = 0;
            int folded = 0;
            for (String line : Files.readAllLines(logPath, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                try {
                    JsonObject ev = Json.parseObject(line);
                    // Already in the snapshot above: the truncation that should have removed this
                    // line did not reach the disk, and applying it a second time would spend an
                    // invite use or repeat a notice. Zero is a line written before this field
                    // existed, or a snapshot from then, and both mean the old behaviour -- replay
                    // everything -- which is what those bytes were written expecting.
                    long seq = ev.has("s") ? ev.lng("s") : 0;
                    if (seq != 0 && seq <= foldedThrough) {
                        folded++;
                        continue;
                    }
                    apply(ev);
                    lastSeq = Math.max(lastSeq, seq);
                    n++;
                } catch (RuntimeException e) {
                    LOG.warn("skipping corrupt event line: {}", e.getMessage());
                }
            }
            // Skipped lines count too: they are still in the file, so the next snapshot has to be
            // scheduled by them or the dead prefix survives until a thousand fresh events arrive and
            // every restart until then re-reads it and re-reports a crash that is long over.
            eventsSinceSnapshot = n + folded;
            if (folded > 0) {
                // Worth a line: it says the last run did not shut down between its snapshot and the
                // truncation that follows it, which is a crash and not a stop.
                LOG.info("{} log events were already in the snapshot and were not replayed", folded);
            }
        }
        LOG.info("loaded {} nodes, {} names, {} invites, {} admins, {} pending",
            nodesByKey.size(), names.size(), invites.size(), admins.size(), pending.size());
        if (authKeyEventsDropped > 0) {
            LOG.warn("{} auth-key records in this state were dropped: auth-keys were removed in #251, and the next"
                + " snapshot will not carry them. A machine that had not yet joined with one needs an invite instead",
                authKeyEventsDropped);
        }
    }

    /**
     * Writes the whole state as a list of replayable events, atomically replaces the snapshot,
     * then truncates the log.
     */
    synchronized void snapshot() throws IOException {
        String json = snapshotJson();
        Path tmp = dir.resolve("state.snapshot.tmp");
        Files.writeString(tmp, json, StandardCharsets.UTF_8);
        try (FileOutputStream fo = new FileOutputStream(tmp.toFile(), true)) {
            fo.getFD().sync();
        }
        Files.move(tmp, snapshotPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        syncDir();
        log.close();
        log = new FileOutputStream(logPath.toFile(), false); // truncate
        eventsSinceSnapshot = 0;
        LOG.debug("snapshot written");
    }

    /**
     * Forces the directory entry, so that the rename above is on disk before the truncation below
     * can be. Without it the two are independent and the filesystem may commit them in either
     * order: a machine that lost power having durably emptied the log but not durably installed the
     * snapshot would come back missing every event since the one before. {@link #lastSeq} makes the
     * other order harmless; this is what keeps this one from happening.
     *
     * <p>Best effort, and it has to be. A directory cannot be opened as a file on Windows, which
     * throws here, and there the ordering is left to the filesystem — as it was everywhere until
     * this existed. Failing a snapshot over it would be the worse trade: the state it has just
     * written is good, and refusing to go on would take the hub down over a durability hint.
     */
    private void syncDir() {
        try (FileChannel c = FileChannel.open(dir, StandardOpenOption.READ)) {
            c.force(true);
        } catch (IOException | UnsupportedOperationException e) {
            LOG.debug("cannot fsync the state directory: {}", e.toString());
        }
    }

    /** The whole state as the snapshot file's JSON: a version, the next node id, and replayable events. */
    synchronized String snapshotJson() {
        List<Object> events = new ArrayList<>();
        for (NodeRec n : nodesByKey.values()) {
            events.add(JsonObject.builder().put("e", "node-registered").put("id", n.id()).put("mkey", n.mkey())
                .put("user", n.user()).put("hostname", n.hostname()).put("os", n.os()).put("at", n.createdAt()).build().asMap());
        }
        for (String a : admins) {
            events.add(JsonObject.builder().put("e", "admin-added").put("user", a).build().asMap());
        }
        for (InviteRec r : invites.values()) {
            events.add(JsonObject.builder().put("e", "invite-created").put("id", r.id()).put("tokenHash", r.tokenHash())
                .put("codeHash", r.codeHash()).put("user", r.user()).put("uses", r.usesLeft()).put("expiresAt", r.expiresAt())
                .put("codeExpiresAt", r.codeExpiresAt()).put("createdBy", r.createdBy()).put("admin", r.admin()).build().asMap());
        }
        for (PendingRec p : pending.values()) {
            events.add(JsonObject.builder().put("e", "pending-added").put("mkey", p.mkey()).put("hostname", p.hostname())
                .put("os", p.os()).put("ip", p.ip()).put("user", p.user()).put("at", p.at()).build().asMap());
        }
        for (NameRec r : names.values()) {
            events.add(JsonObject.builder().put("e", "name-claimed").put("name", r.name()).put("user", r.user())
                .put("mkey", r.mkey()).put("local", r.local()).put("at", r.at()).build().asMap());
        }
        for (DomainRec r : domains.values()) {
            events.add(JsonObject.builder().put("e", "domain-claimed").put("domain", r.domain()).put("user", r.user())
                .put("mkey", r.mkey()).put("at", r.at()).build().asMap());
        }
        for (List<NoticeRec> l : notices.values()) {
            for (NoticeRec r : l) {
                events.add(JsonObject.builder().put("e", "notice-added").put("mkey", r.mkey()).put("linkId", r.linkId())
                    .put("name", r.name()).put("reason", r.reason()).put("at", r.at()).build().asMap());
            }
        }
        for (BanRec b : bans.values()) {
            events.add(JsonObject.builder().put("e", "ban-added").put("cidr", b.cidr())
                .put("reason", b.reason()).put("at", b.at()).build().asMap());
        }
        for (Map.Entry<String, String> e : settings.entrySet()) {
            events.add(JsonObject.builder().put("e", "setting").put("key", e.getKey()).put("value", e.getValue()).build().asMap());
        }
        if (nextHubKey != null) {
            events.add(JsonObject.builder().put("e", "hubkey-rotation").put("next", nextHubKey).put("activatesAt", hubKeyActivatesAt).build().asMap());
        }
        // `seq` is how far into the log this snapshot reaches, so a log that outlives its own
        // truncation can be replayed without counting anything twice (see lastSeq).
        return JsonObject.builder().put("v", STATE_VERSION).put("nextNodeId", nextNodeId)
            .put("seq", lastSeq).put("events", events).toJson();
    }

    @Override
    public synchronized void close() throws IOException {
        snapshot();
        log.close();
    }
}
