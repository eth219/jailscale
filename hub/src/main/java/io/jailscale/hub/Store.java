package io.jailscale.hub;

import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

    record AuthKeyRec(String id, String hash, String owner, String tag, int usesLeft, long expiresAt) {}

    record PendingRec(String mkey, String hostname, String os, String ip, String user, long at) {}

    /** A claimed name: who owns it and which node/local target last used it (ARCHITECTURE.md §8.2). */
    record NameRec(String name, String user, String mkey, String local, long at) {}

    /** A user domain proven by a node's own certificate (ARCHITECTURE.md §8.3). */
    record DomainRec(String domain, String user, String mkey, long at) {}

    /** A raw port assigned to a node's local target (ARCHITECTURE.md §8.4); stable across restarts. */
    record PortRec(int port, String kind, String user, String mkey, String local, long at) {}

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

    private long nextNodeId = 1;
    private final Map<String, NodeRec> nodesByKey = new LinkedHashMap<>();
    private final Map<String, InviteRec> invites = new LinkedHashMap<>();
    private final Map<String, AuthKeyRec> authKeys = new LinkedHashMap<>();
    private final Set<String> admins = new LinkedHashSet<>();
    private final Map<String, PendingRec> pending = new LinkedHashMap<>();
    private final Map<String, NameRec> names = new LinkedHashMap<>();
    private final Map<String, String> settings = new LinkedHashMap<>();
    private final Map<Integer, PortRec> ports = new LinkedHashMap<>();
    private final Map<String, DomainRec> domains = new LinkedHashMap<>();
    /** mkey -> notices waiting for that node to reconnect. */
    private final Map<String, List<NoticeRec>> notices = new LinkedHashMap<>();
    /** cidr text -> ban. Small enough that a list scan per check is cheaper than an index. */
    private final Map<String, BanRec> bans = new LinkedHashMap<>();

    static final String SETTING_INVITE_POLICY = "invitePolicy";
    static final String SETTING_REGISTRATION = "registration";
    static final String SETTING_KNOCK = "knock";
    private String nextHubKey; // hkey: text of the next public key during rotation, or null
    private long hubKeyActivatesAt;

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

    synchronized List<AuthKeyRec> authKeys() {
        return new ArrayList<>(authKeys.values());
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

    synchronized PortRec port(int port) {
        return ports.get(port);
    }

    synchronized List<PortRec> ports() {
        return new ArrayList<>(ports.values());
    }

    /** The port previously assigned to this node for this kind and local target, or 0. */
    synchronized int portFor(String mkey, String kind, String local) {
        for (PortRec r : ports.values()) {
            if (r.mkey().equals(mkey) && r.kind().equals(kind) && r.local().equals(local)) {
                return r.port();
            }
        }
        return 0;
    }

    synchronized void assignPort(int port, String kind, String user, String mkey, String local) throws IOException {
        append(JsonObject.builder().put("e", "port-assigned").put("port", port).put("kind", kind).put("user", user)
            .put("mkey", mkey).put("local", local).put("at", System.currentTimeMillis()));
    }

    synchronized void releasePort(int port) throws IOException {
        if (ports.containsKey(port)) {
            append(JsonObject.builder().put("e", "port-released").put("port", port));
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

    /**
     * Checked here rather than in either caller, because there are two of them -- {@code jailhub
     * authkey create} and the /admin form -- and an auth key's uses go to the record as given,
     * unlike an invite's, where 0 is the sentinel that means "your default". A key created with
     * none left is refused by {@link #consumeAuthKey} on its first use and reported to the node as
     * {@code authkey-invalid}, days later and nowhere near the flag that caused it.
     */
    synchronized AuthKeyRec createAuthKey(String secret, String owner, String tag, int uses, long ttlSeconds) throws IOException {
        if (uses < 1) {
            throw new IllegalArgumentException("uses must be at least 1; an auth key with none left can never be redeemed");
        }
        AuthKeyRec r = new AuthKeyRec(Tokens.id("ak_"), Tokens.hash(secret), owner, tag, uses,
            System.currentTimeMillis() + ttlSeconds * 1000);
        append(JsonObject.builder().put("e", "authkey-created").put("id", r.id()).put("hash", r.hash())
            .put("owner", owner).put("tag", tag).put("uses", uses).put("expiresAt", r.expiresAt()));
        return r;
    }

    synchronized AuthKeyRec consumeAuthKey(String secret) throws IOException {
        String h = Tokens.hash(secret);
        for (AuthKeyRec r : authKeys.values()) {
            if (h.equals(r.hash())) {
                if (r.usesLeft() <= 0 || System.currentTimeMillis() > r.expiresAt()) {
                    return null;
                }
                append(JsonObject.builder().put("e", "authkey-used").put("id", r.id()));
                return r;
            }
        }
        return null;
    }

    synchronized void revokeAuthKey(String id) throws IOException {
        if (authKeys.containsKey(id)) {
            append(JsonObject.builder().put("e", "authkey-revoked").put("id", id));
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
        int n = 0;
        for (PendingRec p : pending.values()) {
            if (ip != null && ip.equals(p.ip())) {
                n++;
            }
        }
        return n;
    }

    // --- persistence -------------------------------------------------------------------------

    private void append(JsonObject.Builder b) throws IOException {
        JsonObject ev = b.build();
        byte[] line = Json.writeUtf8(ev.asMap());
        log.write(line);
        log.write('\n');
        log.flush();
        log.getFD().sync();
        apply(ev);
        if (++eventsSinceSnapshot >= SNAPSHOT_EVERY) {
            snapshot();
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
            case "authkey-created" -> authKeys.put(ev.string("id"), new AuthKeyRec(ev.string("id"), ev.string("hash"),
                ev.optString("owner", null), ev.optString("tag", null), ev.integer("uses"), ev.lng("expiresAt")));
            case "authkey-used" -> {
                AuthKeyRec r = authKeys.get(ev.string("id"));
                if (r != null) {
                    AuthKeyRec u = new AuthKeyRec(r.id(), r.hash(), r.owner(), r.tag(), r.usesLeft() - 1, r.expiresAt());
                    if (u.usesLeft() <= 0) {
                        authKeys.remove(r.id());
                    } else {
                        authKeys.put(r.id(), u);
                    }
                }
            }
            case "authkey-revoked" -> authKeys.remove(ev.string("id"));
            case "pending-added" -> pending.put(ev.string("mkey"), new PendingRec(ev.string("mkey"), ev.optString("hostname", ""),
                ev.optString("os", ""), ev.optString("ip", null), ev.optString("user", null), ev.lng("at")));
            case "pending-cleared" -> pending.remove(ev.string("mkey"));
            case "name-claimed" -> names.put(ev.string("name"), new NameRec(ev.string("name"), ev.string("user"),
                ev.optString("mkey", null), ev.optString("local", null), ev.lng("at")));
            case "name-released" -> names.remove(ev.string("name"));
            case "setting" -> settings.put(ev.string("key"), ev.string("value"));
            case "port-assigned" -> ports.put(ev.integer("port"), new PortRec(ev.integer("port"), ev.string("kind"),
                ev.string("user"), ev.string("mkey"), ev.string("local"), ev.lng("at")));
            case "port-released" -> ports.remove(ev.integer("port"));
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
     */
    static final long STATE_VERSION = 1;

    private void load() throws IOException {
        if (Files.exists(snapshotPath)) {
            JsonObject s = Json.parseObject(Files.readString(snapshotPath, StandardCharsets.UTF_8));
            long v = s.has("v") ? s.lng("v") : STATE_VERSION;
            if (v > STATE_VERSION) {
                throw new IOException(snapshotPath + " is state version " + v + ", this jailhub understands "
                    + STATE_VERSION + ". Run a newer jailhub, or restore the state directory from before the upgrade.");
            }
            nextNodeId = s.lng("nextNodeId");
            for (Object o : s.array("events")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) o;
                apply(Json.parseObject(Json.write(m)));
            }
        }
        if (Files.exists(logPath)) {
            int n = 0;
            for (String line : Files.readAllLines(logPath, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                try {
                    apply(Json.parseObject(line));
                    n++;
                } catch (RuntimeException e) {
                    LOG.warn("skipping corrupt event line: {}", e.getMessage());
                }
            }
            eventsSinceSnapshot = n;
        }
        LOG.info("loaded {} nodes, {} names, {} invites, {} auth-keys, {} admins, {} pending",
            nodesByKey.size(), names.size(), invites.size(), authKeys.size(), admins.size(), pending.size());
    }

    /**
     * Writes the whole state as a list of replayable events, atomically replaces the snapshot,
     * then truncates the log.
     */
    synchronized void snapshot() throws IOException {
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
        for (AuthKeyRec r : authKeys.values()) {
            events.add(JsonObject.builder().put("e", "authkey-created").put("id", r.id()).put("hash", r.hash())
                .put("owner", r.owner()).put("tag", r.tag()).put("uses", r.usesLeft()).put("expiresAt", r.expiresAt()).build().asMap());
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
        for (PortRec r : ports.values()) {
            events.add(JsonObject.builder().put("e", "port-assigned").put("port", r.port()).put("kind", r.kind()).put("user", r.user())
                .put("mkey", r.mkey()).put("local", r.local()).put("at", r.at()).build().asMap());
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
        String json = JsonObject.builder().put("v", STATE_VERSION).put("nextNodeId", nextNodeId).put("events", events).toJson();
        Path tmp = dir.resolve("state.snapshot.tmp");
        Files.writeString(tmp, json, StandardCharsets.UTF_8);
        try (FileOutputStream fo = new FileOutputStream(tmp.toFile(), true)) {
            fo.getFD().sync();
        }
        Files.move(tmp, snapshotPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        log.close();
        log = new FileOutputStream(logPath.toFile(), false); // truncate
        eventsSinceSnapshot = 0;
        LOG.debug("snapshot written ({} events)", events.size());
    }

    @Override
    public synchronized void close() throws IOException {
        snapshot();
        log.close();
    }
}
