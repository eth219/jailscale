package io.jailscale.node;

import io.jailscale.crypto.KeyText;
import io.jailscale.crypto.X25519;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;

/** {@code node.json}: the MachineKey, the hub we belong to, and our registration (ARCHITECTURE.md §4). */
final class NodeState {

    private static final Log LOG = Log.get("state");

    static final String PRIVATE_PREFIX = "mkeypriv";

    private final Path file;

    X25519.Keypair machineKey;
    String hubHost;
    String hubAddr;       // connect here instead of resolving hubHost (tests, split horizon); null = resolve
    int hubPort = 443;
    String hubKey;        // pinned hkey: text
    String nextHubKey;    // announced rotation, or null
    long hubKeyActivatesAt;
    String caFile;        // trust exactly this PEM instead of system roots (tests, private CAs)
    boolean tlsInsecure;  // only with a pinned hub key
    int connections = 1;  // connections to the hub (ARCHITECTURE.md §5.3), 1..4
    boolean registered;
    long nodeId;
    String user;
    String dnsSuffix;
    final java.util.List<LinkRec> links = new java.util.concurrent.CopyOnWriteArrayList<>();
    /** Names the hub said are no longer ours (ARCHITECTURE.md §11.4). Kept so `status` can repeat it. */
    final java.util.List<RevokedRec> revoked = new java.util.concurrent.CopyOnWriteArrayList<>();

    /** One revocation the hub reported. Survives a restart, and is cleared by reopening the name. */
    record RevokedRec(String name, String reason, long at) {}

    /** A link this node keeps open (ARCHITECTURE.md §9.1). {@code linkId}/{@code url} are per hub session. */
    static final class LinkRec {
        final String kind;
        final String host;
        final int port;
        volatile String name;   // assigned by the hub; requested on reopen so it stays stable
        volatile String linkId;
        volatile String url;
        volatile String gateHash;      // visitor gate (ARCHITECTURE.md §9.3): SHA-256 of the visit token, or null
        volatile long gateExpiresAt;   // ms epoch; 0 = never
        volatile int hubPort;          // raw tcp/udp: the hub port assigned last time (requested again on reopen)
        volatile String domain;        // user domain (ARCHITECTURE.md §8.3), or null
        volatile String acmeDirectory; // ACME directory used for the domain, or null for Let's Encrypt
        volatile String acmeEmail;
        volatile long certExpiresAt;   // not persisted: from the loaded certificate
        volatile ProbeResult lastProbe; // not persisted: the last self-probe of this name (§11.3)
        volatile long certWarnedAt;    // not persisted: when the expiry warning was last logged
        volatile boolean proxyProtocol; // prepend a PROXY v1 line for the local app (ARCHITECTURE.md §9.3)
        /** Not persisted: the link id each relay host gave this link (§13.4), by relay address. */
        final java.util.Map<String, String> relayLinkIds = new java.util.concurrent.ConcurrentHashMap<>();

        LinkRec(String kind, String host, int port, String name) {
            this.kind = kind;
            this.host = host;
            this.port = port;
            this.name = name;
        }

        String host() {
            return host;
        }

        int port() {
            return port;
        }

        String local() {
            return host + ":" + port;
        }
    }

    LinkRec linkById(String linkId) {
        if (linkId == null) {
            return null;
        }
        for (LinkRec l : links) {
            // The id the primary gave, or the one a relay host gave the same link (§13.4): a
            // visitor stream carries whichever host delivered it.
            if (linkId.equals(l.linkId) || l.relayLinkIds.containsValue(linkId)) {
                return l;
            }
        }
        return null;
    }

    LinkRec linkByName(String name) {
        for (LinkRec l : links) {
            if (name.equals(l.name)) {
                return l;
            }
        }
        return null;
    }

    private NodeState(Path file) {
        this.file = file;
    }

    static NodeState load(Path file) throws IOException {
        NodeState s = new NodeState(file);
        if (Files.exists(file)) {
            JsonObject o = Json.parseObject(Files.readString(file, StandardCharsets.UTF_8));
            byte[] priv = KeyText.parse(PRIVATE_PREFIX, o.string("machineKey"));
            s.machineKey = new X25519.Keypair(priv, X25519.publicKey(priv));
            if (o.has("hub")) {
                JsonObject h = o.object("hub");
                s.hubHost = h.optString("host", null);
                s.hubAddr = h.optString("addr", null);
                s.hubPort = h.optInt("port", 443);
                s.hubKey = h.optString("hubKey", null);
                s.nextHubKey = h.optString("nextHubKey", null);
                s.hubKeyActivatesAt = h.has("activatesAt") ? h.lng("activatesAt") : 0;
                s.caFile = h.optString("caFile", null);
                s.tlsInsecure = h.optBool("tlsInsecure", false);
                s.connections = h.optInt("connections", 1);
                s.dnsSuffix = h.optString("dnsSuffix", null);
            }
            s.registered = o.optBool("registered", false);
            s.nodeId = o.has("nodeId") ? o.lng("nodeId") : 0;
            s.user = o.optString("user", null);
            if (o.has("links")) {
                for (Object l : o.array("links")) {
                    @SuppressWarnings("unchecked")
                    JsonObject lo = Json.parseObject(Json.write((java.util.Map<String, Object>) l));
                    LinkRec rec = new LinkRec(lo.optString("kind", "https"), lo.string("host"), lo.integer("port"), lo.optString("name", null));
                    rec.gateHash = lo.optString("gateHash", null);
                    rec.gateExpiresAt = lo.has("gateExpiresAt") ? lo.lng("gateExpiresAt") : 0;
                    if (rec.gateHash != null && !"https".equals(rec.kind)) {
                        // An older build let `gate` arm a raw link, which has no HTTP to check a
                        // token in. Dropping it here keeps `ls` and the wire telling one story.
                        LOG.warn("link {} is a raw {} link and cannot be gated; the gate an older build saved on it is dropped",
                            rec.name, rec.kind);
                        rec.gateHash = null;
                        rec.gateExpiresAt = 0;
                    }
                    rec.hubPort = lo.optInt("hubPort", 0);
                    rec.domain = lo.optString("domain", null);
                    rec.acmeDirectory = lo.optString("acmeDirectory", null);
                    rec.acmeEmail = lo.optString("acmeEmail", null);
                    rec.proxyProtocol = lo.optBool("proxyProtocol", false);
                    s.links.add(rec);
                }
            }
            if (o.has("revoked")) {
                for (Object r : o.array("revoked")) {
                    @SuppressWarnings("unchecked")
                    JsonObject ro = Json.parseObject(Json.write((java.util.Map<String, Object>) r));
                    s.revoked.add(new RevokedRec(ro.string("name"), ro.string("reason"), ro.lng("at")));
                }
            }
        } else {
            s.machineKey = X25519.generate();
            s.save();
        }
        return s;
    }

    synchronized void save() throws IOException {
        JsonObject.Builder hub = JsonObject.builder().put("host", hubHost).put("addr", hubAddr).put("port", hubPort).put("hubKey", hubKey)
            .put("nextHubKey", nextHubKey).put("caFile", caFile).put("tlsInsecure", tlsInsecure).put("connections", connections)
            .put("dnsSuffix", dnsSuffix);
        if (hubKeyActivatesAt > 0) {
            hub.put("activatesAt", hubKeyActivatesAt);
        }
        java.util.List<Object> ls = new java.util.ArrayList<>();
        for (LinkRec l : links) {
            ls.add(JsonObject.builder().put("kind", l.kind).put("host", l.host).put("port", l.port).put("name", l.name)
                .put("gateHash", l.gateHash).put("gateExpiresAt", l.gateExpiresAt > 0 ? Long.valueOf(l.gateExpiresAt) : null)
                .put("hubPort", l.hubPort > 0 ? Integer.valueOf(l.hubPort) : null)
                .put("domain", l.domain).put("acmeDirectory", l.acmeDirectory).put("acmeEmail", l.acmeEmail)
                .put("proxyProtocol", l.proxyProtocol).build().asMap());
        }
        java.util.List<Object> rs = new java.util.ArrayList<>();
        for (RevokedRec r : revoked) {
            rs.add(JsonObject.builder().put("name", r.name()).put("reason", r.reason()).put("at", r.at()).build().asMap());
        }
        String json = JsonObject.builder()
            .put("machineKey", KeyText.format(PRIVATE_PREFIX, machineKey.privateKey()))
            .put("hub", hub.build())
            .put("registered", registered)
            .put("nodeId", nodeId > 0 ? Long.valueOf(nodeId) : null)
            .put("user", user)
            .put("links", ls)
            .put("revoked", rs.isEmpty() ? null : rs)
            .toJson();
        Files.createDirectories(file.getParent());
        Path tmp = file.resolveSibling("node.json.tmp");
        Files.writeString(tmp, json + "\n", StandardCharsets.UTF_8);
        try {
            Files.setPosixFilePermissions(tmp, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException _) {
            // Windows: directory ACL
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    String machineKeyText() {
        return KeyText.format(KeyText.MACHINE, machineKey.publicKey());
    }

    boolean hasHub() {
        return hubHost != null && hubKey != null;
    }
}
