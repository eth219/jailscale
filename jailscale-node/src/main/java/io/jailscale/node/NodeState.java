package io.jailscale.node;

import io.jailscale.crypto.KeyText;
import io.jailscale.crypto.X25519;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;

/** {@code node.json}: the MachineKey, the hub we belong to, and our registration (DESIGN.md §5). */
final class NodeState {

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
    int connections = 1;  // connections to the hub (DESIGN.md §8), 1..4
    boolean registered;
    long nodeId;
    String user;
    String dnsSuffix;
    final java.util.List<LinkRec> links = new java.util.concurrent.CopyOnWriteArrayList<>();

    /** A link this node keeps open (DESIGN.md §10.1). {@code linkId}/{@code url} are per hub session. */
    static final class LinkRec {
        final String kind;
        final String host;
        final int port;
        volatile String name;   // assigned by the hub; requested on reopen so it stays stable
        volatile String linkId;
        volatile String url;
        volatile String gateHash;      // visitor gate (DESIGN.md §10.4): SHA-256 of the visit token, or null
        volatile long gateExpiresAt;   // ms epoch; 0 = never
        volatile int hubPort;          // raw tcp/udp: the hub port assigned last time (requested again on reopen)
        volatile String domain;        // user domain (DESIGN.md §9.4), or null
        volatile String acmeDirectory; // ACME directory used for the domain, or null for Let's Encrypt
        volatile String acmeEmail;
        volatile long certExpiresAt;   // not persisted: from the loaded certificate

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
            if (linkId.equals(l.linkId)) {
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
                    rec.hubPort = lo.optInt("hubPort", 0);
                    rec.domain = lo.optString("domain", null);
                    rec.acmeDirectory = lo.optString("acmeDirectory", null);
                    rec.acmeEmail = lo.optString("acmeEmail", null);
                    s.links.add(rec);
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
                .put("domain", l.domain).put("acmeDirectory", l.acmeDirectory).put("acmeEmail", l.acmeEmail).build().asMap());
        }
        String json = JsonObject.builder()
            .put("machineKey", KeyText.format(PRIVATE_PREFIX, machineKey.privateKey()))
            .put("hub", hub.build())
            .put("registered", registered)
            .put("nodeId", nodeId > 0 ? Long.valueOf(nodeId) : null)
            .put("user", user)
            .put("links", ls)
            .toJson();
        Files.createDirectories(file.getParent());
        Path tmp = file.resolveSibling("node.json.tmp");
        Files.writeString(tmp, json + "\n", StandardCharsets.UTF_8);
        try {
            Files.setPosixFilePermissions(tmp, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException ignored) {
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
