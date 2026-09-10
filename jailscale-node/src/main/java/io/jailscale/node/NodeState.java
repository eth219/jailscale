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
    int hubPort = 443;
    String hubKey;        // pinned hkey: text
    String nextHubKey;    // announced rotation, or null
    long hubKeyActivatesAt;
    String caFile;        // trust exactly this PEM instead of system roots (tests, private CAs)
    boolean tlsInsecure;  // only with a pinned hub key
    boolean registered;
    long nodeId;
    String user;
    String dnsSuffix;

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
                s.hubPort = h.optInt("port", 443);
                s.hubKey = h.optString("hubKey", null);
                s.nextHubKey = h.optString("nextHubKey", null);
                s.hubKeyActivatesAt = h.has("activatesAt") ? h.lng("activatesAt") : 0;
                s.caFile = h.optString("caFile", null);
                s.tlsInsecure = h.optBool("tlsInsecure", false);
                s.dnsSuffix = h.optString("dnsSuffix", null);
            }
            s.registered = o.optBool("registered", false);
            s.nodeId = o.has("nodeId") ? o.lng("nodeId") : 0;
            s.user = o.optString("user", null);
        } else {
            s.machineKey = X25519.generate();
            s.save();
        }
        return s;
    }

    synchronized void save() throws IOException {
        JsonObject.Builder hub = JsonObject.builder().put("host", hubHost).put("port", hubPort).put("hubKey", hubKey)
            .put("nextHubKey", nextHubKey).put("caFile", caFile).put("tlsInsecure", tlsInsecure).put("dnsSuffix", dnsSuffix);
        if (hubKeyActivatesAt > 0) {
            hub.put("activatesAt", hubKeyActivatesAt);
        }
        String json = JsonObject.builder()
            .put("machineKey", KeyText.format(PRIVATE_PREFIX, machineKey.privateKey()))
            .put("hub", hub.build())
            .put("registered", registered)
            .put("nodeId", nodeId > 0 ? Long.valueOf(nodeId) : null)
            .put("user", user)
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
