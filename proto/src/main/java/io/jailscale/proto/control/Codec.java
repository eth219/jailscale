package io.jailscale.proto.control;

import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonException;
import io.jailscale.proto.json.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Hand-written JSON codec for {@link Message}; no reflection (ARCHITECTURE.md §3.1). */
public final class Codec {

    /** How much of an unrecognised {@code "t"} is kept for the log line. */
    private static final int MAX_TYPE_CHARS = 40;

    private Codec() {}

    public static byte[] encode(Message m) {
        return encodeToString(m).getBytes(StandardCharsets.UTF_8);
    }

    public static String encodeToString(Message m) {
        JsonObject.Builder b = JsonObject.builder().put("t", m.type());
        switch (m) {
            case Message.Hello x -> {
                b.put("proto", x.proto()).put("version", x.version()).put("os", x.os())
                    .put("conn", x.conn()).put("host", x.host())
                    // Omitted when the node does not advertise one, so a node with no bound to declare
                    // puts the same bytes on the wire as a build from before the field existed.
                    .put("visitors", x.visitors() > 0 ? Integer.valueOf(x.visitors()) : null);
                if (x.relay()) {
                    b.put("relay", true); // same rule: a control connection's Hello is the wire it always was
                }
            }
            case Message.HelloResponse x -> b.put("proto", x.proto()).put("minProto", x.minProto())
                .put("version", x.version()).put("dnsSuffix", x.dnsSuffix())
                .put("relays", x.relays() == null || x.relays().isEmpty() ? null : x.relays());
            case Message.RelaysChanged x -> b.put("relays", x.relays());
            case Message.PeerNodes x -> b.put("mkeys", x.mkeys());
            case Message.Goodbye x -> b.put("reason", x.reason()).put("detail", x.detail());
            case Message.Ping x -> b.put("id", x.id());
            case Message.Pong x -> b.put("id", x.id());
            case Message.RegisterRequest x -> b.put("hostname", x.hostname()).put("os", x.os()).put("user", x.user())
                .put("invite", x.invite()).put("code", x.code()).put("authKey", x.authKey());
            case Message.RegisterResponse x -> b.put("status", x.status()).put("nodeId", x.nodeId())
                .put("user", x.user()).put("reason", x.reason());
            case Message.HubKeyRotation x -> b.put("nextHubKey", x.nextHubKey()).put("activatesAt", x.activatesAt());
            case Message.InviteCreate x -> b.put("user", x.user()).put("uses", x.uses())
                .put("ttlSeconds", x.ttlSeconds()).put("self", x.self());
            case Message.InviteCreated x -> b.put("url", x.url()).put("code", x.code()).put("expiresAt", x.expiresAt());
            case Message.Error x -> b.put("inReplyTo", x.inReplyTo()).put("reason", x.reason());
            case Message.CertUpdate x -> b.put("chainPem", x.chainPem()).put("keyId", x.keyId());
            case Message.LinkOpen x -> b.put("name", x.name()).put("local", x.local());
            case Message.LinkOpened x -> b.put("linkId", x.linkId()).put("name", x.name()).put("url", x.url())
                .put("reason", x.reason());
            case Message.LinkClose x -> b.put("linkId", x.linkId());
            case Message.LinkRevoked x -> b.put("linkId", x.linkId()).put("name", x.name())
                .put("reason", x.reason()).put("at", x.at());
            case Message.SignRequest x -> b.put("streamId", x.streamId()).put("keyId", x.keyId()).put("alg", x.alg())
                .putBytes("content", x.content()).putBytes("serverHello", x.serverHello())
                .putBytes("encryptedExtensions", x.encryptedExtensions()).putBytes("helloRetryRequest", x.helloRetryRequest());
            case Message.SignResponse x -> b.put("streamId", x.streamId()).putBytes("sig", x.sig()).put("reason", x.reason());
            case Message.PeerHello x -> b.put("proto", x.proto()).put("version", x.version()).put("host", x.host())
                .put("address", x.address()).put("endpoint", x.endpoint()).put("role", x.role())
                .put("epoch", x.role() == null ? null : Long.valueOf(x.epoch()));
            case Message.PeerHelloResponse x -> b.put("proto", x.proto()).put("version", x.version()).put("host", x.host())
                .put("address", x.address()).put("endpoint", x.endpoint()).put("role", x.role())
                .put("epoch", x.role() == null ? null : Long.valueOf(x.epoch()));
            case Message.PeerProbe x -> b.putBytes("nonce", x.nonce());
            case Message.PeerProbeAnswer x -> b.putBytes("nonce", x.nonce()).putBytes("mac", x.mac()).put("epoch", x.epoch());
            case Message.PeerChallenge x -> b.put("txt", x.txt());
            case Message.PeerSnapshot x -> b.put("json", x.json());
            case Message.PeerEvent x -> b.put("json", x.json());
            case Message.PeerCert x -> b.put("chainPem", x.chainPem()).put("keyPem", x.keyPem()).put("keyId", x.keyId());
            case Message.PeerHubKey x -> b.put("current", x.current()).put("next", x.next());
            // Unknown exists only on the receiving side (Message §5.4). Encoding one would mean
            // relaying a message whose fields this build never parsed.
            case Message.Unknown x -> throw new IllegalArgumentException("cannot encode an unknown message type '" + x.type() + "'");
        }
        return b.toJson();
    }

    public static Message decode(byte[] utf8) throws CodecException {
        return decode(new String(utf8, StandardCharsets.UTF_8));
    }

    public static Message decode(String json) throws CodecException {
        try {
            JsonObject o = Json.parseObject(json);
            String t = o.string("t");
            return switch (t) {
                case "Hello" -> new Message.Hello(o.integer("proto"), o.string("version"), o.optString("os", ""),
                    o.optInt("conn", 0), o.optString("host", null), o.optInt("visitors", 0), o.optBool("relay", false));
                case "HelloResponse" -> new Message.HelloResponse(o.integer("proto"), o.integer("minProto"),
                    o.string("version"), o.optString("dnsSuffix", null), o.has("relays") ? o.stringArray("relays") : null);
                case "Goodbye" -> new Message.Goodbye(o.string("reason"), o.optString("detail", null));
                case "Ping" -> new Message.Ping(o.lng("id"));
                case "Pong" -> new Message.Pong(o.lng("id"));
                case "RegisterRequest" -> new Message.RegisterRequest(o.string("hostname"), o.optString("os", ""),
                    o.optString("user", null), o.optString("invite", null), o.optString("code", null), o.optString("authKey", null));
                case "RegisterResponse" -> new Message.RegisterResponse(o.string("status"), o.optLong("nodeId"),
                    o.optString("user", null), o.optString("reason", null));
                case "HubKeyRotation" -> new Message.HubKeyRotation(o.string("nextHubKey"), o.lng("activatesAt"));
                case "InviteCreate" -> new Message.InviteCreate(o.optString("user", null), o.optInt("uses", 0),
                    o.has("ttlSeconds") ? o.lng("ttlSeconds") : 0L, o.optBool("self", false));
                case "InviteCreated" -> new Message.InviteCreated(o.string("url"), o.optString("code", null), o.lng("expiresAt"));
                case "Error" -> new Message.Error(o.optString("inReplyTo", null), o.string("reason"));
                case "CertUpdate" -> new Message.CertUpdate(o.stringArray("chainPem"), o.string("keyId"));
                case "LinkOpen" -> new Message.LinkOpen(o.optString("name", null), o.optString("local", null));
                case "LinkOpened" -> new Message.LinkOpened(o.optString("linkId", null), o.optString("name", null),
                    o.optString("url", null), o.optString("reason", null));
                case "LinkClose" -> new Message.LinkClose(o.string("linkId"));
                case "LinkRevoked" -> new Message.LinkRevoked(o.optString("linkId", null), o.string("name"),
                    o.string("reason"), o.lng("at"));
                case "SignRequest" -> new Message.SignRequest(o.lng("streamId"), o.string("keyId"), o.string("alg"), o.bytes("content"),
                    o.optBytes("serverHello"), o.optBytes("encryptedExtensions"), o.optBytes("helloRetryRequest"));
                case "SignResponse" -> new Message.SignResponse(o.lng("streamId"), o.optBytes("sig"), o.optString("reason", null));
                case "PeerHello" -> new Message.PeerHello(o.integer("proto"), o.string("version"), o.optString("host", null),
                    o.optString("address", null), o.optString("endpoint", null), o.optString("role", null),
                    o.has("epoch") ? o.lng("epoch") : 0);
                case "PeerHelloResponse" -> new Message.PeerHelloResponse(o.integer("proto"), o.string("version"),
                    o.optString("host", null), o.optString("address", null), o.optString("endpoint", null),
                    o.optString("role", null), o.has("epoch") ? o.lng("epoch") : 0);
                case "PeerProbe" -> new Message.PeerProbe(o.bytes("nonce"));
                case "PeerProbeAnswer" -> new Message.PeerProbeAnswer(o.bytes("nonce"), o.bytes("mac"), o.lng("epoch"));
                case "PeerChallenge" -> new Message.PeerChallenge(o.has("txt") ? o.stringArray("txt") : List.of());
                case "PeerSnapshot" -> new Message.PeerSnapshot(o.string("json"));
                case "PeerEvent" -> new Message.PeerEvent(o.string("json"));
                case "PeerCert" -> new Message.PeerCert(o.stringArray("chainPem"), o.string("keyPem"), o.string("keyId"));
                case "PeerHubKey" -> new Message.PeerHubKey(o.string("current"), o.optString("next", null));
                case "RelaysChanged" -> new Message.RelaysChanged(o.has("relays") ? o.stringArray("relays") : List.of());
                case "PeerNodes" -> new Message.PeerNodes(o.has("mkeys") ? o.stringArray("mkeys") : List.of());
                // Not an error (ARCHITECTURE.md §5.4): a peer speaking a newer protocol may add
                // message types, and this build has to stay on the channel when it does. The type
                // is truncated because it reaches a log line and comes off the wire.
                default -> new Message.Unknown(t.length() <= MAX_TYPE_CHARS ? t : t.substring(0, MAX_TYPE_CHARS) + "...");
            };
        } catch (JsonException e) {
            throw new CodecException("bad control message: " + e.getMessage(), e);
        }
    }
}
