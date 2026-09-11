package io.jailscale.proto.control;

import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonException;
import io.jailscale.proto.json.JsonObject;
import java.nio.charset.StandardCharsets;

/** Hand-written JSON codec for {@link Message}; no reflection (ARCHITECTURE.md §3.1). */
public final class Codec {

    private Codec() {}

    public static byte[] encode(Message m) {
        return encodeToString(m).getBytes(StandardCharsets.UTF_8);
    }

    public static String encodeToString(Message m) {
        JsonObject.Builder b = JsonObject.builder().put("t", m.type());
        switch (m) {
            case Message.Hello x -> b.put("proto", x.proto()).put("version", x.version()).put("os", x.os()).put("conn", x.conn());
            case Message.HelloResponse x -> b.put("proto", x.proto()).put("minProto", x.minProto())
                .put("version", x.version()).put("dnsSuffix", x.dnsSuffix());
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
            case Message.AdminLinkRequest x -> { }
            case Message.AdminLink x -> b.put("url", x.url()).put("expiresAt", x.expiresAt());
            case Message.Error x -> b.put("inReplyTo", x.inReplyTo()).put("reason", x.reason());
            case Message.CertUpdate x -> b.put("chainPem", x.chainPem()).put("keyId", x.keyId());
            case Message.LinkOpen x -> b.put("kind", x.kind()).put("name", x.name()).put("domain", x.domain()).put("port", x.port())
                .put("local", x.local()).put("chainPem", x.chainPem());
            case Message.LinkOpened x -> b.put("linkId", x.linkId()).put("name", x.name()).put("url", x.url())
                .put("hubPort", x.hubPort()).put("reason", x.reason());
            case Message.LinkClose x -> b.put("linkId", x.linkId());
            case Message.LinkRevoked x -> b.put("linkId", x.linkId()).put("name", x.name())
                .put("reason", x.reason()).put("at", x.at());
            case Message.SignRequest x -> b.put("streamId", x.streamId()).put("keyId", x.keyId()).put("alg", x.alg())
                .putBytes("digest", x.digest());
            case Message.SignResponse x -> b.put("streamId", x.streamId()).putBytes("sig", x.sig()).put("reason", x.reason());
            case Message.ChallengeSet x -> b.put("token", x.token()).put("keyAuthorization", x.keyAuthorization());
            case Message.ChallengeClear x -> b.put("token", x.token());
            case Message.Ack x -> b.put("inReplyTo", x.inReplyTo());
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
                case "Hello" -> new Message.Hello(o.integer("proto"), o.string("version"), o.optString("os", ""), o.optInt("conn", 0));
                case "HelloResponse" -> new Message.HelloResponse(o.integer("proto"), o.integer("minProto"),
                    o.string("version"), o.optString("dnsSuffix", null));
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
                case "AdminLinkRequest" -> new Message.AdminLinkRequest();
                case "AdminLink" -> new Message.AdminLink(o.string("url"), o.lng("expiresAt"));
                case "Error" -> new Message.Error(o.optString("inReplyTo", null), o.string("reason"));
                case "CertUpdate" -> new Message.CertUpdate(o.stringArray("chainPem"), o.string("keyId"));
                case "LinkOpen" -> new Message.LinkOpen(o.string("kind"), o.optString("name", null), o.optString("domain", null),
                    o.has("port") ? o.integer("port") : null, o.optString("local", null), o.has("chainPem") ? o.stringArray("chainPem") : null);
                case "LinkOpened" -> new Message.LinkOpened(o.optString("linkId", null), o.optString("name", null),
                    o.optString("url", null), o.has("hubPort") ? o.integer("hubPort") : null, o.optString("reason", null));
                case "LinkClose" -> new Message.LinkClose(o.string("linkId"));
                case "LinkRevoked" -> new Message.LinkRevoked(o.optString("linkId", null), o.string("name"),
                    o.string("reason"), o.lng("at"));
                case "SignRequest" -> new Message.SignRequest(o.lng("streamId"), o.string("keyId"), o.string("alg"), o.bytes("digest"));
                case "SignResponse" -> new Message.SignResponse(o.lng("streamId"), o.optBytes("sig"), o.optString("reason", null));
                case "ChallengeSet" -> new Message.ChallengeSet(o.string("token"), o.string("keyAuthorization"));
                case "ChallengeClear" -> new Message.ChallengeClear(o.string("token"));
                case "Ack" -> new Message.Ack(o.optString("inReplyTo", null));
                default -> throw new CodecException("unknown message type '" + t + "'");
            };
        } catch (JsonException e) {
            throw new CodecException("bad control message: " + e.getMessage(), e);
        }
    }
}
