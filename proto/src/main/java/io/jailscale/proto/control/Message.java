package io.jailscale.proto.control;

import java.util.List;

/**
 * Control messages carried on mux stream 0 (ARCHITECTURE.md §6.1). Every message serialises to a JSON
 * object with a {@code "t"} type field; {@link Codec} does the encoding by hand.
 */
public sealed interface Message {

    /** Current control protocol version (message schema + frame set). */
    int PROTO = 1;

    String type();

    // --- session ---------------------------------------------------------------------------

    record Hello(int proto, String version, String os, int conn) implements Message {
        @Override public String type() { return "Hello"; }
    }

    record HelloResponse(int proto, int minProto, String version, String dnsSuffix) implements Message {
        @Override public String type() { return "HelloResponse"; }
    }

    record Goodbye(String reason, String detail) implements Message {
        public Goodbye(String reason) {
            this(reason, null);
        }

        public static final String UPGRADE_REQUIRED = "upgrade-required";
        public static final String REVOKED = "revoked";
        /** The hub bars this address. The node keeps its registration; it just cannot get in from here. */
        public static final String BANNED = "banned";
        public static final String SHUTDOWN = "shutdown";
        /** Hand-off: reconnect now, keep this connection only for streams already on it. */
        public static final String DRAINING = "draining";
        @Override public String type() { return "Goodbye"; }
    }

    record Ping(long id) implements Message {
        @Override public String type() { return "Ping"; }
    }

    record Pong(long id) implements Message {
        @Override public String type() { return "Pong"; }
    }

    // --- registration ----------------------------------------------------------------------

    /** Exactly one of invite / code / authKey, or none to knock. {@code user} is the self-chosen name. */
    record RegisterRequest(String hostname, String os, String user, String invite, String code, String authKey)
        implements Message {
        @Override public String type() { return "RegisterRequest"; }
    }

    record RegisterResponse(String status, Long nodeId, String user, String reason) implements Message {
        public static final String APPROVED = "approved";
        public static final String PENDING = "pending";
        public static final String REJECTED = "rejected";
        @Override public String type() { return "RegisterResponse"; }

        public static RegisterResponse approved(long nodeId, String user) {
            return new RegisterResponse(APPROVED, nodeId, user, null);
        }

        public static RegisterResponse pending() {
            return new RegisterResponse(PENDING, null, null, null);
        }

        public static RegisterResponse rejected(String reason) {
            return new RegisterResponse(REJECTED, null, null, reason);
        }
    }

    record HubKeyRotation(String nextHubKey, long activatesAt) implements Message {
        @Override public String type() { return "HubKeyRotation"; }
    }

    // --- invites and admin -----------------------------------------------------------------

    /** {@code uses <= 0} and {@code ttlSeconds <= 0} mean "hub default". */
    record InviteCreate(String user, int uses, long ttlSeconds, boolean self) implements Message {
        @Override public String type() { return "InviteCreate"; }
    }

    record InviteCreated(String url, String code, long expiresAt) implements Message {
        @Override public String type() { return "InviteCreated"; }
    }

    record AdminLinkRequest() implements Message {
        @Override public String type() { return "AdminLinkRequest"; }
    }

    record AdminLink(String url, long expiresAt) implements Message {
        @Override public String type() { return "AdminLink"; }
    }

    /** Generic failure reply to a request that has no dedicated rejected form. */
    record Error(String inReplyTo, String reason) implements Message {
        @Override public String type() { return "Error"; }
    }

    // --- links and TLS (M2/M3; defined now so the schema is versioned from the start) -------

    /** Certificate chain as PEM strings, leaf first. */
    record CertUpdate(List<String> chainPem, String keyId) implements Message {
        @Override public String type() { return "CertUpdate"; }
    }

    /**
     * {@code local} is the node-side target ("host:port"); it keys the stable random name.
     * {@code chainPem}: for user domains, the node's own certificate chain proving the name (§8.3).
     */
    record LinkOpen(String kind, String name, String domain, Integer port, String local, List<String> chainPem) implements Message {
        public static final String HTTPS = "https";
        public static final String TCP = "tcp";
        public static final String UDP = "udp";
        @Override public String type() { return "LinkOpen"; }
    }

    record LinkOpened(String linkId, String name, String url, Integer hubPort, String reason) implements Message {
        @Override public String type() { return "LinkOpened"; }
    }

    record LinkClose(String linkId) implements Message {
        @Override public String type() { return "LinkClose"; }
    }

    /**
     * The hub telling a node that one of its names is no longer served by it (ARCHITECTURE.md §11.4).
     * Sent when another node opens the same name, or when an operator releases it. An honest hub
     * sends this; a compromised one will not, which is what the self-probe (§11.3) is for.
     */
    record LinkRevoked(String linkId, String name, String reason, long at) implements Message {
        /** Another node opened the same name; the newest opener won (§8.2). */
        public static final String REASSIGNED = "reassigned";
        /** An operator released the name, domain or port on the hub. */
        public static final String RELEASED = "released";
        @Override public String type() { return "LinkRevoked"; }
    }

    record SignRequest(long streamId, String keyId, String alg, byte[] digest) implements Message {
        @Override public String type() { return "SignRequest"; }
    }

    record SignResponse(long streamId, byte[] sig, String reason) implements Message {
        @Override public String type() { return "SignResponse"; }
    }

    record ChallengeSet(String token, String keyAuthorization) implements Message {
        @Override public String type() { return "ChallengeSet"; }
    }

    record ChallengeClear(String token) implements Message {
        @Override public String type() { return "ChallengeClear"; }
    }

    /** Positive reply to a request that has no result of its own (ChallengeSet/Clear). */
    record Ack(String inReplyTo) implements Message {
        @Override public String type() { return "Ack"; }
    }
}
