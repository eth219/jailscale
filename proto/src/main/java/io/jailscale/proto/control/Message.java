package io.jailscale.proto.control;

import java.util.List;

/**
 * Control messages carried on mux stream 0 (ARCHITECTURE.md §6.1). Every message serialises to a JSON
 * object with a {@code "t"} type field; {@link Codec} does the encoding by hand.
 */
public sealed interface Message {

    /**
     * Current control protocol version (message schema + frame set). A signing request carries
     * what is to be signed with the node's ServerHello and EncryptedExtensions, a domain claim
     * carries a proof of key possession, and an ACME challenge names its domain; a hub that could
     * not check a request would have to refuse it, so a node speaking an older version is told to
     * upgrade rather than served unchecked.
     */
    int PROTO = 1;

    String type();

    // --- session ---------------------------------------------------------------------------

    /**
     * {@code host} is the name this node resolved to reach the hub, or null when it was told an
     * address directly and DNS was never asked (§7.2). A handshake that completes against the
     * pinned hub key proves that this node's resolver sends the name to that hub -- evidence about
     * the public address records only when the node is somewhere those are all it could have used,
     * which is the hub's call to make from the address it sees.
     */
    record Hello(int proto, String version, String os, int conn, String host, int visitors) implements Message {
        @Override public String type() { return "Hello"; }

        /**
         * How many visitor streams this node will serve at once (ARCHITECTURE.md §9.3), or 0 from a
         * node that does not say. 0 is what a build older than this field sends -- it is absent from
         * the wire and {@code optInt} supplies the default -- and the hub reads it as "no bound I
         * know of" and falls back to its own caps, which is what it did before this field existed.
         *
         * <p>This is the first field added to an existing message since the protocol shipped, so it
         * is the first test of the compatibility §5.4 claims: the decoder reads by name and ignores
         * what it does not recognise, so a new node's Hello is read by an old hub exactly as it
         * always was. That is also why it is a field on Hello rather than a message of its own -- an
         * old hub answers an unknown type with {@code Error{unknown-type}}, which is a reply saying
         * something went wrong, where ignoring a field it has no use for is silence.
         */
        public boolean advertisesCapacity() {
            return visitors > 0;
        }
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
     * {@code chainPem}: for user domains, the node's own certificate chain for the name (§8.3).
     * {@code domainProof}: a signature with that certificate's private key over
     * {@code "jailscale domain claim v1" || handshakeHash || domain}, bound to the Noise handshake
     * of the connection carrying it so it cannot be replayed onto another one. A chain on its own
     * proves nothing, being public in every TLS handshake and in CT logs.
     */
    record LinkOpen(String kind, String name, String domain, Integer port, String local, List<String> chainPem,
        byte[] domainProof) implements Message {
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

    /**
     * {@code content} is the bytes to be signed, not their hash: the hub hashes them itself so it
     * can check what it is signing (ARCHITECTURE.md §9.2). Carrying a bare digest would make the
     * hub a general-purpose signing oracle for its own wildcard key. {@code serverHello},
     * {@code encryptedExtensions} and, after a retry, {@code helloRetryRequest} are the node's
     * own handshake messages, so the hub can rebuild the transcript from the ClientHello it
     * delivered on {@code streamId} and check that the hash in {@code content} is that handshake's.
     */
    record SignRequest(long streamId, String keyId, String alg, byte[] content, byte[] serverHello, byte[] encryptedExtensions,
        byte[] helloRetryRequest) implements Message {
        @Override public String type() { return "SignRequest"; }
    }

    record SignResponse(long streamId, byte[] sig, String reason) implements Message {
        @Override public String type() { return "SignResponse"; }
    }

    /**
     * {@code domain} is the identifier the token belongs to. The hub answers the challenge only for
     * that Host, and only for a domain this node may claim: without it the relay validates any name
     * that resolves to the hub, for any node.
     */
    record ChallengeSet(String domain, String token, String keyAuthorization) implements Message {
        @Override public String type() { return "ChallengeSet"; }
    }

    record ChallengeClear(String token) implements Message {
        @Override public String type() { return "ChallengeClear"; }
    }

    /** Positive reply to a request that has no result of its own (ChallengeSet/Clear). */
    record Ack(String inReplyTo) implements Message {
        @Override public String type() { return "Ack"; }
    }

    /**
     * A message type this build does not know (ARCHITECTURE.md §5.4). Decoding one is deliberately
     * not an error: the peer is authenticated, so this is a newer jailscale sending something this
     * one has no case for, and tearing the control channel down over it would make every added
     * message type a flag day. The receiver logs it and answers {@code Error{unknown-type}}; the
     * sender is the side that must gate anything load-bearing on the peer's {@code proto} number,
     * because an ignored message looks exactly like a delivered one from here.
     *
     * <p>It is never encoded: a build that does not understand a type cannot forward it either.
     */
    record Unknown(String type) implements Message {}
}
