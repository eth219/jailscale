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
    int PROTO = 2;

    String type();

    // --- session ---------------------------------------------------------------------------

    /**
     * {@code host} is the name this node resolved to reach the hub, or null when it was told an
     * address directly and DNS was never asked (§7.2). A handshake that completes against the
     * pinned hub key proves that this node's resolver sends the name to that hub -- evidence about
     * the public address records only when the node is somewhere those are all it could have used,
     * which is the hub's call to make from the address it sees.
     *
     * <p>{@code visitors} is how many visitor streams this node will serve at once
     * (ARCHITECTURE.md §9.3), or 0 from a node that does not say. 0 is what a build older than this
     * field sends -- it is absent from the wire and {@code optInt} supplies the default -- and the
     * hub reads it as "no bound I know of" and falls back to its own caps, which is what it did
     * before this field existed.
     *
     * <p>That was the second field added to an existing message since the protocol shipped --
     * {@code host} was the first, between v0.1.0 and v0.1.1 -- and it rests on the same
     * compatibility §5.4 claims: the decoder reads by name and ignores
     * what it does not recognise, so a new node's Hello is read by an old hub exactly as it
     * always was. That is also why it is a field on Hello rather than a message of its own -- an
     * old hub answers an unknown type with {@code Error{unknown-type}}, which is a reply saying
     * something went wrong, where ignoring a field it has no use for is silence.
     */
    record Hello(int proto, String version, String os, int conn, String host, int visitors) implements Message {
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

    /**
     * One of invite / code, or none to knock. {@code user} is the self-chosen name. {@code authKey}
     * is a credential kind that was removed (#251): the field is still read so that a node older
     * than that which presents one is refused with a reason rather than treated as a knock, and no
     * node sends it any more. Kept on the wire under its old name, as §5.4 asks.
     */
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

    // --- invites -----------------------------------------------------------------------------

    /** {@code uses <= 0} and {@code ttlSeconds <= 0} mean "hub default". */
    record InviteCreate(String user, int uses, long ttlSeconds, boolean self) implements Message {
        @Override public String type() { return "InviteCreate"; }
    }

    record InviteCreated(String url, String code, long expiresAt) implements Message {
        @Override public String type() { return "InviteCreated"; }
    }

    /**
     * Generic failure reply to a request that has no dedicated rejected form.
     *
     * <p>{@code AdminLinkRequest} and {@code AdminLink} used to sit above this and were removed with
     * the admin web page (#253). A node old enough to send one now gets {@code Error{unknown-type}}
     * from {@link Codec}'s default arm, and a hub old enough to send an {@code AdminLink} is
     * decoded as {@link Unknown} and ignored -- which is what §5.4 promises for a type the other
     * side has no case for, in both directions. The names are not reused.
     */
    record Error(String inReplyTo, String reason) implements Message {
        @Override public String type() { return "Error"; }
    }

    // --- links and TLS (M2/M3; defined now so the schema is versioned from the start) -------

    /** Certificate chain as PEM strings, leaf first. */
    record CertUpdate(List<String> chainPem, String keyId) implements Message {
        @Override public String type() { return "CertUpdate"; }
    }

    /**
     * A node asking the hub to serve {@code name} for it (ARCHITECTURE.md §8.2). {@code name} is
     * null to be given one; {@code local} is where the node forwards it, for the hub's records
     * only -- nothing on the hub connects to it.
     */
    record LinkOpen(String name, String local) implements Message {
        @Override public String type() { return "LinkOpen"; }
    }

    record LinkOpened(String linkId, String name, String url, String reason) implements Message {
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
        /** An operator released the name on the hub. */
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
     * A message type this build does not know (ARCHITECTURE.md §5.4). The hub-to-hub messages that
     * used to sit here -- PeerHello, PeerSnapshot, PeerEvent and the rest of the two-hub channel --
     * were removed with the standby (§13), so a hub old enough to send one is decoded as this and
     * ignored, and its names are not reused.
     */
    record Unknown(String type) implements Message {}
}
