package io.jailscale.proto.control;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The control wire as of v0.1.0, pinned (ARCHITECTURE.md §5.4).
 *
 * <p>A released node and a released hub are updated separately, so the compatibility rules are: a
 * field may be added, and it may never be renamed, removed or given a new meaning. Renaming one is
 * not a compile error and not a round-trip failure either — encoder and decoder change together and
 * agree with each other — so nothing but a recorded wire catches it. It cost an outage once already:
 * {@code SignRequest.digest} became {@code content}, and every node built before that died on the
 * new hub with {@code missing field 'content'} and reconnected forever.
 *
 * <p>When a change here is deliberate it needs a {@code PROTO} bump and a line in §5.4. When it is
 * not, this test is where it should stop.
 */
class WireFormatTest {

    /**
     * One fully populated example of every message type, exactly as v0.1.0 puts it on the wire.
     * Appended to and never reordered: three tests below index into this array.
     */
    private static final String[] GOLDEN = {
        "{\"t\":\"Hello\",\"proto\":1,\"version\":\"0.1.0\",\"os\":\"linux\",\"conn\":2,\"host\":\"hub.example.com\"}",
        "{\"t\":\"HelloResponse\",\"proto\":1,\"minProto\":1,\"version\":\"0.1.0\",\"dnsSuffix\":\"hub.example.com\"}",
        "{\"t\":\"Goodbye\",\"reason\":\"upgrade-required\",\"detail\":\"update jailscale and run `jailscale up` again\"}",
        "{\"t\":\"Ping\",\"id\":7}",
        "{\"t\":\"Pong\",\"id\":7}",
        "{\"t\":\"RegisterRequest\",\"hostname\":\"wq-macbook\",\"os\":\"macos\",\"user\":\"wq\",\"invite\":\"inv_9f1c\",\"code\":\"7F3K-92QX\",\"authKey\":\"jk_abc\"}",
        "{\"t\":\"RegisterResponse\",\"status\":\"approved\",\"nodeId\":12,\"user\":\"wq\"}",
        "{\"t\":\"RegisterResponse\",\"status\":\"rejected\",\"reason\":\"invite-expired\"}",
        "{\"t\":\"HubKeyRotation\",\"nextHubKey\":\"hkey:AAAA\",\"activatesAt\":1789000000}",
        "{\"t\":\"InviteCreate\",\"user\":\"bob\",\"uses\":3,\"ttlSeconds\":86400,\"self\":true}",
        "{\"t\":\"InviteCreated\",\"url\":\"https://hub.example.com/join/x\",\"code\":\"7F3K-92QX\",\"expiresAt\":1789000000}",
        "{\"t\":\"Error\",\"inReplyTo\":\"InviteCreate\",\"reason\":\"policy\"}",
        "{\"t\":\"CertUpdate\",\"chainPem\":[\"-----BEGIN CERTIFICATE-----\\nAA==\\n-----END CERTIFICATE-----\"],\"keyId\":\"sha256:ab\"}",
        // LinkOpen lost `kind` and `port` with raw tcp and udp links (§8.4) and `domain`,
        // `chainPem` and `domainProof` with user domains (§8.3); LinkOpened lost `hubPort`. Those
        // are removals, not additions, so they are a protocol break and the PROTO bump in §5.4 is
        // what makes it one: these are the proto 2 lines.
        "{\"t\":\"LinkOpen\",\"name\":\"myapp\",\"local\":\"127.0.0.1:3000\"}",
        "{\"t\":\"LinkOpened\",\"linkId\":\"l1\",\"name\":\"myapp\",\"url\":\"https://myapp.hub.example.com\",\"reason\":\"taken\"}",
        "{\"t\":\"LinkClose\",\"linkId\":\"l1\"}",
        "{\"t\":\"LinkRevoked\",\"linkId\":\"l1\",\"name\":\"myapp\",\"reason\":\"released\",\"at\":1789000000}",
        "{\"t\":\"SignRequest\",\"streamId\":33554472,\"keyId\":\"sha256:ab\",\"alg\":\"ECDSA-P256-SHA256\",\"content\":\"AQID\","
            + "\"serverHello\":\"AgAAAA\",\"encryptedExtensions\":\"CAAAAA\",\"helloRetryRequest\":\"_gk\"}",
        "{\"t\":\"SignResponse\",\"streamId\":40,\"sig\":\"AQID\",\"reason\":\"not-your-stream\"}",
        // Hello again, carrying the field added after v0.1.0 (§9.3). The Hello at the top of this
        // array keeps its exact bytes and is now the old-node case as well: a node with no bound to
        // declare omits the field and puts the same wire out as a build from before it existed.
        // Appended here rather than next to the other Hello because three tests index this array.
        "{\"t\":\"Hello\",\"proto\":1,\"version\":\"0.1.1\",\"os\":\"linux\",\"conn\":0,\"visitors\":450}",
        // The hub-to-hub lines that stood here -- PeerHello and its response, the snapshot and
        // event stream, the certificate and key, the probe pair, the relay list and the node set --
        // went with the standby (§13), as did `relay` on Hello and `relays` on HelloResponse. Both
        // of those were fields omitted when false or empty, so the two lines above keep the exact
        // bytes they always had.
    };

    @Test
    void everyRecordedMessageStillDecodesToTheSameWire() throws Exception {
        for (String wire : GOLDEN) {
            Message m = Codec.decode(wire);
            assertEquals(wire, Codec.encodeToString(m), "the wire moved for " + m.type());
        }
    }

    @Test
    void theWholeMessageSetIsCovered() throws Exception {
        // A new message type with no golden line is a type nobody pinned. Counted against the
        // records declared in Message (reflection is fine here; it is the product that may not use
        // it) so adding one cannot quietly skip this test. Unknown is excluded: it is never sent.
        java.util.Set<String> pinned = new java.util.TreeSet<>();
        for (String wire : GOLDEN) {
            pinned.add(Codec.decode(wire).type());
        }
        java.util.Set<String> declared = new java.util.TreeSet<>();
        for (Class<?> c : Message.class.getDeclaredClasses()) {
            if (c.isRecord() && !c.getSimpleName().equals("Unknown")) {
                declared.add(c.getSimpleName());
            }
        }
        assertEquals(declared, pinned, "every Message record needs a line in GOLDEN");
    }

    @Test
    void theFieldsCarryWhatTheirNamesSay() throws Exception {
        // A rename that changes the encoder and decoder together passes the round trip above, and a
        // swap of two same-typed fields passes it too. These are the ones where being wrong is a
        // signature over the wrong handshake or a challenge answered for the wrong domain.
        Message.SignRequest sr = only(Message.SignRequest.class);
        assertEquals((2L << 24) | 40, sr.streamId());
        assertArrayEquals(new byte[] {1, 2, 3}, sr.content());
        assertArrayEquals(new byte[] {2, 0, 0, 0}, sr.serverHello());
        assertArrayEquals(new byte[] {8, 0, 0, 0}, sr.encryptedExtensions());
        assertArrayEquals(new byte[] {(byte) 0xfe, 9}, sr.helloRetryRequest());

        Message.LinkOpen lo = only(Message.LinkOpen.class);
        assertEquals("myapp", lo.name());
        assertEquals("127.0.0.1:3000", lo.local());
    }

    /**
     * The one {@link #GOLDEN} line of this type, decoded. Looked up by type and not by index: these
     * three assertions used to name GOLDEN[15], [19] and [21], and removing two message types with
     * the admin web (#253) shifted every line after them, so the indices pointed at the wrong
     * messages. Asserting there is exactly one is what keeps the lookup as precise as the index was.
     */
    private static <T extends Message> T only(Class<T> type) throws Exception {
        List<T> found = new ArrayList<>();
        for (String line : GOLDEN) {
            Message m = Codec.decode(line);
            if (type.isInstance(m)) {
                found.add(type.cast(m));
            }
        }
        assertEquals(1, found.size(), type.getSimpleName() + " should appear exactly once in GOLDEN");
        return found.get(0);
    }

    @Test
    void theWireBeforeAFieldWasAddedStillReadsTheSame() throws Exception {
        // Hello.host was added after v0.1.0 shipped (§7.2), which is the additive case §5.4 permits.
        // A v0.1.0 node sends the line below; it has to keep decoding, and re-encoding it has to
        // keep producing the same bytes rather than inventing a field that peer never sent.
        String before = "{\"t\":\"Hello\",\"proto\":1,\"version\":\"0.1.0\",\"os\":\"linux\",\"conn\":2}";
        Message m = Codec.decode(before);
        assertEquals(new Message.Hello(1, "0.1.0", "linux", 2, null, 0), m);
        assertEquals(before, Codec.encodeToString(m));
    }

    @Test
    void aFieldThisBuildDoesNotKnowIsIgnored() throws Exception {
        // The additive case, which is the one compatibility rests on: a newer peer adds a field and
        // an older build reads the message anyway.
        Message m = Codec.decode("{\"t\":\"Hello\",\"proto\":1,\"version\":\"9.9.9\",\"os\":\"plan9\",\"conn\":0,"
            + "\"somethingAdded\":{\"deep\":[1,2,3]}}");
        assertEquals(new Message.Hello(1, "9.9.9", "plan9", 0, null, 0), m);
    }

    @Test
    void anOptionalFieldMayBeAbsent() throws Exception {
        // Nobody may promote an optional field to a required one: that breaks every peer that does
        // not send it yet. (SignRequest without serverHello decodes; refusing to sign it is
        // NodeGroup.sign's job, not the codec's.)
        assertEquals(new Message.Hello(1, "0.1.0", "", 0, null, 0), Codec.decode("{\"t\":\"Hello\",\"proto\":1,\"version\":\"0.1.0\"}"));
        Message.SignRequest bare = assertInstanceOf(Message.SignRequest.class,
            Codec.decode("{\"t\":\"SignRequest\",\"streamId\":1,\"keyId\":\"k\",\"alg\":\"a\",\"content\":\"AQID\"}"));
        assertEquals(null, bare.serverHello());
        Message.LinkOpen bareLink = assertInstanceOf(Message.LinkOpen.class,
            Codec.decode("{\"t\":\"LinkOpen\",\"local\":\"127.0.0.1:3000\"}"));
        assertEquals(null, bareLink.name(), "a node asking to be given a name sends none");
    }

    @Test
    void aMessageTypeThisBuildDoesNotKnowIsNotFatal() throws Exception {
        // The control channel has to survive a newer peer adding a message type, or every added
        // type is a flag day. It survives as Unknown, which the handlers log and answer with
        // Error{unknown-type}.
        Message m = Codec.decode("{\"t\":\"SomethingAddedLater\",\"x\":1}");
        assertEquals(new Message.Unknown("SomethingAddedLater"), m);

        // The type reaches a log line and comes off the wire, so its length is bounded.
        Message long_ = Codec.decode("{\"t\":\"" + "T".repeat(500) + "\"}");
        assertEquals("T".repeat(40) + "...", long_.type());

        // It is never sent on: this build never parsed the fields it would have to forward.
        assertThrows(IllegalArgumentException.class, () -> Codec.encodeToString(new Message.Unknown("SomethingAddedLater")));
    }
}
