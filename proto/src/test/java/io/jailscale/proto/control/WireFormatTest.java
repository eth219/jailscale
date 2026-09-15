package io.jailscale.proto.control;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
        "{\"t\":\"AdminLinkRequest\"}",
        "{\"t\":\"AdminLink\",\"url\":\"https://hub.example.com/admin/login/x\",\"expiresAt\":1789000060}",
        "{\"t\":\"Error\",\"inReplyTo\":\"InviteCreate\",\"reason\":\"policy\"}",
        "{\"t\":\"CertUpdate\",\"chainPem\":[\"-----BEGIN CERTIFICATE-----\\nAA==\\n-----END CERTIFICATE-----\"],\"keyId\":\"sha256:ab\"}",
        "{\"t\":\"LinkOpen\",\"kind\":\"https\",\"name\":\"myapp\",\"domain\":\"app.example.com\",\"port\":10022,"
            + "\"local\":\"127.0.0.1:3000\",\"chainPem\":[\"-----BEGIN CERTIFICATE-----\\nAA==\\n-----END CERTIFICATE-----\"],"
            + "\"domainProof\":\"AQID\"}",
        "{\"t\":\"LinkOpened\",\"linkId\":\"l1\",\"name\":\"myapp\",\"url\":\"https://myapp.hub.example.com\",\"hubPort\":10022,\"reason\":\"taken\"}",
        "{\"t\":\"LinkClose\",\"linkId\":\"l1\"}",
        "{\"t\":\"LinkRevoked\",\"linkId\":\"l1\",\"name\":\"myapp\",\"reason\":\"released\",\"at\":1789000000}",
        "{\"t\":\"SignRequest\",\"streamId\":33554472,\"keyId\":\"sha256:ab\",\"alg\":\"ECDSA-P256-SHA256\",\"content\":\"AQID\","
            + "\"serverHello\":\"AgAAAA\",\"encryptedExtensions\":\"CAAAAA\",\"helloRetryRequest\":\"_gk\"}",
        "{\"t\":\"SignResponse\",\"streamId\":40,\"sig\":\"AQID\",\"reason\":\"not-your-stream\"}",
        "{\"t\":\"ChallengeSet\",\"domain\":\"app.example.com\",\"token\":\"tok\",\"keyAuthorization\":\"tok.thumb\"}",
        "{\"t\":\"ChallengeClear\",\"token\":\"tok\"}",
        "{\"t\":\"Ack\",\"inReplyTo\":\"ChallengeSet\"}",
        // Hello again, carrying the field added after v0.1.0 (§9.3). The Hello at the top of this
        // array keeps its exact bytes and is now the old-node case as well: a node with no bound to
        // declare omits the field and puts the same wire out as a build from before it existed.
        // Appended here rather than next to the other Hello because three tests index this array.
        "{\"t\":\"Hello\",\"proto\":1,\"version\":\"0.1.1\",\"os\":\"linux\",\"conn\":0,\"visitors\":450}",
        // Hub to hub (§13.1), added after v0.1.2. Only ever exchanged between two hubs that both
        // hold hub.key; a node never sees them, and a hub that does not know them answers with
        // Error{unknown-type} like any other message it has no case for.
        "{\"t\":\"PeerHello\",\"proto\":1,\"version\":\"0.2.0\",\"host\":\"hub-b.example.com\"}",
        "{\"t\":\"PeerHelloResponse\",\"proto\":1,\"version\":\"0.2.0\",\"host\":\"hub.example.com\"}",
        "{\"t\":\"PeerSnapshot\",\"json\":\"{\\\"v\\\":1,\\\"nextNodeId\\\":3,\\\"events\\\":[]}\"}",
        "{\"t\":\"PeerEvent\",\"json\":\"{\\\"e\\\":\\\"admin-added\\\",\\\"user\\\":\\\"wq\\\"}\"}",
        "{\"t\":\"PeerCert\",\"chainPem\":[\"-----BEGIN CERTIFICATE-----\\nAA==\\n-----END CERTIFICATE-----\"],"
            + "\"keyPem\":\"-----BEGIN PRIVATE KEY-----\\nAA==\\n-----END PRIVATE KEY-----\",\"keyId\":\"sha256:ab\"}",
        "{\"t\":\"PeerHubKey\",\"current\":\"hkeypriv:AAAA\",\"next\":\"hkeypriv:BBBB\"}",
        // §13.3: the hello carries the sender's advertised address (absent when unknown, so the
        // v0.1.3 line above still reads the same), and the challenge values travel to the standby.
        "{\"t\":\"PeerHello\",\"proto\":1,\"version\":\"0.2.0\",\"host\":\"hub.example.com\",\"address\":\"203.0.113.2\"}",
        "{\"t\":\"PeerHelloResponse\",\"proto\":1,\"version\":\"0.2.0\",\"host\":\"hub.example.com\",\"address\":\"203.0.113.1\"}",
        "{\"t\":\"PeerChallenge\",\"txt\":[\"abc\",\"def\"]}",
        // §13.4: a relay connection's Hello, the relay list on the response, its change, and the
        // node set two hubs exchange. The Hello and HelloResponse lines above keep their bytes: the
        // new fields are omitted when false or empty.
        "{\"t\":\"Hello\",\"proto\":1,\"version\":\"0.1.6\",\"os\":\"linux\",\"conn\":3,\"visitors\":450,\"relay\":true}",
        "{\"t\":\"HelloResponse\",\"proto\":1,\"minProto\":1,\"version\":\"0.1.6\",\"dnsSuffix\":\"hub.example.com\",\"relays\":[\"203.0.113.1\",\"203.0.113.2:8443\"]}",
        "{\"t\":\"RelaysChanged\",\"relays\":[\"203.0.113.2\"]}",
        "{\"t\":\"PeerNodes\",\"mkeys\":[\"mkey:a\",\"mkey:b\"]}",
        "{\"t\":\"PeerHello\",\"proto\":1,\"version\":\"0.2.0\",\"host\":\"hub.example.com\",\"address\":\"203.0.113.2\",\"endpoint\":\"203.0.113.2:8443\"}",
        // §13.5: role and epoch on the hellos (omitted before a hub has a role to state), and the
        // liveness proof a node carries between the standby and the primary.
        "{\"t\":\"PeerHelloResponse\",\"proto\":1,\"version\":\"0.2.0\",\"host\":\"hub.example.com\",\"address\":\"203.0.113.1\",\"role\":\"primary\",\"epoch\":4}",
        "{\"t\":\"PeerProbe\",\"nonce\":\"AQID\"}",
        "{\"t\":\"PeerProbeAnswer\",\"nonce\":\"AQID\",\"mac\":\"CQk\",\"epoch\":4}"
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
        Message.SignRequest sr = assertInstanceOf(Message.SignRequest.class, Codec.decode(GOLDEN[19]));
        assertEquals((2L << 24) | 40, sr.streamId());
        assertArrayEquals(new byte[] {1, 2, 3}, sr.content());
        assertArrayEquals(new byte[] {2, 0, 0, 0}, sr.serverHello());
        assertArrayEquals(new byte[] {8, 0, 0, 0}, sr.encryptedExtensions());
        assertArrayEquals(new byte[] {(byte) 0xfe, 9}, sr.helloRetryRequest());

        Message.LinkOpen lo = assertInstanceOf(Message.LinkOpen.class, Codec.decode(GOLDEN[15]));
        assertEquals("app.example.com", lo.domain());
        assertArrayEquals(new byte[] {1, 2, 3}, lo.domainProof());

        Message.ChallengeSet cs = assertInstanceOf(Message.ChallengeSet.class, Codec.decode(GOLDEN[21]));
        assertEquals("app.example.com", cs.domain());
        assertEquals("tok", cs.token());
        assertEquals("tok.thumb", cs.keyAuthorization());
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
            Codec.decode("{\"t\":\"LinkOpen\",\"kind\":\"https\",\"local\":\"127.0.0.1:3000\"}"));
        assertEquals(null, bareLink.name());
        assertEquals(null, bareLink.domainProof());
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
