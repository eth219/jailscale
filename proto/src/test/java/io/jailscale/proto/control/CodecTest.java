package io.jailscale.proto.control;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class CodecTest {

    @Test
    void everyMessageRoundTrips() throws Exception {
        Message[] all = {
            new Message.Hello(1, "0.1.0", "macos", 2, "hub.example.com", 450),
            new Message.HelloResponse(1, 1, "0.1.0", "hub.example.com"),
            new Message.Goodbye(Message.Goodbye.UPGRADE_REQUIRED),
            new Message.Goodbye(Message.Goodbye.UPGRADE_REQUIRED, "this hub speaks protocol 2 and newer"),
            new Message.Ping(7), new Message.Pong(7),
            new Message.RegisterRequest("wq-macbook", "macos", "wq", "9f1c", null, null),
            new Message.RegisterRequest("ci-1", "linux", null, null, "7F3K-92QX", null),
            Message.RegisterResponse.approved(12, "wq"),
            Message.RegisterResponse.pending(),
            Message.RegisterResponse.rejected("invite-expired"),
            new Message.HubKeyRotation("hkey:AAAA", 1789000000L),
            new Message.InviteCreate("bob", 3, 86400, false),
            new Message.InviteCreate(null, 0, 0, true),
            new Message.InviteCreated("https://hub/join/x", "7F3K-92QX", 1789000000L),
            new Message.Error("InviteCreate", "policy"),
            new Message.CertUpdate(List.of("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"), "sha256:ab"),
            new Message.LinkOpen("https", "myapp", null, null, "127.0.0.1:3000", null, null),
            new Message.LinkOpen("tcp", null, null, 10022, "127.0.0.1:22", null, null),
            new Message.LinkOpen("https", null, "app.example.com", null, "127.0.0.1:3000",
                java.util.List.of("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"), new byte[] {9, 8, 7}),
            new Message.Ack("ChallengeSet"),
            new Message.LinkOpened("l1", "myapp", "https://myapp.hub.example.com", null, null),
            new Message.LinkOpened(null, null, null, null, "taken"),
            new Message.LinkClose("l1"),
            new Message.SignRequest((2L << 24) | 40, "sha256:ab", "ECDSA-P256-SHA256", new byte[] {1, 2, 3}, new byte[] {2, 0, 0, 0},
                new byte[] {8, 0, 0, 0}, null),
            new Message.SignRequest(41, "sha256:ab", "ECDSA-P256-SHA256", new byte[] {1}, new byte[] {2}, new byte[] {8}, new byte[] {2, 9}),
            new Message.SignResponse(40, new byte[] {4, 5}, null),
            new Message.SignResponse(40, null, "not-your-stream"),
            new Message.ChallengeSet("app.example.com", "tok", "tok.thumb"),
            new Message.ChallengeClear("tok"),
            new Message.PeerHello(1, "0.2.0", "hub-b.example.com", "203.0.113.2"),
            new Message.PeerHello(1, "0.2.0", "hub-b.example.com", "203.0.113.2", "203.0.113.2:8443"),
            new Message.PeerHelloResponse(1, "0.2.0", "hub.example.com", "203.0.113.1", "203.0.113.1:8443"),
            new Message.PeerHello(1, "0.2.0", "hub.example.com", "203.0.113.2", null, "standby", 3),
            new Message.PeerHelloResponse(1, "0.2.0", "hub.example.com", "203.0.113.1", null, "primary", 4),
            new Message.PeerProbe(new byte[] {1, 2, 3}),
            new Message.PeerProbeAnswer(new byte[] {1, 2, 3}, new byte[] {9, 9}, 4),
            new Message.PeerHello(1, "0.2.0", "hub-b.example.com", null),
            new Message.PeerHelloResponse(1, "0.2.0", "hub.example.com", "203.0.113.1"),
            new Message.PeerChallenge(List.of("abc", "def")),
            new Message.PeerChallenge(List.of()),
            new Message.PeerSnapshot("{\"v\":1,\"nextNodeId\":3,\"events\":[]}"),
            new Message.PeerEvent("{\"e\":\"admin-added\",\"user\":\"wq\"}"),
            new Message.PeerCert(List.of("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"),
                "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----", "sha256:ab"),
            new Message.PeerHubKey("hkeypriv:AAAA", null),
            new Message.PeerHubKey("hkeypriv:AAAA", "hkeypriv:BBBB"),
            new Message.Hello(1, "0.1.6", "linux", 3, null, 450, true),
            new Message.HelloResponse(1, 1, "0.1.6", "hub.example.com", List.of("203.0.113.1", "203.0.113.2:8443")),
            new Message.RelaysChanged(List.of("203.0.113.2")),
            new Message.RelaysChanged(List.of()),
            new Message.PeerNodes(List.of("mkey:a", "mkey:b")),
        };
        for (Message m : all) {
            byte[] enc = Codec.encode(m);
            Message dec = Codec.decode(enc);
            assertEquals(m.type(), dec.type());
            if (m instanceof Message.SignRequest a && dec instanceof Message.SignRequest b) {
                assertEquals(a.streamId(), b.streamId());
                assertArrayEquals(a.content(), b.content());
                assertArrayEquals(a.serverHello(), b.serverHello());
                assertArrayEquals(a.encryptedExtensions(), b.encryptedExtensions());
                assertArrayEquals(a.helloRetryRequest(), b.helloRetryRequest());
            } else if (m instanceof Message.LinkOpen a && dec instanceof Message.LinkOpen b) {
                assertEquals(a.domain(), b.domain());
                assertEquals(a.chainPem(), b.chainPem());
                assertArrayEquals(a.domainProof(), b.domainProof());
            } else if (m instanceof Message.PeerProbe a && dec instanceof Message.PeerProbe b) {
                assertArrayEquals(a.nonce(), b.nonce());
            } else if (m instanceof Message.PeerProbeAnswer a && dec instanceof Message.PeerProbeAnswer b) {
                assertArrayEquals(a.nonce(), b.nonce());
                assertArrayEquals(a.mac(), b.mac());
                assertEquals(a.epoch(), b.epoch());
            } else if (m instanceof Message.SignResponse a && dec instanceof Message.SignResponse b) {
                assertArrayEquals(a.sig(), b.sig());
                assertEquals(a.reason(), b.reason());
            } else {
                assertEquals(m, dec, m.type());
            }
        }
    }

    @Test
    void wireFormIsCompact() {
        assertEquals("{\"t\":\"Hello\",\"proto\":1,\"version\":\"0.1.0\",\"os\":\"linux\",\"conn\":0}",
            Codec.encodeToString(new Message.Hello(1, "0.1.0", "linux", 0, null, 0)));
        assertEquals("{\"t\":\"RegisterResponse\",\"status\":\"pending\"}",
            Codec.encodeToString(Message.RegisterResponse.pending()));
    }

    @Test
    void rejectsUnknownAndMalformed() {
        // An unrecognised type is not in this list on purpose: it decodes to Message.Unknown so the
        // control channel survives a newer peer (ARCHITECTURE.md §5.4, WireFormatTest). Malformed
        // is still malformed.
        assertThrows(CodecException.class, () -> Codec.decode("{\"proto\":1}"));
        assertThrows(CodecException.class, () -> Codec.decode("{\"t\":\"Hello\",\"proto\":\"one\",\"version\":\"v\"}"));
        assertThrows(CodecException.class, () -> Codec.decode("not json"));
        assertThrows(CodecException.class, () -> Codec.decode("{\"t\":\"SignRequest\",\"streamId\":1,\"keyId\":\"k\",\"alg\":\"a\",\"digest\":\"***\"}"));
    }

    @Test
    void goodbyeDetailIsOptionalOnTheWire() throws Exception {
        // A hub that predates the field, or any Goodbye that has nothing to add, sends only the
        // reason; decoding must not fail or invent one.
        Message m = Codec.decode("{\"t\":\"Goodbye\",\"reason\":\"shutdown\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertTrue(m instanceof Message.Goodbye g && "shutdown".equals(g.reason()) && g.detail() == null, m.toString());
    }
}
