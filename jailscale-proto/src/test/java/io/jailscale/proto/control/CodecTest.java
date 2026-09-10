package io.jailscale.proto.control;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Test;

class CodecTest {

    @Test
    void everyMessageRoundTrips() throws Exception {
        Message[] all = {
            new Message.Hello(1, "0.1.0", "macos", 2),
            new Message.HelloResponse(1, 1, "0.1.0", "hub.example.com"),
            new Message.Goodbye(Message.Goodbye.UPGRADE_REQUIRED),
            new Message.Ping(7), new Message.Pong(7),
            new Message.RegisterRequest("wq-macbook", "macos", "wq", "9f1c", null, null),
            new Message.RegisterRequest("ci-1", "linux", null, null, null, "jk_abc"),
            Message.RegisterResponse.approved(12, "wq"),
            Message.RegisterResponse.pending(),
            Message.RegisterResponse.rejected("invite-expired"),
            new Message.HubKeyRotation("hkey:AAAA", 1789000000L),
            new Message.InviteCreate("bob", 3, 86400, false),
            new Message.InviteCreate(null, 0, 0, true),
            new Message.InviteCreated("https://hub/join/x", "7F3K-92QX", 1789000000L),
            new Message.AdminLinkRequest(),
            new Message.AdminLink("https://hub/admin/login/x", 1789000060L),
            new Message.Error("InviteCreate", "policy"),
            new Message.CertUpdate(List.of("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"), "sha256:ab"),
            new Message.LinkOpen("https", "myapp", null, null, "127.0.0.1:3000", null),
            new Message.LinkOpen("tcp", null, null, 10022, "127.0.0.1:22", null),
            new Message.LinkOpen("https", null, "app.example.com", null, "127.0.0.1:3000", java.util.List.of("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")),
            new Message.Ack("ChallengeSet"),
            new Message.LinkOpened("l1", "myapp", "https://myapp.hub.example.com", null, null),
            new Message.LinkOpened(null, null, null, null, "taken"),
            new Message.LinkClose("l1"),
            new Message.SignRequest((2L << 24) | 40, "sha256:ab", "ECDSA-P256-SHA256", new byte[] {1, 2, 3}),
            new Message.SignResponse(40, new byte[] {4, 5}, null),
            new Message.SignResponse(40, null, "not-your-stream"),
            new Message.ChallengeSet("tok", "tok.thumb"),
            new Message.ChallengeClear("tok"),
        };
        for (Message m : all) {
            byte[] enc = Codec.encode(m);
            Message dec = Codec.decode(enc);
            assertEquals(m.type(), dec.type());
            if (m instanceof Message.SignRequest a && dec instanceof Message.SignRequest b) {
                assertEquals(a.streamId(), b.streamId());
                assertArrayEquals(a.digest(), b.digest());
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
            Codec.encodeToString(new Message.Hello(1, "0.1.0", "linux", 0)));
        assertEquals("{\"t\":\"RegisterResponse\",\"status\":\"pending\"}",
            Codec.encodeToString(Message.RegisterResponse.pending()));
    }

    @Test
    void rejectsUnknownAndMalformed() {
        assertThrows(CodecException.class, () -> Codec.decode("{\"t\":\"Nope\"}"));
        assertThrows(CodecException.class, () -> Codec.decode("{\"proto\":1}"));
        assertThrows(CodecException.class, () -> Codec.decode("{\"t\":\"Hello\",\"proto\":\"one\",\"version\":\"v\"}"));
        assertThrows(CodecException.class, () -> Codec.decode("not json"));
        assertThrows(CodecException.class, () -> Codec.decode("{\"t\":\"SignRequest\",\"streamId\":1,\"keyId\":\"k\",\"alg\":\"a\",\"digest\":\"***\"}"));
    }
}
