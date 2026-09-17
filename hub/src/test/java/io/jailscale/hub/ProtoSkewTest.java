package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.crypto.KeyText;
import io.jailscale.crypto.NoiseIk;
import io.jailscale.crypto.X25519;
import io.jailscale.proto.control.Codec;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.mux.NoiseChannel;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.net.URI;
import java.nio.file.Path;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * What the hub answers a node whose protocol is not its own (ARCHITECTURE.md §5.4).
 *
 * <p>{@code Message.PROTO} and {@code NodeSession.MIN_PROTO} are both 1 today, so the branch that
 * refuses an old node has never run against a live peer: what was tested was the codec round trip
 * of {@code Goodbye(upgrade-required)}, which is the message and not the decision. The decision is
 * the thing that matters at a flag day -- a hub and its nodes are redeployed one after the other,
 * never at the same instant, so a mixed pair is the normal state of an upgrade and not an edge
 * case. This speaks the wire the way a node does (TLS, {@code POST /v1/noise}, Noise IK with the
 * hub's own prologue) with the protocol number as the only variable.
 *
 * <p>It uses the hub's constants, not the node's, so it is a statement about what the hub promises
 * rather than about the two halves agreeing with each other.
 */
@Timeout(60)
class ProtoSkewTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private int port;

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("jps");
        java.net.ServerSocket portSocket = TestPorts.listen(1024);
        port = portSocket.getLocalPort();
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.listenOn(portSocket);
        hub.start();
    }

    @AfterEach
    void stop() throws Exception {
        hub.close();
    }

    /**
     * A node's first message and the hub's answer to it, with the machine key thrown away
     * afterwards. Everything here is what {@code HubClient.connect} does; the protocol number in
     * the Hello is the only thing a caller varies.
     */
    private Message hello(int proto, int conn) throws Exception {
        SSLContext ctx = Tls.clientContext(CERT, false);
        try (SSLSocket s = Tls.connect(ctx, "hub.test", "127.0.0.1", port, false, 10_000)) {
            Http.writeRequest(s.getOutputStream(), "POST", "hub.test", "/v1/noise",
                new Headers().add("Connection", "Upgrade").add("Upgrade", HttpFront.UPGRADE_PROTOCOL), new byte[0]);
            HttpResponse r = Http.readResponse(s.getInputStream(), 4096);
            assertEquals(101, r.status(), "the hub would not upgrade the connection: " + r.bodyText());
            NoiseIk hs = NoiseIk.initiator(HubKeys.PROLOGUE, X25519.generate(),
                KeyText.parse(KeyText.HUB, hub.keys().publicText()));
            byte[][] answer = new byte[1][];
            NoiseChannel ch = NoiseChannel.initiate(s.getInputStream(), s.getOutputStream(), hs,
                Codec.encode(new Message.Hello(proto, "9.9.9", "linux", conn, null, 0)), answer);
            ch.close();
            return Codec.decode(answer[0]);
        }
    }

    @Test
    void aNodeSpeakingAnOlderProtocolIsToldToUpgradeAndNamedBothVersions() throws Exception {
        Message m = hello(NodeSession.MIN_PROTO - 1, 0);
        Message.Goodbye g = assertInstanceOf(Message.Goodbye.class, m,
            "an old node has to be answered, not dropped: it never gets a HelloResponse, so this "
                + "message is the only place the numbers can reach it");
        assertEquals(Message.Goodbye.UPGRADE_REQUIRED, g.reason());
        // The detail is the only thing the node can print, so it has to carry the hub's floor, the
        // node's own number, and something to do about it.
        assertTrue(g.detail().contains("protocol " + NodeSession.MIN_PROTO), g.detail());
        assertTrue(g.detail().contains(String.valueOf(NodeSession.MIN_PROTO - 1)), g.detail());
        assertTrue(g.detail().contains("jailscale up"), g.detail());
        // And it got nothing else: a refused node is not registered and holds no session.
        assertEquals(0, hub.registry().size(), "a refused node was left attached to the hub");
    }

    @Test
    void aNodeSpeakingTheHubsOwnProtocolIsToldTheFloorAndTheSuffix() throws Exception {
        Message m = hello(Message.PROTO, 0);
        Message.HelloResponse r = assertInstanceOf(Message.HelloResponse.class, m, String.valueOf(m));
        assertEquals(Message.PROTO, r.proto());
        assertEquals(NodeSession.MIN_PROTO, r.minProto());
        assertEquals("hub.test", r.dnsSuffix());
    }

    @Test
    void aNodeNewerThanTheHubIsNotRefusedHere() throws Exception {
        // The floor is a floor, not an equality: a node from a later release has to be able to
        // connect and find out what the hub speaks, which is what minProto in the answer is for.
        // Refusing here instead would make every upgrade a flag day in both directions.
        Message m = hello(Message.PROTO + 7, 0);
        Message.HelloResponse r = assertInstanceOf(Message.HelloResponse.class, m, String.valueOf(m));
        assertEquals(NodeSession.MIN_PROTO, r.minProto());
    }

    @Test
    void theHubCannotDemandMoreThanItSpeaks() {
        // Bumping one of these without the other is the flag-day mistake this catches: a MIN_PROTO
        // above PROTO refuses every node in existence, including the ones built from that commit.
        assertTrue(NodeSession.MIN_PROTO <= Message.PROTO,
            "MIN_PROTO=" + NodeSession.MIN_PROTO + " is above the PROTO=" + Message.PROTO + " this hub speaks");
    }

    /**
     * The same callback refuses a connection index it cannot use, and the two rules that can do it
     * are asserted one at a time. An index at {@link NodeSession#MAX_CONNECTIONS} is deliberately
     * not the case used: for a machine key the hub has never seen, both the range rule and the
     * "extra connection from an unregistered node" rule are true at once, so the test would pass
     * with either of them deleted. It did, until the rule it was supposed to be about was removed
     * and nothing went red.
     */
    @Test
    void aNegativeConnectionIndexIsRefusedByName() throws Exception {
        Message.Goodbye g = assertInstanceOf(Message.Goodbye.class, hello(Message.PROTO, -1));
        assertEquals("bad-connection-index", g.reason());
        assertNull(g.detail(), "this one is for a peer that is broken, not for a person to read");
        assertEquals(0, hub.registry().size());
    }

    @Test
    void anExtraConnectionFromANodeTheHubHasNeverSeenIsRefused() throws Exception {
        // Connection 0 is the one that registers (§5.3). Arriving on a later index without it means
        // the hub has no node to attach the session to, whatever the index says.
        Message.Goodbye g = assertInstanceOf(Message.Goodbye.class, hello(Message.PROTO, 1));
        assertEquals("bad-connection-index", g.reason());
        assertEquals(0, hub.registry().size());
    }
}
