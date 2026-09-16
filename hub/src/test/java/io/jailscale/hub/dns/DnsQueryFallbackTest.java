package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * ARCHITECTURE.md §11.5 and §13.3: {@link DnsQuery} asks over UDP and then over TCP.
 *
 * <p>This is what lets the responder meter every name. `_jailhub-self` was exempt from the answer
 * rate because the lookup for it gave up when a datagram did not come back, so an attacker able to
 * forge a source into the hub's own network could stop a hub learning its own address -- and an
 * exempt name is a name's worth of egress no budget bounds. The fallback removes the reason for the
 * exemption, so the fallback is the thing to hold: a server that answers on TCP and says nothing at
 * all on UDP must still be heard.
 */
@Timeout(60)
class DnsQueryFallbackTest {

    @Test
    void aQuestionUdpDoesNotAnswerIsAskedAgainOverTcp() throws Exception {
        DnsResponder zone = new DnsResponder("hub.example.com");
        zone.setTxt(List.of("only-over-tcp"));

        // One number, two sockets, as a real server has -- except that this one never reads its
        // datagrams. A bound and silent UDP socket is what a flood on the path looks like to the
        // caller: the question goes out and the answer does not come back.
        try (DatagramSocket silent = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
            ServerSocket tcp = new ServerSocket()) {
            int port = silent.getLocalPort();
            tcp.setReuseAddress(true);
            tcp.bind(new InetSocketAddress("127.0.0.1", port), 4);
            Thread.ofVirtual().start(() -> serve(tcp, zone));

            long started = System.nanoTime();
            List<String> got = DnsQuery.txt("127.0.0.1", port, "_acme-challenge.hub.example.com", 500);
            assertEquals(List.of("only-over-tcp"), got, "the TCP half answered what UDP would not");
            assertTrue(System.nanoTime() - started >= 400_000_000L,
                "and it waited for the datagram first, rather than skipping UDP");
        }
    }

    /** The zone, over TCP: a two-byte length, the question, and the answer the responder builds. */
    private static void serve(ServerSocket tcp, DnsResponder zone) {
        while (!tcp.isClosed()) {
            try (Socket s = tcp.accept()) {
                DataInputStream in = new DataInputStream(s.getInputStream());
                byte[] q = new byte[in.readUnsignedShort()];
                in.readFully(q);
                byte[] r = zone.respond(q);
                DataOutputStream out = new DataOutputStream(s.getOutputStream());
                out.writeShort(r.length);
                out.write(r);
                out.flush();
            } catch (IOException e) {
                return;
            }
        }
    }

    @Test
    void anAnswerForAnotherQuestionIsNotThisOne() throws Exception {
        // An off-path forgery guesses the id; one that guesses wrong used to end the lookup with
        // "bad DNS response". It now sends the caller to TCP, where guessing is not on offer.
        DnsResponder zone = new DnsResponder("hub.example.com");
        zone.setTxt(List.of("the-real-answer"));
        try (DatagramSocket wrong = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
            ServerSocket tcp = new ServerSocket()) {
            int port = wrong.getLocalPort();
            tcp.setReuseAddress(true);
            tcp.bind(new InetSocketAddress("127.0.0.1", port), 4);
            Thread.ofVirtual().start(() -> serve(tcp, zone));
            Thread.ofVirtual().start(() -> {
                try {
                    byte[] buf = new byte[512];
                    java.net.DatagramPacket p = new java.net.DatagramPacket(buf, buf.length);
                    wrong.receive(p);
                    byte[] forged = zone.respond(java.util.Arrays.copyOf(buf, p.getLength()));
                    forged[0] ^= 0x5a;  // somebody else\'s id
                    wrong.send(new java.net.DatagramPacket(forged, forged.length, p.getSocketAddress()));
                } catch (IOException ignored) {
                    // the test is over
                }
            });
            assertEquals(List.of("the-real-answer"),
                DnsQuery.txt("127.0.0.1", port, "_acme-challenge.hub.example.com", 2000));
        }
    }
}
