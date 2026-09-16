package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
        try (Pair p = pair()) {
            int port = p.port();
            Thread.ofVirtual().start(() -> serve(p.tcp, zone));

            long started = System.nanoTime();
            List<String> got = DnsQuery.txt("127.0.0.1", port, "_acme-challenge.hub.example.com", 500);
            assertEquals(List.of("only-over-tcp"), got, "the TCP half answered what UDP would not");
            assertTrue(System.nanoTime() - started >= 400_000_000L,
                "and it waited for the datagram first, rather than skipping UDP");
        }
    }

    @Test
    void aTrickleOnTheTcpPathIsBoundedByOneDeadlineAndNotByOneRead() throws Exception {
        // A per-read timeout bounds the pieces, not the message: a peer that sends one byte just
        // inside it makes progress forever. `Hub.checkAddress` asks this while holding a lock and
        // while answering an operator's command, so the fallback has to be bounded as a whole.
        try (Pair p = pair()) {
            Thread.ofVirtual().start(() -> {
                try (java.net.Socket s = p.tcp.accept()) {
                    s.getOutputStream().write(new byte[] {0x10, 0x00});  // 4,096 bytes to come
                    for (int i = 0; i < 4096; i++) {
                        s.getOutputStream().write(0);
                        s.getOutputStream().flush();
                        Thread.sleep(50);                                // ... one at a time
                    }
                } catch (IOException | InterruptedException ignored) {
                    // the caller gave up, which is the point
                }
            });
            long started = System.nanoTime();
            assertThrows(IOException.class,
                () -> DnsQuery.txt("127.0.0.1", p.port(), "_acme-challenge.hub.example.com", 300));
            long ms = (System.nanoTime() - started) / 1_000_000L;
            assertTrue(ms < 10_000, "the whole exchange should be bounded, gave up after " + ms + " ms");
        }
    }

    /**
     * A TCP listener and a UDP socket on one number, drawn the way {@code DnsResponder.start} draws
     * them since #102: the number comes from TCP and UDP is asked for the twin, since the reverse
     * order lost that race on Windows. Neither socket asks for reuse -- an exclusive bind is what
     * makes "the twin is free" mean anything, and SO_REUSEADDR on Windows would let this bind on
     * top of a listener that is already there and then test that listener instead of this one.
     */
    private static Pair pair() throws IOException {
        IOException last = null;
        for (int attempt = 0; attempt < 32; attempt++) {
            ServerSocket tcp = new ServerSocket();
            try {
                tcp.bind(new InetSocketAddress("127.0.0.1", 0), 4);
                return new Pair(tcp, new DatagramSocket(new InetSocketAddress("127.0.0.1", tcp.getLocalPort())));
            } catch (IOException e) {
                last = e;
                tcp.close();
            }
        }
        throw new IOException("no number free for both TCP and UDP after 32 tries", last);
    }

    private record Pair(ServerSocket tcp, DatagramSocket udp) implements AutoCloseable {
        int port() {
            return tcp.getLocalPort();
        }

        @Override public void close() throws IOException {
            udp.close();
            tcp.close();
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
        try (Pair p = pair()) {
            Thread.ofVirtual().start(() -> serve(p.tcp, zone));
            Thread.ofVirtual().start(() -> {
                try {
                    byte[] buf = new byte[512];
                    java.net.DatagramPacket in = new java.net.DatagramPacket(buf, buf.length);
                    p.udp.receive(in);
                    byte[] forged = zone.respond(java.util.Arrays.copyOf(buf, in.getLength()));
                    forged[0] ^= 0x5a;  // somebody else\'s id
                    p.udp.send(new java.net.DatagramPacket(forged, forged.length, in.getSocketAddress()));
                } catch (IOException ignored) {
                    // the test is over
                }
            });
            assertEquals(List.of("the-real-answer"),
                DnsQuery.txt("127.0.0.1", p.port(), "_acme-challenge.hub.example.com", 2000));
        }
    }
}
