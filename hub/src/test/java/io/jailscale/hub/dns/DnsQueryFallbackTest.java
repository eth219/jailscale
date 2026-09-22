package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * ARCHITECTURE.md §11.5: {@link DnsQuery} asks over UDP and then over TCP.
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

    /** How many times {@link #pair()} tries before it gives up. */
    private static final int TRIES = 32;

    /**
     * How wide a band of held UDP ports the test below builds, in ports. Wider than {@link #TRIES},
     * and that is the whole point: a band no wider than the attempt budget is one a stepping loop
     * walks straight out of the top of, so the test would pass against the defect it is here to
     * catch. It did, before the band was widened.
     */
    private static final int BAND = TRIES + 16;

    @Test
    void theFixtureEscapesABandOfHeldTwinsRatherThanSteppingThroughIt() throws Exception {
        // #220. pair() is the fixture half of #181: it drew TCP, asked UDP for the twin, gave the
        // loser back and tried the next number up. Against a contiguous band of held twins that is
        // one chance taken TRIES times a port apart, which is what ran out on windows-2025 with
        // eight. Built here as a band and not as a coin flip.
        List<DatagramSocket> band = new ArrayList<>();
        Set<Integer> bandPorts = new HashSet<>();
        try {
            int from = drawTcpPort();
            // The window has to be made of port numbers: an allocator near the top of the range is
            // about to wrap, and InetSocketAddress reports that as IllegalArgumentException rather
            // than as the IOException the loop below catches.
            // 65_536 and not 65_535: the band's topmost port is from + BAND - 1, which is the
            // bound the loop below uses.
            assumeTrue(from + BAND <= 65_536,
                "the allocator drew " + from + ", within " + BAND + " of the top of the range");
            for (int port = from; port < from + BAND; port++) {
                DatagramSocket s = new DatagramSocket(null);
                try {
                    s.bind(new InetSocketAddress("127.0.0.1", port));
                    band.add(s);
                    bandPorts.add(port);
                } catch (IOException taken) {
                    // Somebody else has it. That is a hole, and a hole is only a problem inside the
                    // window checked below -- a number that comes free part-way through is one the
                    // old stepping loop could have landed on, so the premise is about the window
                    // and not about the whole range.
                    s.close();
                }
            }
            // Where the allocator is now, and therefore where a stepping loop would start. This
            // is deliberately the last draw before pair(): what follows binds nothing, so pair()'s
            // own first attempt is one step from here and the premises below are about it rather
            // than about somewhere the allocator was a while ago.
            int next = drawTcpPort();

            // Three premises, checked and not assumed. Without all of them there is nothing to
            // escape and this test would pass against the old stepping loop -- which it did, when
            // the band was only as wide as the budget and the loop stepped out of the top of it.
            assumeTrue(next >= from,
                "the allocator drew " + next + " after " + from + ", so it does not step and there is no band");
            assumeTrue(next + TRIES < from + BAND,
                "the allocator drew " + next + " after " + from + ", leaving fewer than " + TRIES
                    + " of the band above it, so a stepping loop could walk out of the top");
            for (int port = next; port <= next + TRIES; port++) {
                final int held = port;
                assumeTrue(bandPorts.contains(port),
                    () -> "the band has a hole at " + held + ", inside the " + TRIES
                        + " numbers a stepping loop would try, so it could succeed on the hole");
            }

            // Against the old loop this throws: every number it would step to is held. Against this
            // one, UDP draws on the second attempt and its allocator will not hand out a number it
            // has already given to the band.
            try (Pair p = pair()) {
                // One assertion and not two: the premise loop above put every number in
                // [next, next + TRIES] into bandPorts, so "not a number this test holds" already
                // says "not one a stepping loop would have reached".
                assertTrue(!bandPorts.contains(p.port()),
                    "drew " + p.port() + ", which this test is holding, so it did not escape the band");
                // And it is the pair this fixture promises, not merely a number: a TCP listener and
                // a UDP socket that both hold it.
                assertEquals(p.port(), p.udp().getLocalPort());
                assertTrue(p.tcp().isBound() && !p.tcp().isClosed());
            }
        } finally {
            for (DatagramSocket s : band) {
                s.close();
            }
        }
    }

    /**
     * A TCP port from the ephemeral range, given back before it is returned: where the allocator
     * is about to go.
     *
     * <p>{@code DnsResponderTest} has a method of this name too, and this is not a copy of it that
     * wants merging. Each probe has to bind the way the thing it is predicting binds, and the two
     * differ: that one mirrors {@code DnsResponder.start}, which asks for SO_REUSEADDR, and this
     * one mirrors {@link #pair()}, which deliberately does not -- the javadoc there says why. A
     * probe that bound unlike its subject would be predicting the wrong allocator.
     */
    private static int drawTcpPort() throws IOException {
        try (ServerSocket probe = new ServerSocket()) {
            probe.bind(new InetSocketAddress("127.0.0.1", 0), 4);
            return probe.getLocalPort();
        }
    }

    /**
     * A TCP listener and a UDP socket on one number, drawn with the same two ideas
     * {@code DnsResponder.start} took in #181 -- the sides alternate and the losers are held until
     * the search ends -- and not with the same code or the same numbers. What differs is listed at
     * the end of this comment, because "draws them the way start() does" was written here once and
     * was not true.
     *
     * <p>#102 settled that TCP should draw and UDP be asked for the twin, because a closed TCP port
     * is held for 2MSL where a closed UDP socket holds nothing, so TCP is the crowded space. That
     * is why TCP draws first here. It is not why it draws every time: #181 found a contiguous
     * <em>band</em> of held UDP twins on {@code windows-2025}, and a loop that steps one number at
     * a time walks into a band however many attempts it is given -- thirty-two included, which is
     * what this helper used to have. Whichever space is crowded, its own allocator will not hand
     * out a number it has already given away, so asking it to draw is what escapes a band. Losers
     * are held for the same reason: a number given back is one the next attempt may be handed
     * again.
     *
     * <p>Two things are deliberately not {@code start}'s. Neither socket here asks for reuse,
     * where both of {@code start}'s do: an exclusive bind is what makes "the twin is free" mean
     * anything, and SO_REUSEADDR on Windows would let this bind on top of a listener that is
     * already there and then test that listener instead of this one. And the budget is
     * {@value #TRIES} rather than {@code start}'s {@value DnsResponder#PAIR_TRIES}, which is what
     * it has always been -- a
     * fixture that cannot find a number fails one test, where a hub that cannot is a hub that did
     * not start.
     *
     * <p>Nor does this call {@code start}: the pair wanted here is a listener that never reads its
     * datagrams, which is the opposite of a responder. Whether the binding itself should be one
     * piece of code that both use is #221.
     */
    private static Pair pair() throws IOException {
        IOException last = null;
        // Every socket opened and not returned, so that none of them is still holding a number
        // after this method leaves -- by the return, the throw, or a RuntimeException from a bind.
        List<Closeable> held = new ArrayList<>();
        try {
            for (int attempt = 0; attempt < TRIES; attempt++) {
                ServerSocket tcp = new ServerSocket();
                held.add(tcp);
                try {
                    if (attempt % 2 == 0) {
                        tcp.bind(new InetSocketAddress("127.0.0.1", 0), 4);
                        DatagramSocket udp = new DatagramSocket(new InetSocketAddress("127.0.0.1", tcp.getLocalPort()));
                        held.remove(tcp);
                        return new Pair(tcp, udp);
                    }
                    // UDP draws. The socket is made first and bound by the constructor, so it is
                    // added to the held list before the TCP bind that may throw past it.
                    DatagramSocket udp = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
                    held.add(udp);
                    tcp.bind(new InetSocketAddress("127.0.0.1", udp.getLocalPort()), 4);
                    held.remove(tcp);
                    held.remove(udp);
                    return new Pair(tcp, udp);
                } catch (IOException e) {
                    last = e;
                }
            }
        } finally {
            for (Closeable c : held) {
                try {
                    c.close();
                } catch (IOException ignored) {
                    // Already gone, which is the only way close fails here.
                }
            }
        }
        throw new IOException("no number free for both TCP and UDP after " + TRIES + " tries", last);
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
