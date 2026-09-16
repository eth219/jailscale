package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The bound on how many connections TCP 53 holds at once (#114), and the counters that will size
 * its successor.
 *
 * <p>Until this, nothing bounded the accept loop and nothing counted it: one laptop held 16,126
 * connections open against this listener and stopped only because it ran out of its own ephemeral
 * ports, not because the server refused anything. Descriptors are process-wide, so that is the hub's
 * TLS, its node sessions and its relay being spent by an unauthenticated port.
 *
 * <p><b>Not a rate limit, and the difference is the point.</b> {@link ResponseRate} exists because a
 * datagram's source is a claim; a TCP source has completed a handshake and is a fact, so there is no
 * reflection here to meter. What is bounded is the descriptor, which is why the test below counts
 * connections held rather than queries answered.
 */
class DnsTcpBoundTest {

    private static final String HUB = "hub.example.com";

    /**
     * The bound under test, small on purpose. Filling the shipped
     * {@link DnsResponder#MAX_TCP_IN_FLIGHT} would mean standing up 256 loopback connections and
     * counting them before anything else moved, so what these assertions would really measure on a
     * loaded runner is a clock — which is the shape #125 was. Four races nothing. That the shipped
     * responder gets the constant is pinned separately.
     */
    private static final int BOUND = 4;

    /**
     * Longer than this class can take, so the connection deadline never expires under an assertion.
     * The shipped {@link DnsResponder#TCP_DEADLINE_MS} exists to stop anyone holding a slot, and
     * holding slots is exactly how the bound is filled below -- left at five seconds, a stall would
     * free the slots mid-test and what failed would be the clock rather than the bound.
     */
    private static final long PATIENT_DEADLINE_MS = 120_000;

    private static DnsResponder bounded() {
        return new DnsResponder(HUB, "token-test", BOUND, PATIENT_DEADLINE_MS);
    }

    @Test
    void theBoundIsAtTheConnectionItClaimsToBeAt() throws Exception {
        try (DnsResponder d = bounded()) {
            d.start("127.0.0.1", 0);
            List<Socket> held = new ArrayList<>();
            try {
                // Exactly the bound, all held open without a byte: every one of these is inside it.
                for (int i = 0; i < BOUND; i++) {
                    held.add(connect(d.port()));
                }
                // The accept loop runs on its own thread, so "held" on this side is not yet "counted"
                // on that one. Waiting for the count is the only honest way to say the bound is full.
                waitFor(() -> d.tcpInFlight() == BOUND,
                    () -> "in flight reached " + d.tcpInFlight() + " of " + BOUND);
                assertEquals(0, d.tcpRefused(), "nothing up to the bound should have been refused");

                // One more. It is closed unread, which is the whole behaviour: no answer, no error,
                // and from the resolver's side indistinguishable from the hub being gone.
                Socket over = connect(d.port());
                held.add(over);
                assertEquals(-1, over.getInputStream().read(), "the connection over the bound should be closed, not served");
                waitFor(() -> d.tcpRefused() == 1, () -> "refused counter reached " + d.tcpRefused());

                // And the bound is not a wall: give one back and the next is served, with a real
                // answer, so what was refused was the count and not the listener falling over.
                // Asserted at the exact count rather than "below the bound", which would also hold
                // if a second slot had come back on its own -- and a slot coming back on its own is
                // the deadline firing, which is the one thing this test must not be measuring.
                held.remove(0).close();
                waitFor(() -> d.tcpInFlight() == BOUND - 1,
                    () -> "in flight fell to " + d.tcpInFlight() + ", wanted exactly " + (BOUND - 1));
                byte[] q = DnsFuzzTest.query("_acme-challenge." + HUB, 16);
                try (Socket after = connect(d.port())) {
                    assertArrayEqualsAfterExchange(d, after, q);
                }
                assertEquals(1, d.tcpRefused(), "only the one over the bound should have been refused");
            } finally {
                for (Socket s : held) {
                    try {
                        s.close();
                    } catch (IOException ignored) {
                        // closing
                    }
                }
            }
        }
    }

    @Test
    void aSlotCannotBeHeldBeyondTheConnectionDeadlineByDribbling() throws Exception {
        // The bound is only worth having if a slot comes back. This used to be setSoTimeout(5000)
        // around DataInputStream.readFully, which bounds one read and is restarted by every byte
        // that arrives -- so a client declaring a 4,096-byte message and sending one byte every four
        // seconds held its slot for about four and a half hours, and the whole bound could be held
        // indefinitely for roughly 64 bytes a second. Deadline here, not timeout.
        long deadlineMs = 1_500;
        try (DnsResponder d = new DnsResponder(HUB, "token-test", BOUND, deadlineMs)) {
            d.start("127.0.0.1", 0);
            try (Socket s = connect(d.port())) {
                s.setSoTimeout(30_000);
                java.io.OutputStream out = s.getOutputStream();
                out.write(new byte[] {0x0f, (byte) 0xff});          // "4,095 bytes are coming"
                out.flush();
                long t0 = System.nanoTime();
                int got;
                try {
                    // A byte every 300 ms, forever if it were allowed: each one would restart a
                    // per-read timeout, and none of them restarts a deadline.
                    while (true) {
                        out.write(0);
                        out.flush();
                        Thread.sleep(300);
                        if (s.getInputStream().available() > 0 || s.isClosed()) {
                            break;
                        }
                        if (System.nanoTime() - t0 > 20_000_000_000L) {
                            break;
                        }
                    }
                    got = s.getInputStream().read();
                } catch (IOException e) {
                    got = -1;                                        // reset by the server: also gone
                }
                long ms = (System.nanoTime() - t0) / 1_000_000;
                assertEquals(-1, got, "the server should have given up on a client that never finishes");
                assertTrue(ms < 10_000, "it should give up at the deadline, not go on being fed; took " + ms + " ms");
            }
            waitFor(() -> d.tcpInFlight() == 0, () -> "the slot came back; in flight is " + d.tcpInFlight());
        }
    }

    @Test
    void theShippedResponderGetsTheShippedBound() {
        // The two tests above run at BOUND, so without this a default responder could be handed any
        // number -- nought, or Integer.MAX_VALUE, which is the same as the unbounded loop this
        // replaces -- and both of them would stay green.
        try (DnsResponder d = new DnsResponder(HUB)) {
            assertEquals(DnsResponder.MAX_TCP_IN_FLIGHT, d.maxTcpInFlight());
        }
        assertTrue(DnsResponder.MAX_TCP_IN_FLIGHT > 0 && DnsResponder.MAX_TCP_IN_FLIGHT < 1024,
            "far above what this zone sends to TCP and far below a descriptor budget the whole "
                + "process shares, including on a host that never raised it from 1,024: " + DnsResponder.MAX_TCP_IN_FLIGHT);
        // The bound is a count and the deadline is what makes the count recycle; a bound with no
        // deadline is slots held for as long as the other end likes, which is what this replaced.
        assertTrue(DnsResponder.TCP_DEADLINE_MS > 0 && DnsResponder.TCP_DEADLINE_MS <= 30_000,
            "a query and its answer is one round trip on an established socket: " + DnsResponder.TCP_DEADLINE_MS + " ms");
    }

    @Test
    void everyConnectionIsCountedWhetherOrNotItAsksAnything() throws Exception {
        // The denominator. A refused connection is still an accepted one, or the refusal rate has
        // nothing to be a rate of -- which is the shape the UDP counters were nearly given too.
        try (DnsResponder d = bounded()) {
            d.start("127.0.0.1", 0);
            assertEquals(0, d.tcpAccepted());
            assertEquals(0, d.tcpInFlight());
            byte[] q = DnsFuzzTest.query("_acme-challenge." + HUB, 16);
            for (int i = 0; i < 3; i++) {
                try (Socket s = connect(d.port())) {
                    assertArrayEqualsAfterExchange(d, s, q);
                }
            }
            waitFor(() -> d.tcpAccepted() == 3, () -> "accepted reached " + d.tcpAccepted());
            // And they are given back: a served connection that closes does not hold its place.
            waitFor(() -> d.tcpInFlight() == 0, () -> "in flight fell back to " + d.tcpInFlight());
            assertEquals(0, d.tcpRefused());
        }
    }

    private static Socket connect(int port) throws IOException {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress("127.0.0.1", port), 2000);
            s.setSoTimeout(5000);
            return s;
        } catch (IOException e) {
            s.close();
            throw e;
        }
    }

    /** One framed query and its answer, which has to be what the encoder would have built. */
    private static void assertArrayEqualsAfterExchange(DnsResponder d, Socket s, byte[] q) throws IOException {
        DataOutputStream out = new DataOutputStream(s.getOutputStream());
        out.writeShort(q.length);
        out.write(q);
        out.flush();
        DataInputStream in = new DataInputStream(s.getInputStream());
        byte[] answer = new byte[in.readUnsignedShort()];
        in.readFully(answer);
        org.junit.jupiter.api.Assertions.assertArrayEquals(d.respond(q), answer, "a connection inside the bound is served normally");
    }

    private interface Check {
        boolean ok();
    }

    /** Polls a count the accept loop owns, and says what it actually reached when it does not. */
    private static void waitFor(Check c, java.util.function.Supplier<String> got) throws Exception {
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            if (c.ok()) {
                return;
            }
            Thread.sleep(20);
        }
        assertTrue(false, got.get());
    }
}
