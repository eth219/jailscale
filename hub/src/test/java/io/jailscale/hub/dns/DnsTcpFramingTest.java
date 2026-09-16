package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The frame around a DNS message on TCP (RFC 1035 §4.2.2): a two-byte length and then that many
 * bytes. {@link DnsResponder#respond} is the same call on both transports and is covered
 * thoroughly on the UDP side, and the well-formed exchange is pinned by
 * {@code DnsResponderTest.theTcpListenerIsOnTheNumberThePairWasBoundTo}, which drives a TXT set
 * too large for a datagram through it. What had no test at all is the rest of {@code serveTcp}
 * (#113): the ceiling on the prefix, a prefix that does not match what follows, and a connection
 * that sends something other than a question or nothing at all.
 *
 * <p><b>A closed connection is the correct answer to nearly all of this</b>, which would make four
 * of these tests the same test if the assertion were only "it closed". What separates them is
 * <em>when</em> it closed: a guard that fires closes in about a millisecond, and a read that gives
 * up closes at {@code serveTcp}'s own timeout. So the bound is the assertion, and it is tight
 * enough to tell those two apart — a bound of "sometime before the read timeout" would pass a
 * server with no guard at all and a shorter timeout, which is how this class was written the first
 * time.
 */
class DnsTcpFramingTest {

    private static final String HUB = "hub.example.com";
    private static final String CHALLENGE = "_acme-challenge." + HUB;
    private static final int TYPE_TXT = 16;

    /**
     * A guard that fires closes the connection before it reads anything, which is under a
     * millisecond on loopback. A whole second is three orders of magnitude of slack for a loaded
     * runner and still far below any read timeout worth setting, so this separates "the ceiling
     * fired" from "the read gave up" without knowing what the read timeout is.
     */
    private static final long GUARD_FIRES_WITHIN_MS = 1000;

    /** Long enough that a server waiting on its own timeout is seen waiting, not seen timing out. */
    private static final int PATIENT_MS = 20_000;

    @Test
    void aPrefixOverTheCeilingIsDroppedWithoutWaitingForTheBytesItPromised() throws Exception {
        // len > 4096 returns before `new byte[len]`, so the ceiling bounds what a connection can
        // make this server allocate as well as what it reads: a 65,535-byte prefix costs nothing.
        try (DnsResponder d = new DnsResponder(HUB)) {
            d.start("127.0.0.1", 0);
            try (Conn c = Conn.to(d.port(), PATIENT_MS)) {
                c.writePrefix(65535);
                c.assertClosesWithin(GUARD_FIRES_WITHIN_MS);
            }
        }
    }

    @Test
    void theCeilingIsAtTheByteItClaimsToBeAt() throws Exception {
        // 4096 is allowed and 4097 is not, so `>=` here would be a different server. Neither is a
        // question and neither gets an answer; what tells them apart is that the allowed one is
        // waited for and the refused one is dropped on the spot.
        try (DnsResponder d = new DnsResponder(HUB)) {
            d.start("127.0.0.1", 0);
            try (Conn c = Conn.to(d.port(), PATIENT_MS)) {
                c.writePrefix(4097);
                c.assertClosesWithin(GUARD_FIRES_WITHIN_MS);
            }
            try (Conn c = Conn.to(d.port(), 500)) {
                c.writePrefix(4096);
                // Still holding when this socket's own timeout runs out is the claim, and it is the
                // cheap half of it: waiting out the server's timeout to watch it close would cost
                // five seconds a run to learn nothing this does not already say.
                c.assertStillHolding();
            }
        }
    }

    @Test
    void aPrefixLongerThanWhatFollowsIsClosedRatherThanAnsweredWithWhatArrived() throws Exception {
        // readFully throws EOFException and it is swallowed as "client gone", which is right. What
        // this pins is that a short frame is never answered from the bytes that did arrive: half a
        // question that happens to parse is still not the question that was asked.
        try (DnsResponder d = new DnsResponder(HUB)) {
            d.start("127.0.0.1", 0);
            d.setTxt(List.of("one"));
            byte[] q = DnsFuzzTest.query(CHALLENGE, TYPE_TXT);
            try (Conn c = Conn.to(d.port(), PATIENT_MS)) {
                c.writePrefix(q.length + 10);            // promise ten bytes that never come
                c.write(q);
                c.finishSending();                       // EOF, so the server stops waiting at once
                assertEquals(-1, c.read(), "a frame that was cut short should be closed, not answered");
            }
        }
    }

    @Test
    void aZeroLengthFrameIsNotAQuestionAndIsNotAnswered() throws Exception {
        try (DnsResponder d = new DnsResponder(HUB)) {
            d.start("127.0.0.1", 0);
            try (Conn c = Conn.to(d.port(), PATIENT_MS)) {
                c.writePrefix(0);
                c.finishSending();
                assertEquals(-1, c.read(), "an empty message is under the twelve-byte header and answers nothing");
            }
        }
    }

    @Test
    void aReplySentToTheServerIsIgnoredOverTcpAsItIsOverUdp() throws Exception {
        // The UDP side pins this in DnsResponderTest.ignoresGarbageAndResponses. Over TCP the same
        // input has a second way to go wrong: `respond` returns null and nothing may be written, so
        // an empty frame would be a reply to something that was not a question.
        try (DnsResponder d = new DnsResponder(HUB)) {
            d.start("127.0.0.1", 0);
            byte[] reply = DnsFuzzTest.query(CHALLENGE, TYPE_TXT);
            reply[2] |= (byte) 0x80;                     // QR: this is an answer, not a question
            try (Conn c = Conn.to(d.port(), PATIENT_MS)) {
                c.writeFrame(reply);
                c.finishSending();
                assertEquals(-1, c.read(), "a response is not answered, and no empty frame is sent either");
            }
        }
    }

    @Test
    void aConnectionThatSendsNothingIsLetGoRatherThanHeld() throws Exception {
        // The only thing between this server and a connection held open for as long as the other
        // end likes. Both halves are asserted, and neither names the timeout's value: it is not
        // dropped at once, and it does not last.
        try (DnsResponder d = new DnsResponder(HUB)) {
            d.start("127.0.0.1", 0);
            try (Conn c = Conn.to(d.port(), 500)) {
                c.assertStillHolding();
                c.patience(PATIENT_MS);
                c.assertClosesWithin(PATIENT_MS);
            }
        }
    }

    /** A raw connection to the responder's TCP side, so a test can write a frame that is not one. */
    private record Conn(Socket socket, DataInputStream in, DataOutputStream out) implements AutoCloseable {

        static Conn to(int port, int timeoutMs) throws IOException {
            Socket s = new Socket();
            try {
                s.connect(new InetSocketAddress("127.0.0.1", port), 2000);
                s.setSoTimeout(timeoutMs);
                return new Conn(s, new DataInputStream(s.getInputStream()), new DataOutputStream(s.getOutputStream()));
            } catch (IOException | RuntimeException e) {
                s.close();
                throw e;
            }
        }

        void patience(int timeoutMs) throws IOException {
            socket.setSoTimeout(timeoutMs);
        }

        void writePrefix(int len) throws IOException {
            out.writeShort(len);
            out.flush();
        }

        void write(byte[] b) throws IOException {
            out.write(b);
            out.flush();
        }

        void writeFrame(byte[] message) throws IOException {
            writePrefix(message.length);
            write(message);
        }

        /** Nothing more is coming: the server sees EOF rather than waiting out its own timeout. */
        void finishSending() throws IOException {
            socket.shutdownOutput();
        }

        int read() throws IOException {
            return in.read();
        }

        /**
         * That the server closed, and did it inside {@code boundMs}. A server that holds on is
         * reported as holding on rather than as this socket's timeout expiring, because the
         * distinction is the whole point of every caller.
         */
        void assertClosesWithin(long boundMs) throws IOException {
            long t0 = System.nanoTime();
            int got;
            try {
                got = in.read();
            } catch (SocketTimeoutException e) {
                throw new AssertionError("the server was still holding the connection "
                    + socket.getSoTimeout() + " ms later; expected it to close within " + boundMs + " ms");
            }
            long ms = (System.nanoTime() - t0) / 1_000_000;
            assertEquals(-1, got, "expected the server to close, and it answered");
            assertTrue(ms <= boundMs, "the server closed, but took " + ms + " ms and the bound is " + boundMs + " ms");
        }

        /** That the server is still holding when this socket's own timeout runs out. */
        void assertStillHolding() throws IOException {
            try {
                assertEquals(-1, in.read(), "expected the server to still be holding, and it answered");
                throw new AssertionError("the server closed the connection rather than waiting for the frame");
            } catch (SocketTimeoutException expected) {
                // Nothing came and nothing closed: it is waiting, which is the claim.
            }
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }
}
