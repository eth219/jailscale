package io.jailscale.proto.net;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Ports for the tests, handed out so that two of them cannot be given the same one.
 *
 * <p>The idiom this replaces was everywhere: open a socket on port 0, read the number, close it,
 * and bind that number later. Between the close and the bind the port belongs to nobody, and the
 * next thing in the same JVM that asks the kernel for an ephemeral port can be handed it -- so a
 * hub started in {@code @BeforeEach} found its own port taken by an echo server two lines further
 * down. That is not a rare shape: it failed three times on one day in three different test classes
 * and on two operating systems, and once on {@code main} in the {@code budget} job, which pull
 * requests do not run (jailscale#108).
 *
 * <p><b>Both halves are needed.</b> Remembering what {@link #reserve} has given out stops this
 * class handing the same number twice, which was never the common failure; the failure was an
 * unrelated listener being handed a number already promised to something else. So {@link #listen}
 * exists too, and the listeners the tests open themselves go through it: it re-rolls when the
 * kernel offers a port this class has promised, holding the refused sockets open until it has one,
 * because letting them go is how the kernel comes to offer the same number again.
 *
 * <p>Surefire runs one JVM per module with no parallelism, so no two callers here run at once.
 * <b>What this does not cover</b>, and what a reserved port can still be lost to:
 * <ul>
 *   <li>a listener the code under test opens on port 0 -- every hub started in a test binds a DNS
 *       TCP/UDP pair that way, and the plain-HTTP front too, so a number
 *       reserved and not yet bound can be handed to one of them. It happened four times in two days
 *       (#196). A hub's listen port is no longer exposed to it: {@link #listen} hands over a bound
 *       socket and {@code Hub.listenOn} takes it, so nothing is ever unheld. Reserving immediately
 *       before the bind does not help when the thing in between is {@code Hub.start()}, which draws
 *       port 0 up to sixteen times of its own ({@code DnsResponder.PAIR_TRIES}, which is where
 *       that number lives);</li>
 *   <li>the DNS suites ({@code DnsResponderTest}, {@code DnsQueryFallbackTest},
 *       {@code ReferralTest}), which draw their own numbers because they are testing that draw;</li>
 *   <li>another process on the machine. The bind still fails, and the message says so rather than
 *       a number being quietly reused.</li>
 * </ul>
 */
public final class TestPorts {

    /** Every port this class has handed out or bound, for the life of the JVM. */
    private static final Set<Integer> TAKEN = ConcurrentHashMap.newKeySet();
    /** Enough re-rolls that exhausting them means something other than bad luck. */
    private static final int ATTEMPTS = 64;

    private TestPorts() {
    }

    /**
     * A loopback port for something that will bind it itself, later: a daemon's, a peer's, a raw
     * port range, or a port a test wants nothing listening on. The number is remembered, so nothing
     * else here is given it.
     *
     * <p><b>Not for a hub's listen port any more.</b> The residual below is real and a hub lost that
     * race four times in two days (#196), three of them inside {@code Hub.start}. A hub takes an
     * already-bound socket now — {@link #listen} and {@code Hub.listenOn} — so the number is never
     * unheld. What is left here is the shapes that cannot take a bound socket: something in another
     * process binds it, or the whole point is that nothing does.
     */
    public static int reserve() throws IOException {
        List<ServerSocket> refused = new ArrayList<>();
        try {
            for (int i = 0; i < ATTEMPTS; i++) {
                ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
                int port = s.getLocalPort();
                if (TAKEN.add(port)) {
                    // Closed before returning, because the caller is the one that binds it. That
                    // is the residual this class cannot remove: between here and their bind the
                    // port is held by nothing, so anything else in this JVM that asks the kernel
                    // for one -- including a listener the code under test opens on port 0 -- can
                    // be given it. The class comment lists what that means in practice; the short
                    // of it is to call this immediately before the bind it is for.
                    s.close();
                    return port;
                }
                // Held rather than closed while the loop turns, for the reason listen() holds
                // them: a port let go here is one the kernel may offer again on the next try.
                refused.add(s);
            }
            throw new IOException("no unused loopback port in " + ATTEMPTS + " tries");
        } finally {
            for (ServerSocket s : refused) {
                s.close();
            }
        }
    }

    /** A listener on loopback, on a port nothing else here has been promised. */
    public static ServerSocket listen(int backlog) throws IOException {
        List<ServerSocket> refused = new ArrayList<>();
        try {
            for (int i = 0; i < ATTEMPTS; i++) {
                ServerSocket s = new ServerSocket(0, backlog, InetAddress.getLoopbackAddress());
                if (TAKEN.add(s.getLocalPort())) {
                    return s;
                }
                // Held, not closed: a port let go here is one the kernel may offer again on the
                // next turn of this loop, and then this would spin rather than move on.
                refused.add(s);
            }
            throw new IOException("no unpromised loopback port in " + ATTEMPTS + " tries");
        } finally {
            for (ServerSocket s : refused) {
                s.close();
            }
        }
    }

    /**
     * The first of {@code n} consecutive ports free for TCP <em>and</em> UDP on loopback, for the
     * hub's raw-port range (ARCHITECTURE.md §8.4). Scanned rather than asked for, because the
     * kernel has no way to be asked for a run of them, and remembered like the rest so two test
     * classes cannot scan their way to the same base.
     */
    public static int reserveRange(int n) throws IOException {
        outer:
        for (int base = 20_000; base < 60_000; base += n) {
            for (int p = base; p < base + n; p++) {
                if (TAKEN.contains(p)) {
                    continue outer;
                }
                try (ServerSocket t = new ServerSocket(); DatagramSocket u = new DatagramSocket(null)) {
                    t.setReuseAddress(true);
                    t.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), p));
                    u.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), p));
                } catch (IOException e) {
                    continue outer;
                }
            }
            for (int p = base; p < base + n; p++) {
                TAKEN.add(p);
            }
            return base;
        }
        throw new IOException("no free range of " + n + " ports between 20000 and 60000");
    }
}
