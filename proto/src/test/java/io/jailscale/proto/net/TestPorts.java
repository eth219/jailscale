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
import io.jailscale.proto.net.TestPorts;

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
 * exists too, and every listener in the tests goes through it: it re-rolls when the kernel offers a
 * port this class has promised, holding the refused sockets open until it has one, because letting
 * them go is how the kernel comes to offer the same number again.
 *
 * <p>Surefire runs one JVM per module with no parallelism, so every collision seen so far is
 * between two callers here. A port taken by another process on the machine is outside what this can
 * do anything about -- the bind still fails, and the message says so rather than a number being
 * quietly reused.
 */
public final class TestPorts {

    /** Every port this class has handed out or bound, for the life of the JVM. */
    private static final Set<Integer> TAKEN = ConcurrentHashMap.newKeySet();
    /** Enough re-rolls that exhausting them means something other than bad luck. */
    private static final int ATTEMPTS = 64;

    private TestPorts() {
    }

    /**
     * A loopback port for something that will bind it itself, later: a hub's listen port, a
     * daemon's, a peer's. The number is remembered, so nothing else here is given it.
     */
    public static int reserve() throws IOException {
        for (int i = 0; i < ATTEMPTS; i++) {
            int port;
            try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
                port = s.getLocalPort();
            }
            if (TAKEN.add(port)) {
                return port;
            }
        }
        throw new IOException("no unused loopback port in " + ATTEMPTS + " tries");
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
