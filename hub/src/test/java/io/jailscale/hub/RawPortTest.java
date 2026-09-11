package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** DESIGN.md §9.5: raw TCP and UDP through hub-assigned ports. */
@Timeout(90)
class RawPortTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private int port;
    private Daemon node;
    private ServerSocket echoTcp;
    private DatagramSocket echoUdp;

    @AfterEach
    void stop() throws Exception {
        if (node != null) {
            node.close();
        }
        if (hub != null) {
            hub.close();
        }
        if (echoTcp != null) {
            echoTcp.close();
        }
        if (echoUdp != null) {
            echoUdp.close();
        }
    }

    private static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return s.getLocalPort();
        }
    }

    /** First port of {@code n} consecutive ports that are free for both TCP and UDP on loopback. */
    private static int freeRange(int n) {
        outer:
        for (int base = 20000; base < 60000; base += n) {
            for (int p = base; p < base + n; p++) {
                try (ServerSocket t = new ServerSocket(); DatagramSocket u = new DatagramSocket(null)) {
                    t.setReuseAddress(true);
                    t.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), p));
                    u.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), p));
                } catch (IOException e) {
                    continue outer;
                }
            }
            return base;
        }
        throw new IllegalStateException("no free port range");
    }

    @Test
    void tcpAndUdpThroughAssignedPorts() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("jr");
        port = freePort();
        int lo = freeRange(4);
        HubConfig cfg = HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test").withPortRange(lo, lo + 3);
        hub = new Hub(cfg);
        hub.start();

        // Local echo servers.
        echoTcp = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            try {
                while (true) {
                    Socket s = echoTcp.accept();
                    Thread.ofVirtual().start(() -> {
                        try (s) {
                            s.getInputStream().transferTo(s.getOutputStream());
                        } catch (IOException ignored) {
                            // done
                        }
                    });
                }
            } catch (IOException ignored) {
                // closed
            }
        });
        echoUdp = new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        Thread.ofVirtual().start(() -> {
            byte[] buf = new byte[65536];
            try {
                while (true) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    echoUdp.receive(p);
                    byte[] reply = ("echo:" + new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
                    echoUdp.send(new DatagramPacket(reply, reply.length, p.getSocketAddress()));
                }
            } catch (IOException ignored) {
                // closed
            }
        });

        node = new Daemon(NodeConfig.in(root.resolve("node")));
        node.start();
        Path sock = root.resolve("node/jailscale.sock");
        JsonObject up = Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "alice").put("caFile", CERT.toString()).build());
        assertTrue(up.optBool("ok", false), up.toString());

        // --gate is refused for raw links; a plain https open still works alongside.
        assertTrue(!Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", echoTcp.getLocalPort()).put("kind", "tcp").put("gate", true).build())
            .optBool("ok", false));

        JsonObject tcp = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", echoTcp.getLocalPort()).put("kind", "tcp").build());
        assertTrue(tcp.optBool("ok", false), tcp.toString());
        int tcpPort = tcp.integer("hubPort");
        assertEquals("tcp://hub.test:" + tcpPort, tcp.string("url"));
        assertTrue(tcpPort >= lo && tcpPort <= lo + 3);

        // Bytes both ways, more than one frame, through hub port -> node -> local echo.
        byte[] payload = new byte[200_000];
        new Random(7).nextBytes(payload);
        try (Socket v = new Socket("127.0.0.1", tcpPort)) {
            Thread writer = Thread.ofVirtual().start(() -> {
                try {
                    v.getOutputStream().write(payload);
                    v.getOutputStream().flush();
                    v.shutdownOutput();
                } catch (IOException ignored) {
                    // read side reports
                }
            });
            byte[] got = new DataInputStream(v.getInputStream()).readNBytes(payload.length);
            assertArrayEquals(payload, got);
            writer.join();
        }

        // A second raw link gets a different port; a requested port is honoured.
        JsonObject udp = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", echoUdp.getLocalPort()).put("kind", "udp")
            .put("hubPort", lo + 2).build());
        assertTrue(udp.optBool("ok", false), udp.toString());
        assertEquals(lo + 2, udp.integer("hubPort"));
        assertNotEquals(tcpPort, udp.integer("hubPort"));

        try (DatagramSocket v = new DatagramSocket()) {
            v.setSoTimeout(10_000);
            InetSocketAddress hubAddr = new InetSocketAddress("127.0.0.1", lo + 2);
            for (int i = 0; i < 3; i++) {
                byte[] msg = ("ping" + i).getBytes(StandardCharsets.UTF_8);
                v.send(new DatagramPacket(msg, msg.length, hubAddr));
                DatagramPacket p = new DatagramPacket(new byte[1500], 1500);
                v.receive(p);
                assertEquals("echo:ping" + i, new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8));
            }
        }

        // Ports are stable across a reconnect: the same local target gets the same hub port.
        assertEquals(tcpPort, hub.store().portFor(node.machineKey(), "tcp", "127.0.0.1:" + echoTcp.getLocalPort()));
        JsonObject again = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", echoTcp.getLocalPort()).put("kind", "tcp").build());
        assertTrue(again.optBool("ok", false), again.toString());
        assertEquals(tcpPort, again.integer("hubPort"));

        // Close releases the listener.
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "close").put("name", "tcp/" + tcpPort).build()).optBool("ok", false));
        Thread.sleep(100);
        try (ServerSocket s = new ServerSocket()) {
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress("127.0.0.1", tcpPort));
        }

        // Exhausting the range is reported.
        JsonObject a = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", 1).put("kind", "tcp").build());
        JsonObject b = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", 2).put("kind", "tcp").build());
        JsonObject c = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", 3).put("kind", "tcp").build());
        assertTrue(a.optBool("ok", false) && b.optBool("ok", false), a + " " + b);
        assertTrue(!c.optBool("ok", false) && c.string("error").contains("no-free-port"), c.toString());
    }
}
