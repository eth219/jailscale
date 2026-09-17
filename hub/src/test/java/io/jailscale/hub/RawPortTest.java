package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.net.DuplexThread;
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
import java.nio.file.Path;
import java.util.Random;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/** ARCHITECTURE.md §8.4: raw TCP and UDP through hub-assigned ports. */
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
        TestCloseables.closeAll(node, hub, echoTcp, echoUdp);
    }

    /** The {@code ?from=} value in a directory page's "next" link. */
    private static String cursorOf(String html) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("/links\\?from=([^\"]+)").matcher(html);
        assertTrue(m.find(), html);
        return m.group(1);
    }

    @Test
    void tcpAndUdpThroughAssignedPorts() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("jr");
        java.net.ServerSocket portSocket = TestPorts.listen(1024);
        port = portSocket.getLocalPort();
        int lo = TestPorts.reserveRange(4);
        HubConfig cfg = HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test").withPortRange(lo, lo + 3);
        hub = new Hub(cfg);
        hub.listenOn(portSocket);
        hub.start();

        // Local echo servers.
        echoTcp = TestPorts.listen(8);
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

        // The directory is ordered by what each row says, not by the link's internal name. A raw
        // port is named "tcp/<port>" and drawn as "<hub>:<port>", so ordering by the name put it
        // under "t" -- after every https name up to "s" -- at a position matching nothing a reader
        // can see. Between "bravo" and "sierra" is where "hub.test:<port>" reads as belonging.
        for (String n : new String[] {"bravo", "sierra"}) {
            assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "open")
                .put("port", echoTcp.getLocalPort()).put("name", n).build()).optBool("ok", false));
        }
        String dir = hub.front().route(new HttpRequest("GET", "/links", "HTTP/1.1", new Headers(), null)).bodyText();
        int bravo = dir.indexOf("bravo.hub.test");
        int rawRow = dir.indexOf("hub.test:" + tcpPort);
        int sierra = dir.indexOf("sierra.hub.test");
        assertTrue(bravo >= 0 && rawRow >= 0 && sierra >= 0, dir);
        assertTrue(bravo < rawRow && rawRow < sierra, "the raw port is not where its address reads: " + dir);

        // The key doubles as the paging cursor, so it is read back by machine: by a standby, or by
        // this hub after a restart under a different LANG. A raw port's number goes into it, and
        // built in the JVM's default locale that number comes out in Arabic-Indic or Devanagari
        // digits -- so the same link yields a different cursor on two hosts of the same pair, and
        // neither can follow the other's "next page". The cursor has to be the same string
        // whatever the host is set to. Page size 1 so the emitted cursor is the raw port's own.
        HttpRequest page1 = new HttpRequest("GET", "/links", "HTTP/1.1", new Headers(), null);
        String here = cursorOf(hub.front().directory(page1, 1));
        java.util.Locale previous = java.util.Locale.getDefault();
        String elsewhere;
        try {
            java.util.Locale.setDefault(java.util.Locale.forLanguageTag("ar-EG"));
            elsewhere = cursorOf(hub.front().directory(page1, 1));
        } finally {
            java.util.Locale.setDefault(previous);
        }
        assertTrue(here.contains("hub.test"), "expected the raw port to be the cursor, got " + here);
        assertEquals(here, elsewhere, "the cursor must not follow the JVM's numbering system");

        // Bytes both ways, more than one frame, through hub port -> node -> local echo.
        byte[] payload = new byte[200_000];
        new Random(7).nextBytes(payload);
        try (Socket v = new Socket("127.0.0.1", tcpPort)) {
            // Windows cannot poll one socket for read and for write at once (DuplexThread): this
            // thread writes the visitor socket while the test thread reads it, which is the shape
            // that used to hang this test on Windows alone.
            Thread writer = DuplexThread.start("rawport-writer", () -> {
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

        // The `gate` command is refused on a raw link too, not only `open --gate`. It used to set
        // the gate, save it and print a visit link, while the raw path served every visitor
        // without looking at a token.
        JsonObject gate = Ipc.call(sock, JsonObject.builder().put("cmd", "gate").put("name", "tcp/" + tcpPort).build());
        assertTrue(!gate.optBool("ok", false), gate.toString());
        assertTrue(gate.toString().contains("https"), gate.toString());
        JsonObject rows = Ipc.call(sock, JsonObject.builder().put("cmd", "ls").build());
        assertTrue(!rows.toString().contains("\"gate\":true"), rows.toString());
        // and the port still serves, so the refusal did not break the link
        try (Socket v = new Socket("127.0.0.1", tcpPort)) {
            v.getOutputStream().write("hi".getBytes(StandardCharsets.UTF_8));
            v.getOutputStream().flush();
            v.shutdownOutput();
            assertArrayEquals("hi".getBytes(StandardCharsets.UTF_8), new DataInputStream(v.getInputStream()).readNBytes(2));
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
