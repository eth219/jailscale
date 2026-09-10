package io.jailscale.hub;

import io.jailscale.proto.mux.Frame;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Raw TCP/UDP publishing (DESIGN.md §9.5): the hub listens on an assigned port and forwards
 * every visitor connection (TCP) or every visitor address (UDP, one DGRAM stream each) to the
 * node. No TLS, no SNI: bytes in, bytes out.
 */
final class RawPorts implements AutoCloseable {

    private static final Log LOG = Log.get("raw");
    static final long UDP_IDLE_MS = 60_000;
    private static final long UDP_SWEEP_MS = 5_000;

    private interface Listener extends AutoCloseable {
        @Override
        void close();
    }

    private final Hub hub;
    private final Map<String, Listener> listeners = new ConcurrentHashMap<>();

    RawPorts(Hub hub) {
        this.hub = hub;
    }

    /** Binds the link's port; throws if the port is not free on this host. */
    void start(Links.Link link) throws IOException {
        Listener l = Links.UDP.equals(link.kind()) ? new Udp(link) : new Tcp(link);
        Listener old = listeners.put(link.linkId(), l);
        if (old != null) {
            old.close();
        }
        LOG.info("{} port {} -> {} ({})", link.kind(), link.port(), link.local(), link.user());
    }

    void stop(Links.Link link) {
        Listener l = listeners.remove(link.linkId());
        if (l != null) {
            l.close();
        }
    }

    @Override
    public void close() {
        for (Listener l : new ArrayList<>(listeners.values())) {
            l.close();
        }
        listeners.clear();
    }

    private final class Tcp implements Listener {
        private final Links.Link link;
        private final ServerSocket server;

        Tcp(Links.Link link) throws IOException {
            this.link = link;
            server = new ServerSocket();
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(hub.config().listenHost(), link.port()), 64);
            Thread.ofVirtual().name("raw-tcp-" + link.port()).start(this::accept);
        }

        private void accept() {
            while (!server.isClosed()) {
                Socket s;
                try {
                    s = server.accept();
                } catch (IOException e) {
                    break;
                }
                Thread.ofVirtual().name("raw-tcp-" + link.port() + "-" + s.getPort()).start(() -> serve(s));
            }
        }

        private void serve(Socket s) {
            NodeGroup group = link.group();
            MuxStream stream = null;
            try {
                s.setTcpNoDelay(true);
                String ip = s.getInetAddress().getHostAddress();
                int port = s.getPort();
                s.setSoTimeout(SniRouter.HELLO_TIMEOUT_MS);
                io.jailscale.proto.net.ProxyProtocol.Header ph = hub.readProxyHeader(s);
                if (ph != null && ph.known()) {
                    ip = ph.srcIp();
                    port = ph.srcPort();
                }
                s.setSoTimeout(0);
                stream = group.openVisitor(link, null, ip, port, null, false);
                Relay.pump(s, stream, new byte[0]);
            } catch (IOException e) {
                LOG.debug("tcp {} visitor {} refused: {}", link.port(), s.getInetAddress(), e.getMessage());
                Relay.closeQuietly(s);
            } finally {
                if (stream != null) {
                    group.visitorDone(stream);
                }
            }
        }

        @Override
        public void close() {
            try {
                server.close();
            } catch (IOException ignored) {
                // closing
            }
        }
    }

    private final class Udp implements Listener {
        private record Flow(MuxStream stream, long[] lastSeen) {}

        private final Links.Link link;
        private final DatagramChannel channel;
        private final Map<SocketAddress, Flow> flows = new ConcurrentHashMap<>();
        private volatile boolean closed;

        Udp(Links.Link link) throws IOException {
            this.link = link;
            channel = DatagramChannel.open();
            channel.bind(new InetSocketAddress(hub.config().listenHost(), link.port()));
            Thread.ofVirtual().name("raw-udp-" + link.port()).start(this::receive);
            Thread.ofVirtual().name("raw-udp-sweep-" + link.port()).start(this::sweep);
        }

        private void receive() {
            ByteBuffer buf = ByteBuffer.allocate(Frame.MAX_DATA + 1);
            while (!closed) {
                SocketAddress from;
                try {
                    buf.clear();
                    from = channel.receive(buf);
                } catch (ClosedChannelException e) {
                    break;
                } catch (IOException e) {
                    LOG.debug("udp {} receive: {}", link.port(), e.getMessage());
                    continue;
                }
                if (from == null) {
                    continue;
                }
                buf.flip();
                if (buf.remaining() > Frame.MAX_DATA) {
                    LOG.debug("udp {}: dropping {}-byte datagram from {}", link.port(), buf.remaining(), from);
                    continue;
                }
                byte[] datagram = new byte[buf.remaining()];
                buf.get(datagram);
                Flow f = flows.get(from);
                if (f == null) {
                    f = open(from);
                    if (f == null) {
                        continue;
                    }
                }
                f.lastSeen()[0] = System.currentTimeMillis();
                try {
                    f.stream().send(datagram);
                } catch (IOException e) {
                    end(from, f);
                }
            }
        }

        private Flow open(SocketAddress from) {
            NodeGroup group = link.group();
            MuxStream stream;
            try {
                stream = group.openVisitor(link, null, ((InetSocketAddress) from).getAddress().getHostAddress(),
                    ((InetSocketAddress) from).getPort(), null, true);
            } catch (IOException e) {
                LOG.debug("udp {} visitor {} refused: {}", link.port(), from, e.getMessage());
                return null;
            }
            Flow f = new Flow(stream, new long[] {System.currentTimeMillis()});
            flows.put(from, f);
            Thread.ofVirtual().name("raw-udp-" + link.port() + "-back").start(() -> {
                try {
                    byte[] d;
                    while ((d = stream.receive()) != null) {
                        f.lastSeen()[0] = System.currentTimeMillis();
                        channel.send(ByteBuffer.wrap(d), from);
                    }
                } catch (IOException ignored) {
                    // flow over
                } finally {
                    end(from, f);
                }
            });
            return f;
        }

        private void end(SocketAddress from, Flow f) {
            if (flows.remove(from, f)) {
                f.stream().reset(0);
                link.group().visitorDone(f.stream());
            }
        }

        private void sweep() {
            while (!closed) {
                try {
                    Thread.sleep(UDP_SWEEP_MS);
                } catch (InterruptedException e) {
                    return;
                }
                long cutoff = System.currentTimeMillis() - UDP_IDLE_MS;
                for (Map.Entry<SocketAddress, Flow> e : flows.entrySet()) {
                    if (e.getValue().lastSeen()[0] < cutoff) {
                        end(e.getKey(), e.getValue());
                    }
                }
            }
        }

        @Override
        public void close() {
            closed = true;
            try {
                channel.close();
            } catch (IOException ignored) {
                // closing
            }
            for (Map.Entry<SocketAddress, Flow> e : flows.entrySet()) {
                end(e.getKey(), e.getValue());
            }
        }
    }
}
