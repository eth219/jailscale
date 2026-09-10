package io.jailscale.hub;

import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.tls.Sni;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Public port 443 (DESIGN.md §9.1): peek the ClientHello, then either terminate TLS for the
 * hub's own name, relay the raw bytes to the node serving {@code <name>.<hub>}, or answer with
 * a short page under the wildcard certificate.
 */
final class SniRouter {

    private static final Log LOG = Log.get("sni");
    static final int HELLO_TIMEOUT_MS = 5_000;
    static final int MAX_PER_IP = 64;
    static final int MAX_PER_NAME = 1024;
    static final long HOLD_MS = 3_000;

    private final Hub hub;
    private final Map<String, AtomicInteger> perIp = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> perName = new ConcurrentHashMap<>();

    SniRouter(Hub hub) {
        this.hub = hub;
    }

    /** Serves one accepted raw connection to completion. */
    void serve(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();
        AtomicInteger ipCount = perIp.computeIfAbsent(ip, k -> new AtomicInteger());
        if (ipCount.incrementAndGet() > MAX_PER_IP) {
            ipCount.decrementAndGet();
            Relay.closeQuietly(socket);
            return;
        }
        String name = null;
        try {
            socket.setTcpNoDelay(true);
            socket.setSoTimeout(HELLO_TIMEOUT_MS);
            Sni.Peek peek = Sni.peek(socket.getInputStream());
            String sni = peek.serverName();
            if (sni == null) {
                LOG.debug("{}: no SNI, closing", ip);
                Relay.closeQuietly(socket);
                return;
            }
            if (sni.equals(hub.config().hostname())) {
                hub.front().serve(layer(socket, peek.consumed(), hub.tls().context().getSocketFactory()));
                return;
            }
            name = hub.links().nameOf(sni);
            Links.Link link;
            if (name != null) {
                link = hub.links().byName(name);
                if (link == null && hub.store().nameOwner(name) != null) {
                    link = hub.links().awaitOnline(name, false, HOLD_MS); // node reconnecting (hand-off, restart)
                }
                if (link == null) {
                    fallback(socket, peek.consumed(), name);
                    return;
                }
            } else {
                // A user domain (DESIGN.md §9.4): passthrough only, the hub has no certificate to answer with.
                name = sni.toLowerCase(java.util.Locale.ROOT);
                link = hub.links().byDomain(name);
                if (link == null && hub.store().domain(name) != null) {
                    link = hub.links().awaitOnline(name, true, HOLD_MS);
                }
                if (link == null) {
                    LOG.debug("{}: unknown SNI {}, closing", ip, sni);
                    Relay.closeQuietly(socket);
                    return;
                }
            }
            AtomicInteger nameCount = perName.computeIfAbsent(name, k -> new AtomicInteger());
            if (nameCount.incrementAndGet() > MAX_PER_NAME) {
                nameCount.decrementAndGet();
                Relay.closeQuietly(socket);
                return;
            }
            try {
                relay(socket, peek, link);
            } finally {
                nameCount.decrementAndGet();
            }
        } catch (IOException e) {
            LOG.debug("{}: {}", ip, e.getMessage());
            Relay.closeQuietly(socket);
        } finally {
            ipCount.decrementAndGet();
        }
    }

    private void relay(Socket socket, Sni.Peek peek, Links.Link link) throws IOException {
        NodeGroup group = link.group();
        socket.setSoTimeout(0);
        MuxStream stream = group.openVisitor(link, peek.serverName(), socket.getInetAddress().getHostAddress(),
            link.domain() != null ? "domain:" + link.domain() : hub.tls().keyId(), false);
        try {
            Relay.pump(socket, stream, peek.consumed());
        } finally {
            group.visitorDone(streamOwner(group, stream), stream);
        }
    }

    static NodeSession streamOwner(NodeGroup group, MuxStream stream) {
        for (NodeSession s : group.all()) {
            if (s.mux() != null && s.mux().stream(stream.id()) == stream) {
                return s;
            }
        }
        return group.primary();
    }

    /** TLS with the wildcard certificate (the hub has the key) and a one-line answer. */
    private void fallback(Socket socket, byte[] consumed, String name) throws IOException {
        try (SSLSocket s = layer(socket, consumed, hub.tls().context().getSocketFactory())) {
            s.setSoTimeout(HELLO_TIMEOUT_MS);
            s.startHandshake();
            // Drain the request line so the client gets a clean response.
            io.jailscale.proto.http.Http.readRequest(s.getInputStream(), 4096);
            HttpResponse.html(404, "<!doctype html><meta charset=utf-8><title>jailscale</title>"
                + "<p><b>" + HttpFront.escape(name) + "</b> 링크는 지금 열려 있지 않습니다.</p>").writeTo(s.getOutputStream());
        } catch (io.jailscale.proto.http.HttpException e) {
            // not HTTP; nothing to say
        }
    }

    /** Wraps an accepted socket in server-mode TLS, replaying the bytes already read. */
    static SSLSocket layer(Socket socket, byte[] consumed, SSLSocketFactory factory) throws IOException {
        SSLSocket s = (SSLSocket) factory.createSocket(socket, new ByteArrayInputStream(consumed), true);
        s.setUseClientMode(false);
        javax.net.ssl.SSLParameters p = s.getSSLParameters();
        p.setProtocols(Tls.PROTOCOLS);
        p.setApplicationProtocols(Tls.ALPN_HTTP11);
        s.setSSLParameters(p);
        return s;
    }
}
