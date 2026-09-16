package io.jailscale.hub;

import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.util.Log;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

/**
 * {@code GET /metrics} on a listener of its own (ARCHITECTURE.md §6.3), plain HTTP, loopback by
 * default. The hub's name on 443 is the public internet -- there is no inside to be on -- so the
 * scrape is separated by where it listens rather than by a credential checked on 443, which is what
 * etcd (<code>--listen-metrics-urls</code>), Spring Boot's management port and headscale's
 * <code>metrics_listen_addr</code> all do. The address is the authorisation, as it is for the admin
 * socket next door (§6.3); a scraper elsewhere reaches this through a tunnel or a proxy that can
 * say who is asking, which this cannot.
 *
 * <p>Nothing else is served here. A second path on this port would be a second thing to reason
 * about every time someone widens the bind address.
 */
final class MetricsFront implements AutoCloseable {

    private static final Log LOG = Log.get("metrics");
    private static final int TIMEOUT_MS = 10_000;

    private final Hub hub;
    private final ServerSocket server;

    MetricsFront(Hub hub, String host, int port) throws IOException {
        this.hub = hub;
        server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(host, port), 16);
        Thread.ofVirtual().name("metrics-accept").start(this::accept);
        if (isLoopback(host)) {
            LOG.info("metrics on {}:{}", host, port());
        } else {
            // The point of this listener is that it is not on the public name. An operator who
            // widens it has to mean it, and should hear that nothing here asks who is scraping.
            LOG.warn("metrics on {}:{} -- not loopback, and this endpoint has no authentication; "
                + "put it behind a proxy or a firewall", host, port());
        }
    }

    int port() {
        return server.getLocalPort();
    }

    private static boolean isLoopback(String host) {
        try {
            return InetAddress.getByName(host).isLoopbackAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private void accept() {
        while (!server.isClosed()) {
            Socket s;
            try {
                s = server.accept();
            } catch (IOException e) {
                break;
            }
            Thread.ofVirtual().name("metrics-" + s.getPort()).start(() -> serve(s));
        }
    }

    private void serve(Socket socket) {
        try (socket) {
            socket.setSoTimeout(TIMEOUT_MS);
            HttpRequest req;
            try {
                req = Http.readRequest(socket.getInputStream(), 0);
            } catch (HttpException e) {
                HttpResponse.text(e.status(), e.getMessage()).writeTo(socket.getOutputStream(), e.isHead());
                return;
            } catch (EOFException e) {
                return;
            }
            route(req).writeTo(socket.getOutputStream(), req.isHead());
        } catch (IOException e) {
            LOG.debug("metrics: {}", e.getMessage());
        }
    }

    HttpResponse route(HttpRequest req) {
        if (!req.method().equals("GET") && !req.method().equals("HEAD")) {
            // Allow is the one field RFC 9110 §15.5.6 requires of a 405, and it is what a scraper
            // pointed at this port with the wrong method reads to find out what to send instead.
            return HttpResponse.text(405, "method not allowed").header("Allow", "GET, HEAD");
        }
        if (!req.path().equals("/metrics")) {
            return HttpResponse.text(404, "not found");
        }
        return HttpResponse.text(200, Metrics.prometheus(hub)).header("Cache-Control", "no-store");
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
