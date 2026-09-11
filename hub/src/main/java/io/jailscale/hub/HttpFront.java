package io.jailscale.hub;

import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * The hub's own HTTP endpoints on its name (DESIGN.md §6.1): {@code /v1/key}, {@code /v1/noise}
 * (Upgrade), {@code /join/<token>}, and a root page. {@link SniRouter} hands over connections
 * whose SNI is the hub's own name, already wrapped in TLS.
 */
final class HttpFront {

    private static final Log LOG = Log.get("http");
    static final String UPGRADE_PROTOCOL = "jailscale-control-v1";
    private static final int HTTP_TIMEOUT_MS = 15_000;
    private static final int MAX_BODY = 64 * 1024;
    /**
     * Unauthenticated Noise handshakes per source address (DESIGN.md §12.4). A node opens up to
     * four connections and retries with backoff, and a NAT'd site puts many nodes behind one
     * address, so the burst is roomy; the sustained rate is what caps a flood.
     */
    static final int HANDSHAKE_BURST = 30;
    static final double HANDSHAKE_PER_SECOND = 1.0;

    private final Hub hub;
    private final RateLimiter handshakes = new RateLimiter(HANDSHAKE_BURST, HANDSHAKE_PER_SECOND);

    HttpFront(Hub hub) {
        this.hub = hub;
    }

    /**
     * Serves one TLS connection to completion. {@code ip} is the caller's address as resolved by
     * {@link SniRouter}, which is the PROXY header's address when the hub sits behind a proxy
     * (DESIGN.md §9.6) and the socket's peer otherwise.
     */
    void serve(Socket socket, String ip) {
        try (socket) {
            socket.setSoTimeout(HTTP_TIMEOUT_MS);
            if (socket instanceof javax.net.ssl.SSLSocket ssl) {
                ssl.startHandshake();
            }
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            HttpRequest req;
            try {
                req = Http.readRequest(in, MAX_BODY);
            } catch (HttpException e) {
                HttpResponse.text(e.status(), e.getMessage()).writeTo(out);
                return;
            } catch (EOFException e) {
                return;
            }
            LOG.debug("{} {} from {}", req.method(), req.path(), ip);
            String path = req.path();
            if (path.equals("/v1/noise")) {
                if (!req.method().equals("POST") || !req.wantsUpgrade(UPGRADE_PROTOCOL)) {
                    HttpResponse.text(426, "expected Upgrade: " + UPGRADE_PROTOCOL).writeTo(out);
                    return;
                }
                if (!handshakes.allow(ip)) {
                    LOG.warn("too many handshakes from {}, refusing", ip);
                    HttpResponse.text(429, "too many handshakes").writeTo(out);
                    return;
                }
                HttpResponse.upgrade(UPGRADE_PROTOCOL).writeTo(out);
                new NodeSession(hub, socket, ip).run(in, out);
                return;
            }
            route(req).writeTo(out);
        } catch (IOException e) {
            LOG.debug("connection error: {}", e.toString());
        }
    }

    HttpResponse route(HttpRequest req) throws IOException {
        String path = req.path();
        if (path.equals("/admin") || path.startsWith("/admin/")) {
            return hub.adminWeb().handle(req);
        }
        if (!req.method().equals("GET") && !req.method().equals("HEAD")) {
            return HttpResponse.text(405, "method not allowed");
        }
        if (path.equals("/v1/key")) {
            JsonObject.Builder b = JsonObject.builder()
                .put("hubKey", hub.keys().publicText())
                .put("nextHubKey", hub.keys().nextPublicText());
            long act = hub.store().hubKeyActivatesAt();
            if (act > 0) {
                b.put("notAfter", act / 1000);
            }
            return HttpResponse.json(200, b.toJson()).header("Cache-Control", "no-store");
        }
        if (path.startsWith("/join/")) {
            String token = path.substring("/join/".length());
            if (token.isEmpty() || token.contains("/")) {
                return HttpResponse.text(404, "not found");
            }
            // Viewing the page never consumes the invite (DESIGN.md §11.3).
            String url = hub.config().baseUrl() + "/join/" + escape(token);
            return HttpResponse.html(200, page("jailscale invitation",
                "<p>Run this on the machine you want to join:</p>"
                + "<pre>jailscale up --invite " + url + "</pre>"
                + "<p>Install jailscale first if you do not have it. Opening this page does not use "
                + "the invitation up.</p>"));
        }
        if (path.equals("/")) {
            // Say what this hub actually accepts. It used to claim an invitation was always
            // required, which is wrong on any hub whose operator opened registration.
            boolean open = "open".equals(hub.store().setting(Store.SETTING_REGISTRATION, "invite"));
            String how = open
                ? "<p>To join, run <code>jailscale up --hub " + escape(hub.config().hostname())
                    + "</code>. Your machine then waits for the operator to approve it.</p>"
                : "<p>Joining needs an invitation. Members create them with <code>jailscale invite</code>.</p>";
            return HttpResponse.html(200, page("jailscale hub",
                "<p><code>" + escape(hub.config().hostname()) + "</code> is a jailscale hub.</p>"
                + how
                + "<p>jailscale publishes a port on your machine over HTTPS without opening an inbound "
                + "port. This hub relays the bytes; your machine terminates the TLS. "
                + "<a href=\"https://github.com/eth219/jailscale\">What this is</a>.</p>"));
        }
        return HttpResponse.text(404, "not found");
    }

    private static String page(String title, String body) {
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>" + escape(title) + "</title>"
            + "<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.6}"
            + "pre{background:#f4f4f4;padding:1rem;overflow-x:auto}</style></head><body><h1>" + escape(title) + "</h1>"
            + body + "</body></html>";
    }

    static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '&' -> sb.append("&amp;");
                case '"' -> sb.append("&quot;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }
}
