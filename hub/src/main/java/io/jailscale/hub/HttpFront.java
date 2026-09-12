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
 * The hub's own HTTP endpoints on its name (ARCHITECTURE.md §5.1): {@code /v1/key}, {@code /v1/noise}
 * (Upgrade), {@code /join/<token>}, and a root page. {@link SniRouter} hands over connections
 * whose SNI is the hub's own name, already wrapped in TLS.
 */
final class HttpFront {

    private static final Log LOG = Log.get("http");
    static final String UPGRADE_PROTOCOL = "jailscale-control-v1";
    private static final int HTTP_TIMEOUT_MS = 15_000;
    private static final int MAX_BODY = 64 * 1024;
    /**
     * Unauthenticated Noise handshakes per source address (ARCHITECTURE.md §11.5). A node opens up to
     * four connections and retries with backoff, and a NAT'd site puts many nodes behind one
     * address, so the burst is roomy; the sustained rate is what caps a flood.
     */
    static final int HANDSHAKE_BURST = 30;
    static final double HANDSHAKE_PER_SECOND = 1.0;
    /** Where the page sends someone who does not have the binary yet. */
    private static final String REPO = "https://github.com/eth219/jailscale";

    private final Hub hub;
    private final RateLimiter handshakes = new RateLimiter(HANDSHAKE_BURST, HANDSHAKE_PER_SECOND);

    HttpFront(Hub hub) {
        this.hub = hub;
    }

    /**
     * Serves one TLS connection to completion. {@code ip} is the caller's address as resolved by
     * {@link SniRouter}, which is the PROXY header's address when the hub sits behind a proxy
     * (ARCHITECTURE.md §8.5) and the socket's peer otherwise.
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
            // Viewing the page never consumes the invite (ARCHITECTURE.md §10).
            String url = hub.config().baseUrl() + "/join/" + escape(token);
            return HttpResponse.html(200, page("jailscale invitation",
                "<p>Run this on the machine you want to join:</p>"
                + "<pre>jailscale up --invite " + url + "</pre>"
                + "<p>Install jailscale first if you do not have it. Opening this page does not use "
                + "the invitation up.</p>"));
        }
        if (path.equals("/")) {
            return HttpResponse.html(200, page("jailscale hub", home(req))).header("Cache-Control", "no-store");
        }
        return HttpResponse.text(404, "not found");
    }

    /**
     * The hub's own page: what it is, how to join it, and how it is doing. Counts and resource
     * use are public; they describe the service, not the people on it. Per-node detail and the
     * controls over it appear only for a signed-in admin, since that is who and where.
     */
    private String home(HttpRequest req) {
        StringBuilder b = new StringBuilder();
        String host = escape(hub.config().hostname());
        b.append("<p><code>").append(host).append("</code> is a jailscale hub. It publishes a port on your")
            .append(" machine over HTTPS without opening an inbound port: the hub relays the bytes and your")
            .append(" machine terminates the TLS. <a href=\"").append(REPO).append("\">What this is</a>.</p>");

        // In the order someone has to do it. The page used to say how to join and stop there, which
        // leaves out both where the binary comes from and what joining was for.
        b.append("<h2>Publish a port</h2>");
        b.append("<p><a href=\"").append(REPO).append("/releases/latest\">Download <code>jailscale</code></a>")
            .append(" for Linux, Apple-silicon macOS or Windows: one file, no runtime to install")
            .append(" underneath it, no root. Intel Macs run <code>jailscale.jar</code> on a JVM.</p>");
        // Say what this hub actually accepts rather than assuming a default.
        boolean open = "open".equals(hub.store().setting(Store.SETTING_REGISTRATION, "invite"));
        if (open) {
            b.append("<p>Registration is open, so joining takes effect immediately:</p>")
                .append("<pre>jailscale up --hub ").append(host).append("\njailscale open 3000</pre>");
        } else {
            b.append("<p>Joining needs an invitation. Members create them with <code>jailscale invite</code>;")
                .append(" with one in hand:</p>")
                .append("<pre>jailscale up --invite &lt;url&gt;\njailscale open 3000</pre>");
        }
        b.append("<p>That serves <code>127.0.0.1:3000</code> at <code>https://&lt;name&gt;.").append(host)
            .append("</code>, with a certificate your own machine terminates. <code>--name myapp</code> asks for")
            .append(" a particular name, <code>--tcp</code> forwards a raw port instead, and")
            .append(" <code>--domain app.example.com</code> uses a domain of yours, whose key never leaves your")
            .append(" machine.</p>");

        int online = hub.registry().size();
        long rss = Resources.rssBytes();
        b.append("<h2>Status</h2><table>");
        row(b, "Version", escape(Hub.version()));
        row(b, "Uptime", Resources.humanDuration(Resources.uptimeMillis()));
        row(b, "Nodes", online + " online of " + hub.store().nodes().size() + " registered");
        row(b, "Links open", String.valueOf(hub.links().all().size()));
        row(b, "Certificate", certificateRow());
        // Heap is a small part of what a native image occupies, so where RSS is unavailable say
        // that rather than let a two-megabyte heap read as the process footprint.
        row(b, "Memory", rss < 0
            ? Resources.humanBytes(Resources.heapUsedBytes()) + " heap in use (resident size unavailable here)"
            : Resources.humanBytes(rss) + " resident");
        b.append("</table>");

        // A public hub is asking people to route their traffic through a stranger's machine. What it
        // can and cannot do with that traffic belongs on its own front page, not only in the docs.
        b.append("<h2>What this hub can see</h2>");
        b.append("<p>Not the traffic. It reads the TLS SNI to pick a node and forwards the rest untouched;")
            .append(" the session key belongs to the machine at the other end. It does hold the wildcard")
            .append(" private key for <code>*.").append(host).append("</code> and signs one handshake digest")
            .append(" per visitor, so a dishonest hub could point a name at a machine of its own instead.")
            .append(" That is what <code>jailscale verify</code> checks from your side, and what the daemon")
            .append(" re-checks on its own every half hour. A domain you bring yourself never involves this")
            .append(" hub's key at all.</p>");

        b.append("<h2>Limits</h2><table>");
        row(b, "Visitors per name", SniRouter.MAX_PER_NAME + " at once");
        row(b, "Links per node", String.valueOf(Links.MAX_LINKS_PER_NODE));
        row(b, "New control connections", HANDSHAKE_BURST + " per address, then "
            + (long) HANDSHAKE_PER_SECOND + " a second");
        b.append("</table>");
        b.append("<p>The operator can remove a node or bar an address, so treat an open hub you do not run")
            .append(" as a place to try this rather than one to depend on.</p>");

        AdminWeb.Session s = hub.adminWeb().adminSession(req);
        if (s != null) {
            b.append("<p>Signed in as <b>").append(escape(s.user())).append("</b>. ")
                .append("<a href=\"/admin\">Full admin page</a>.</p>");
            b.append(hub.adminWeb().nodesAndBans(
                "<input type=hidden name=csrf value=\"" + escape(s.csrf()) + "\">", "/"));
        }
        return b.toString();
    }

    /**
     * The wildcard's remaining life, not just "loaded". Its expiry takes every name under the hub
     * down at once, and until now the only place that number appeared was a log line at install
     * time (ARCHITECTURE.md §15).
     */
    private String certificateRow() {
        if (!hub.tls().isLoaded()) {
            return "not loaded yet";
        }
        long left = hub.tls().leaf().getNotAfter().getTime() - System.currentTimeMillis();
        return left <= 0
            ? "EXPIRED " + Resources.humanDuration(-left) + " ago"
            : escape(hub.tls().leaf().getNotAfter().toString()) + " (" + Resources.humanDuration(left) + " left)";
    }

    private static void row(StringBuilder b, String label, String value) {
        b.append("<tr><td>").append(label).append("</td><td>").append(value).append("</td></tr>");
    }

    private static String page(String title, String body) {
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>" + escape(title) + "</title>"
            + "<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.6}"
            + "pre{background:#f4f4f4;padding:1rem;overflow-x:auto}"
            + "table{border-collapse:collapse;margin:1rem 0}td,th{padding:.25rem .75rem .25rem 0;text-align:left;"
            + "border-bottom:1px solid #eee;font-weight:normal}th{font-weight:600}</style></head><body><h1>" + escape(title) + "</h1>"
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
