package io.jailscale.hub;

import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

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
    /** How many open links the page lists before it stops and says how many are left. */
    private static final int LINKS_SHOWN = 50;

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
        if (path.equals("/v1/status")) {
            return HttpResponse.json(200, status().toString()).header("Cache-Control", "no-store");
        }
        if (path.equals("/metrics")) {
            // Moved off the public name rather than deleted (§6.3). Saying where it went would be
            // saying an address that is deliberately not this one, so it says which flag instead.
            return HttpResponse.text(404, "metrics are not served on this name; see --metrics-listen");
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
     * Liveness, for something that is not a person and has no credential: is this hub up, which
     * build answered, how long it has been up, and when the certificate runs out -- the last being
     * the one that takes every name down at once and the one worth alerting on. That is the whole
     * list. It used to carry the counters and the hub's state as well, which made the public name's
     * health check a second copy of {@code /metrics}; the counters live on the metrics listener now
     * and the per-node detail behind {@code /admin} (ARCHITECTURE.md §6.3). Fields may be added; a
     * monitor that reads the ones it knows keeps working (§5.4).
     */
    private JsonObject status() {
        return JsonObject.builder()
            .put("ok", true)
            .put("hostname", hub.config().hostname())
            .put("version", Hub.version())
            .put("uptimeSeconds", Resources.uptimeMillis() / 1000)
            .put("certificateNotAfter", hub.tls().isLoaded() ? hub.tls().leaf().getNotAfter().getTime() / 1000 : null)
            .build();
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

        int online = hub.registry().size();
        long rss = Resources.rssBytes();
        b.append("<h2>Status</h2><table>");
        // Said plainly when it is not a release, because the string alone does not say so to
        // anyone who does not read Maven: a hub built from main reports the pom's version, which
        // only a tag build replaces (`versions:set` in release.yml), so every source, `edge` and
        // workflow_dispatch build carries a number that reads like a release. One of them served
        // this page as "0.1.0-SNAPSHOT" long after v0.1.2 shipped, and the operator reading it had
        // no way to tell from here that it was neither 0.1.0 nor current.
        row(b, "Version", escape(Hub.version()) + (released(Hub.version()) ? "" : " (not a release build)"));
        // Which build, and which key: the two things about this hub that can be compared with
        // something the reader already has. Both are self-reported, which the note below says.
        String sha = Build.executableSha256();
        if (sha != null) {
            row(b, "Binary", "<code>sha256:" + sha + "</code>");
        }
        row(b, "Hub key", "<code>" + escape(hub.keys().publicText()) + "</code>");
        String nextKey = hub.keys().nextPublicText();
        if (nextKey != null) {
            row(b, "Next hub key", "<code>" + escape(nextKey) + "</code>");
        }
        row(b, "Uptime", Resources.humanDuration(Resources.uptimeMillis()));
        row(b, "Nodes", online + " online of " + hub.store().nodes().size() + " registered");
        row(b, "Certificate", certificateRow());
        // Heap is a small part of what a native image occupies, so where RSS is unavailable say
        // that rather than let a two-megabyte heap read as the process footprint.
        row(b, "Memory", rss < 0
            ? Resources.humanBytes(Resources.heapUsedBytes()) + " heap in use (resident size unavailable here)"
            : Resources.humanBytes(rss) + " resident");
        b.append("</table>");
        // Saying what these two lines are not is the point of printing them. A hub that has been
        // tampered with writes this page, so they catch a mistake and nothing more (§11.2).
        b.append("<p><small>The hub key is the one a node pins when it joins, and <code>jailscale status</code>")
            .append(" prints the one yours pinned. The binary hash is of the file this process is running: compare it")
            .append(" with <code>SHA256SUMS.txt</code> in <a href=\"").append(REPO).append("/releases\">the release")
            .append("</a> it claims to be, remembering that a container or source build is its own binary. Both are")
            .append(" what this hub says about itself, so they tell you an operator is running what they think they")
            .append(" are; a dishonest hub prints whatever it likes here.</small></p>");

        // What this hub is actually serving. The addresses are public by construction -- a visitor
        // reaches one by typing it -- so listing them tells nobody anything a DNS lookup would not.
        // Who owns a name and which local port it reaches are a different matter and stay behind the
        // admin session, as the node list does.
        b.append("<h2>Open links</h2>");
        List<Links.Link> links = new ArrayList<>(hub.links().all());
        links.sort(Comparator.comparing(Links.Link::name));
        if (links.isEmpty()) {
            b.append("<p>None open right now.</p>");
        } else {
            b.append("<table>");
            for (Links.Link l : links.subList(0, Math.min(links.size(), LINKS_SHOWN))) {
                row(b, address(l), l.kind());
            }
            b.append("</table>");
            if (links.size() > LINKS_SHOWN) {
                b.append("<p>and ").append(links.size() - LINKS_SHOWN).append(" more.</p>");
            }
        }

        b.append("<h2>Limits</h2><table>");
        // Two numbers, because the first one alone was a limit pretending to be a capacity: this
        // row said 1024 while the node serving the name held a few hundred (ARCHITECTURE.md §9.3),
        // so the figure a reader took for "how many this can serve" was one nothing had measured
        // and the binding constraint was somewhere else entirely. What the nodes say they hold is
        // the answer, and it is a sum over the ones online -- which is why it moves when a node
        // goes away, and why it reads 0 on a hub whose nodes are older than that field.
        row(b, "Visitors per name", SniRouter.MAX_PER_NAME + " at once, and no more than the node"
            + " serving it will hold");
        long capacity = hub.registry().visitorCapacity();
        row(b, "Visitors the nodes will hold", (capacity > 0 ? capacity + " together" : "not advertised")
            + ", " + hub.router().visitorsInFlight() + " being served right now");
        // Both numbers, because either one alone misleads. The count is what admission checks; the
        // budget is what the hub can actually hold, and it is the one that binds first.
        row(b, "Buffered per visitor", MuxStream.WINDOW / 1024 + " KiB at most");
        row(b, "Buffered in total", hub.flowBudget().limitBytes() / (1024 * 1024) + " MiB, then the"
            + " slowest stream is dropped");
        row(b, "Links per node", String.valueOf(Links.MAX_LINKS_PER_NODE));
        row(b, "New control connections", HANDSHAKE_BURST + " per address, then "
            + (long) HANDSHAKE_PER_SECOND + " a second");
        b.append("</table>");
        b.append("<p>The operator can remove a node or bar an address, so treat an open hub you do not run")
            .append(" as a place to try this rather than one to depend on.</p>");

        // The admin tables and their forms come last, under everything a visitor came for.
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
     * Where a visitor goes for this link: a raw port is a host and a port and nothing to click,
     * an https link is the name itself, which is also the only useful thing to do with the row.
     */
    private String address(Links.Link l) {
        String host = escape(l.host(hub.config()));
        if (l.raw()) {
            return "<code>" + escape(hub.config().hostname()) + ":" + l.port() + "</code>";
        }
        return "<a href=\"https://" + host + "\">" + host + "</a>";
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

    /**
     * The frame every page shares. One stylesheet, inline, because a second request for a file that
     * never changes is a second thing to serve and to cache-bust; it is under a kilobyte.
     *
     * <p>One column, 48rem: wide enough that a 64-character hash and a two-part status line sit on
     * one line each, which is what was actually wrong at 40rem, and narrow enough to read. Section
     * headings are small and muted because on this page they are labels between blocks rather than
     * titles anyone reads. Dark is the system's choice, not a toggle, since there is nothing here
     * to remember a preference with.
     */
    private static String page(String title, String body) {
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            + "<title>" + escape(title) + "</title><style>"
            + ":root{color-scheme:light dark;--bg:#fff;--ink:#15171a;--dim:#70757c;--rule:#e7e8ea;--wash:#f5f6f7;--link:#0b57d0}"
            + "body{font-family:system-ui,-apple-system,sans-serif;max-width:48rem;margin:4rem auto 6rem;"
            + "padding:0 1.5rem;line-height:1.65;color:var(--ink);background:var(--bg);overflow-wrap:break-word}"
            + "h1{font-size:1.5rem;letter-spacing:-.01em;margin:0 0 1rem}"
            + "h2{font-size:.75rem;text-transform:uppercase;letter-spacing:.09em;color:var(--dim);"
            + "font-weight:600;margin:2.75rem 0 .5rem}"
            + "p{margin:.75rem 0}a{color:var(--link)}"
            + "pre{background:var(--wash);padding:.9rem 1rem;overflow-x:auto;border-radius:.5rem;line-height:1.5}"
            + "table{border-collapse:collapse;width:100%;margin:.25rem 0}"
            + "td{padding:.5rem 0;text-align:left;border-top:1px solid var(--rule);vertical-align:baseline}"
            + "tr:first-child td{border-top:0}"
            + "td:first-child{width:11rem;color:var(--dim);padding-right:1rem}"
            + "td code{word-break:break-all}"
            + "small{color:var(--dim);font-size:.85rem;line-height:1.55;display:block;margin:.75rem 0}"
            + "@media(max-width:30rem){td,td:first-child{display:block;width:auto;padding:0}"
            + "td:first-child{border-top:1px solid var(--rule);padding-top:.5rem}td+td{padding-bottom:.5rem}}"
            + "@media(prefers-color-scheme:dark){:root{--bg:#131517;--ink:#e6e8eb;--dim:#8b9096;--rule:#282b30;"
            + "--wash:#1c1f23;--link:#8ab4f8}}"
            + "</style></head><body><h1>" + escape(title) + "</h1>" + body + "</body></html>";
    }

    /**
     * Whether this version names a release rather than a build on the way to one. `dev` is what a
     * build with no manifest reports; a `-SNAPSHOT` is Maven's word for the same thing, and
     * {@code Updates} already treats it as sorting below the release it heads for.
     */
    private static boolean released(String version) {
        return version != null && !version.equals("dev") && !version.endsWith("-SNAPSHOT");
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
