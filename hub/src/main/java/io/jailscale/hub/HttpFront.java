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
    /** How many open links the front page shows before it hands over to the directory at /links. */
    private static final int LINKS_ON_HOME = 8;
    /**
     * How many the directory itself lists before it stops and says how many are left. Of everything
     * these pages print this is the only part with no fixed length -- twenty links per node
     * (ARCHITECTURE.md §8.2) and no bound on nodes -- and it is answered without a session to
     * anyone who asks, so it has a ceiling like every other unauthenticated answer here.
     */
    private static final int LINKS_SHOWN = 200;

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
        if (path.equals("/links")) {
            return HttpResponse.html(200, page("Open links", directory(req))).header("Cache-Control", "no-store");
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
        JsonObject.Builder b = JsonObject.builder()
            .put("ok", true)
            .put("hostname", hub.config().hostname())
            .put("version", Hub.version())
            .put("uptimeSeconds", Resources.uptimeMillis() / 1000)
            .put("certificateNotAfter", hub.tls().isLoaded() ? hub.tls().leaf().getNotAfter().getTime() / 1000 : null)
            .put("role", hub.role())
            .put("availability", availability());
        PeerClient pc = hub.peerClient();
        if (hub.isStandby() && pc != null) {
            // Only a standby has a primary to name. A primary that names a peer (§13.5) has a
            // client too, but it dials for a comparison of epochs, not to follow.
            b.put("primary", pc.primaryHost()).put("inSync", pc.isSynced());
        }
        b.put("epoch", hub.epoch());
        return b.build();
    }

    /**
     * §13.2: the fraction of each window this process was running, by its own record, and what it
     * saw of each peer while it was. Two quantities, kept apart. {@code since} says how far back
     * the record goes, because a window that reaches further than that is reported over less.
     */
    private JsonObject availability() {
        long now = System.currentTimeMillis();
        Availability a = hub.availability();
        JsonObject.Builder process = JsonObject.builder().put("since", a.since() / 1000);
        for (Availability.Window w : Availability.WINDOWS) {
            Double f = a.processFraction(w.millis(), now);
            if (f != null) {
                process.put(w.label(), Math.round(f * 10_000) / 10_000.0 + "");
            }
        }
        // The table behind the page's columns: minutes down per day (30, oldest first) and per
        // hour (24); -1 where the record has nothing for that bucket.
        process.put("downMinutesPerDay", boxed(downMinutes(a::processDownBetween, now, 86_400_000L, 30)));
        process.put("downMinutesPerHour", boxed(downMinutes(a::processDownBetween, now, 3_600_000L, 24)));
        JsonObject.Builder peers = JsonObject.builder();
        for (String name : a.peerNames()) {
            JsonObject.Builder p = JsonObject.builder();
            for (Availability.Window w : Availability.WINDOWS) {
                Double f = a.peerFraction(name, w.millis(), now);
                if (f != null) {
                    p.put(w.label(), Math.round(f * 10_000) / 10_000.0 + "");
                }
            }
            peers.put(name, p.build());
        }
        return JsonObject.builder().put("process", process.build()).put("peers", peers.build()).build();
    }

    /** Minutes down per bucket, oldest first; -1 where the record has nothing. */
    private static long[] downMinutes(java.util.function.BiFunction<Long, Long, Long> down, long now, long bucketMs, int buckets) {
        long[] out = new long[buckets];
        long end = now;
        for (int i = buckets - 1; i >= 0; i--) {
            long ms = down.apply(end - bucketMs, end);
            out[i] = ms < 0 ? -1 : (ms + 30_000) / 60_000;
            end -= bucketMs;
        }
        return out;
    }

    private static List<Object> boxed(long[] v) {
        List<Object> l = new ArrayList<>(v.length);
        for (long x : v) {
            l.add(x);
        }
        return l;
    }

    /** The status colours (good, warning, critical), validated for colour-vision separation as a set. */
    private static final String GOOD = "#0ca30c";
    private static final String WARNING = "#fab219";
    private static final String CRITICAL = "#d03b3b";

    /**
     * One inline SVG in the shape a status page uses: a bar per bucket, coloured by what the
     * bucket was -- green with nothing down, amber with less than {@code severeAt} minutes down,
     * red with that or more -- and, so that colour is never the only channel, shorter the worse
     * it was. A bucket from before the record began draws a faint stub and says so. Every bar
     * carries its number in a title, which is the tooltip, and the JSON status carries the same
     * numbers, which is the table.
     */
    private static String strip(long[] minutes, long now, long bucketMs, long severeAt, String what) {
        int slot = 10;
        int w = 8;
        int h = 26;
        StringBuilder s = new StringBuilder();
        s.append("<svg class=\"avail\" width=\"").append(minutes.length * slot).append("\" height=\"").append(h)
            .append("\" viewBox=\"0 0 ").append(minutes.length * slot).append(' ').append(h)
            .append("\" role=\"img\" aria-label=\"").append(escape(what)).append("\">");
        for (int i = 0; i < minutes.length; i++) {
            int x = i * slot + 1;
            long end = now - (minutes.length - 1 - i) * bucketMs;
            String when = escape(java.time.Instant.ofEpochMilli(end - bucketMs).toString().substring(0, bucketMs >= 86_400_000L ? 10 : 16)
                .replace('T', ' '));
            s.append("<g><title>").append(when).append(": ");
            String fill;
            int bar;
            if (minutes[i] < 0) {
                s.append("no record</title><rect x=\"").append(x).append("\" y=\"").append(h - 3).append("\" width=\"").append(w)
                    .append("\" height=\"3\" rx=\"1.5\" fill=\"currentColor\" fill-opacity=\".2\"/></g>");
                continue;
            } else if (minutes[i] == 0) {
                s.append("up throughout");
                fill = GOOD;
                bar = h;
            } else if (minutes[i] < severeAt) {
                s.append(minutes[i]).append(" min down");
                fill = WARNING;
                bar = h * 2 / 3;
            } else {
                s.append(minutes[i]).append(" min down");
                fill = CRITICAL;
                bar = h / 3;
            }
            s.append("</title><rect x=\"").append(x).append("\" y=\"").append(h - bar).append("\" width=\"").append(w)
                .append("\" height=\"").append(bar).append("\" rx=\"1.5\" fill=\"").append(fill).append("\"/></g>");
        }
        return s.append("</svg>").toString();
    }

    /** The line under a strip: how far back it reaches, the figure for that window, and where it ends. */
    private static String ends(String from, Double fraction, String to) {
        return "<small class=\"ends\"><span>" + from + "</span><span>" + Availability.percent(fraction) + " uptime</span><span>" + to + "</span></small>";
    }

    private static final String LEGEND = "<small class=\"legend\"><span class=\"sw\" style=\"background:" + GOOD + "\"></span>up "
        + "<span class=\"sw\" style=\"background:" + WARNING + "\"></span>down under an hour (a quarter, per hour) "
        + "<span class=\"sw\" style=\"background:" + CRITICAL + "\"></span>down longer. Shorter bars are worse; each bar says its minutes.</small>";

    /** "100% 24h · 99.98% 7d · 99.9% 30d", or what the record's age allows. */
    private static String availabilityText(java.util.function.Function<Long, Double> fraction) {
        StringBuilder t = new StringBuilder();
        for (Availability.Window w : Availability.WINDOWS) {
            Double f = fraction.apply(w.millis());
            if (f == null) {
                continue;
            }
            if (t.length() > 0) {
                t.append(" · ");
            }
            t.append(Availability.percent(f)).append(' ').append(w.label());
        }
        return t.length() == 0 ? "no record yet" : t.toString();
    }

    /**
     * The hub's own page: what it is, how to join it, and how it is doing. Counts and resource
     * use are public; they describe the service, not the people on it. Per-node detail and the
     * controls over it appear only for a signed-in admin, since that is who and where.
     */
    private String home(HttpRequest req) {
        StringBuilder b = new StringBuilder(nav("/"));
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
        // Two availability figures and never one (§13.2): the process's own record counts a hub
        // whose port is firewalled as up, and what a peer saw is reachability but only exists
        // once there is a peer. Each is labelled with what it measures.
        long now = System.currentTimeMillis();
        Availability avail = hub.availability();
        String sinceNote = now - avail.since() < Availability.WINDOWS.get(Availability.WINDOWS.size() - 1).millis()
            ? " (record since " + escape(java.time.Instant.ofEpochMilli(avail.since()).toString().substring(0, 10)) + ")" : "";
        long day = 86_400_000L;
        long hour = 3_600_000L;
        row(b, "Availability", "by this process's own record" + sinceNote
            + strip(downMinutes(avail::processDownBetween, now, day, 30), now, day, 60, "Uptime per day, last 30 days")
            + ends("30 days ago", avail.processFraction(30 * day, now), "Today")
            + strip(downMinutes(avail::processDownBetween, now, hour, 24), now, hour, 15, "Uptime per hour, last 24 hours")
            + ends("24 hours ago", avail.processFraction(day, now), "Now") + LEGEND);
        for (String peer : avail.peerNames()) {
            row(b, "Seen from here", "<code>" + escape(peer) + "</code>"
                + strip(downMinutes((f, t) -> avail.peerDownBetween(peer, f, t), now, day, 30), now, day, 60,
                    "The channel to " + peer + " per day, last 30 days")
                + ends("30 days ago", avail.peerFraction(peer, 30 * day, now), "Today"));
        }
        PeerClient pc = hub.peerClient();
        if (hub.isStandby() && pc != null) {
            row(b, "Role", "standby of <code>" + escape(pc.primaryHost()) + "</code>, "
                + (pc.isSynced() ? "in sync" : pc.isConnected() ? "connected, not yet in sync" : "not connected"
                    + (pc.lastError() == null ? "" : " (" + escape(pc.lastError()) + ")"))
                + ", epoch " + hub.epoch());
        } else {
            List<Peers.Session> standbys = hub.peers().all();
            StringBuilder r = new StringBuilder("primary");
            if (standbys.isEmpty()) {
                r.append(", no standby connected");
            } else {
                r.append(", standby");
                for (Peers.Session ps : standbys) {
                    r.append(" <code>").append(escape(ps.name())).append("</code>");
                }
                r.append(" in sync");
            }
            r.append(", epoch ").append(hub.epoch());
            row(b, "Role", r.toString());
        }
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

        // A taste of what this hub is serving, and the directory for the rest. The whole list used
        // to be here, which made the one section that grows without bound the one a visitor
        // scrolled through to reach the limits: every other section on this page has a fixed
        // length. The rows are the directory's rows, so the two pages are one list and not two
        // designs; what /links adds is the rest of them and what they mean.
        b.append("<h2>Open links</h2>");
        List<Links.Link> links = sortedLinks();
        if (links.isEmpty()) {
            b.append("<p>None open right now.</p>");
        } else {
            linkRows(b, links.subList(0, Math.min(links.size(), LINKS_ON_HOME)));
            if (links.size() > LINKS_ON_HOME) {
                b.append("<p><a href=\"/links\">All ").append(links.size()).append(" open links &rarr;</a></p>");
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
     * The directory: everything this hub is serving, on a URL of its own so that it is something
     * one person can send another. Splitting it off rather than folding the page into scripted
     * tabs keeps both halves linkable and keeps the no-script bargain the rest of this front end
     * makes.
     *
     * <p>Three facts per link, and every one of them is something the hub already holds for its
     * own routing: the address, which is public by construction because a visitor reaches it by
     * typing it; how many visitors are being relayed to it at this instant; and how long it has
     * been open. Nothing here is fetched from the link itself. A thumbnail or a favicon would mean
     * the hub connecting to a node's app as a visitor and republishing what came back on its own
     * front page -- which is the one thing the front page tells people it does not do -- and would
     * put whatever anyone who can join chooses to serve on the operator's page. Who owns a name and
     * which local port it reaches stay behind the admin session, as the node list does.
     */
    private String directory(HttpRequest req) {
        StringBuilder b = new StringBuilder(nav("/links"));
        List<Links.Link> links = sortedLinks();
        if (links.isEmpty()) {
            b.append("<p>None open right now. <a href=\"/\">What this hub is</a>.</p>");
            return b.toString();
        }
        b.append("<p>").append(links.size()).append(links.size() == 1 ? " link is" : " links are")
            .append(" being served through <code>").append(escape(hub.config().hostname()))
            .append("</code> right now. Each is somebody's own machine; the hub relays the bytes and")
            .append(" does not terminate the TLS, so what is behind one of these is between you and it.</p>");
        // Where this page starts: the first row whose key is not before the cursor. A page's worth
        // is capped, so without this the rows past the cap were counted in the sentence above and
        // then unreachable -- no next page and no way to ask for one. The cursor is the ordering
        // key itself and every link has a distinct one, so paging cannot stall on a repeat.
        String from = cursor(req);
        int start = 0;
        while (from != null && start < links.size() && sortKey(links.get(start)).compareTo(from) < 0) {
            start++;
        }
        if (start == links.size()) {
            // The cursor names a point past the last row, which is what a bookmarked or forwarded
            // one becomes once the links it started from close. Saying so beats an empty table
            // under a sentence that has just counted the links this hub is serving.
            b.append("<p>Nothing is open at that point in the list any more. ")
                .append("<a href=\"/links\">Start from the first</a>.</p>");
        } else {
            int end = Math.min(start + LINKS_SHOWN, links.size());
            linkRows(b, links.subList(start, end));
            if (end < links.size()) {
                // The next row's own key, never the cursor the caller sent, so nothing a visitor
                // typed is echoed back into the page.
                b.append("<p><a href=\"/links?from=").append(escape(sortKey(links.get(end)))).append("\">The next ")
                    .append(Math.min(LINKS_SHOWN, links.size() - end)).append(" of ").append(links.size() - end)
                    .append(" remaining &rarr;</a></p>");
            }
            if (start > 0) {
                b.append("<p><a href=\"/links\">&larr; Back to the first ").append(LINKS_SHOWN).append("</a></p>");
            }
        }
        b.append("<p><small>A visitor count is the connections open at the moment this page was")
            .append(" built, not a total, and a link with none says nothing rather than zero. \"Open\"")
            .append(" is since the link was opened: a node that restarts or hands its name to another")
            .append(" machine opens a new one, so this counts the current one, not the name.</small></p>");
        return b.toString();
    }

    /**
     * The paging cursor, or null when there is none. A query string is decoded per-escape, so a
     * malformed one -- {@code ?from=%zz}, a truncated {@code %2} -- makes {@code query()} throw,
     * and nothing between here and the virtual thread serving the connection catches anything but
     * {@link IOException}: the visitor got no response at all and the thread died printing a
     * stack trace. A cursor nobody can read is no cursor, and the page still answers.
     */
    private static String cursor(HttpRequest req) {
        try {
            return req.query().get("from");
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * One row per link: the address, and beside it the three things the hub already knows for its
     * own routing. Nothing here is fetched from the link itself.
     */
    private void linkRows(StringBuilder b, List<Links.Link> links) {
        long now = System.currentTimeMillis();
        b.append("<table class=\"links\">");
        for (Links.Link l : links) {
            StringBuilder facts = new StringBuilder(escape(l.kind()));
            // Only names and domains are counted per name, so a raw port says nothing here rather
            // than a zero that would read as "nobody is connected" when it means "not measured".
            if (!l.raw()) {
                int v = hub.router().visitorsFor(l.name());
                if (v > 0) {
                    facts.append(" &middot; ").append(v).append(v == 1 ? " visitor" : " visitors");
                }
            }
            facts.append(" &middot; open ").append(Resources.humanDuration(now - l.openedAt()));
            row(b, address(l), facts.toString());
        }
        b.append("</table>");
    }

    /**
     * Every live link, in the order a directory wants them: the order the rows read in. The key is
     * built once per link and sorted alongside it, because {@code Comparator.comparing} would build
     * it afresh on both sides of every comparison -- on a hub holding thousands of links that is
     * hundreds of thousands of short-lived strings per request, on a page that shows eight rows,
     * in the process relaying every visitor's bytes.
     */
    private List<Links.Link> sortedLinks() {
        record Keyed(String key, Links.Link link) {}
        List<Keyed> keyed = new ArrayList<>();
        for (Links.Link l : hub.links().all()) {
            keyed.add(new Keyed(sortKey(l), l));
        }
        keyed.sort(Comparator.comparing(Keyed::key));
        List<Links.Link> links = new ArrayList<>(keyed.size());
        for (Keyed k : keyed) {
            links.add(k.link());
        }
        return links;
    }

    /**
     * What the row will actually say, which is what a reader scans and so what the list is
     * ordered by. Sorting by {@code name()} put a raw port among the names beginning with its
     * kind -- {@code tcp/2001} sorts under "t" while the row reads {@code <hub>:2001} -- so raw
     * rows landed at a position matching nothing on the page. The port is padded because this key
     * is compared as text and 9000 belongs before 20000, not after it; that also makes every
     * link's key distinct, which is what lets it serve as the paging cursor.
     */
    private String sortKey(Links.Link l) {
        return l.raw() ? hub.config().hostname() + ":" + String.format("%05d", l.port()) : l.host(hub.config());
    }

    /**
     * The two public pages, as links and not as tabs a script swaps: each keeps its own URL, so
     * either can be handed to someone, and neither needs a script to arrive at. The page you are
     * on is not a link to itself.
     */
    private static String nav(String here) {
        return "<nav>" + tab("/", "Hub", here) + tab("/links", "Links", here) + "</nav>";
    }

    private static String tab(String path, String label, String here) {
        return path.equals(here) ? "<span aria-current=\"page\">" + label + "</span>"
            : "<a href=\"" + path + "\">" + label + "</a>";
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
            + "nav{display:flex;gap:1.25rem;margin:-.25rem 0 2rem;font-size:.9rem}"
            + "nav [aria-current]{color:var(--ink);font-weight:600}"
            + "pre{background:var(--wash);padding:.9rem 1rem;overflow-x:auto;border-radius:.5rem;line-height:1.5}"
            + "table{border-collapse:collapse;width:100%;margin:.25rem 0}"
            + "svg.avail{display:block;margin:.5rem 0 0;max-width:100%}td small{margin:.2rem 0 0}"
            + "small.ends{display:flex;justify-content:space-between;max-width:300px}"
            + ".sw{display:inline-block;width:.7em;height:.7em;border-radius:2px;margin:0 .3em 0 .1em;vertical-align:-.05em}"
            + "td{padding:.5rem 0;text-align:left;border-top:1px solid var(--rule);vertical-align:baseline}"
            + "tr:first-child td{border-top:0}"
            + "td:first-child{width:11rem;color:var(--dim);padding-right:1rem}"
            // The directory is a list, not label-and-value: its first column is the address and
            // carries the weight, so it takes the width it needs and the facts beside it recede.
            + "table.links td:first-child{width:auto;color:inherit}table.links td+td{color:var(--dim)}"
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
