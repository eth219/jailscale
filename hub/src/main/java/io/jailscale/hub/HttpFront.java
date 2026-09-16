package io.jailscale.hub;

import io.jailscale.proto.control.Message;
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
 * (Upgrade), {@code /join/<token>}, {@code /robots.txt}, a root page and the link directory at
 * {@code /links}. {@link SniRouter} hands over connections whose SNI is the hub's own name,
 * already wrapped in TLS.
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
    /**
     * The floor in words, read from the constant the handshake enforces so the page cannot drift
     * from it (ARCHITECTURE.md §5.4). Written once because the page says it twice -- in the
     * paragraph above the join and in the status row -- and two copies of a sentence about a
     * number are two places for it to go stale separately.
     */
    private static final String TAKES = NodeSession.MIN_PROTO == Message.PROTO
        ? "nothing older" : "protocol " + NodeSession.MIN_PROTO + " and newer";
    /** How many open links the front page shows before it hands over to the directory at /links. */
    private static final int LINKS_ON_HOME = 8;
    /**
     * How many the directory itself lists before it stops and says how many are left. Of everything
     * these pages print this is the only part with no fixed length -- twenty links per node
     * (ARCHITECTURE.md §8.2) and no bound on nodes -- and it is answered without a session to
     * anyone who asks, so it has a ceiling like every other unauthenticated answer here.
     */
    private static final int LINKS_SHOWN = 200;

    /**
     * The one path a crawler is asked not to fetch, and it is not the obvious one.
     *
     * <p>{@code Disallow} and {@code noindex} do opposite things and only one of them keeps a page
     * out of a search index. A disallowed page is never fetched, so its {@code noindex} is never
     * read, and a URL somebody linked from elsewhere can still be listed on the strength of that
     * link alone -- which for {@code /join/<token>} would publish the token, the very thing the
     * page is protecting. So the pages that must not be indexed are deliberately left fetchable and
     * say {@code noindex} themselves ({@link #NOINDEX}); being crawled costs them nothing, since
     * opening an invitation has never spent it.
     *
     * <p>{@code /admin} is the exception and is here for a different reason than secrecy: a login
     * link is one-shot and {@code AdminWeb} consumes it on the GET, so a machine that fetches one
     * to see what is there burns it. Nothing under it is indexable anyway -- without a session it
     * answers 403 -- so the meta stays on those pages as the second layer.
     *
     * <p>All of it is advice a crawler may ignore, so this raises the floor and is not a control;
     * the control would be listing a link only when the node asks to be listed (#99).
     */
    private static final String ROBOTS = "User-agent: *\nDisallow: /admin\n";

    /**
     * {@code nofollow} as well as {@code noindex}, because these two pages are the ones carrying
     * addresses that lead to other people's machines: without it a crawler that has read the
     * directory walks into every app behind it, which is a heavier version of the thing the
     * directory refuses to do itself. It also keeps a crawler from paging through the whole list
     * one {@code ?from=} at a time.
     */
    static final String NOINDEX = "<meta name=\"robots\" content=\"noindex,nofollow\">";

    /**
     * What every answer on this name carries. The front end's own shape is what makes the policy
     * exact rather than aspirational: there is no script, no external stylesheet, no font, and
     * nothing is ever fetched from a node, so {@code default-src 'none'} is the truth and not an
     * aspiration. {@code form-action} and {@code frame-ancestors} are the two that matter, and they
     * matter for {@link AdminWeb}: its forms change the hub's state, and they are the reason this
     * is applied to every response rather than only to the pages.
     *
     * <p>{@code img-src 'self'} for the icon, which is a route here and not a data URI; if it ever
     * becomes one this has to say {@code data:} instead. {@code Referrer-Policy: no-referrer}
     * because an invitation URL and an admin login URL are credentials in a path, and a Referer
     * header is the one way a path travels somewhere nobody chose to send it.
     */
    private static final String[][] SECURITY_HEADERS = {
        {"Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; "
            + "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"},
        {"X-Content-Type-Options", "nosniff"},
        {"Referrer-Policy", "no-referrer"},
        // No HSTS. It was in this table and came out: HSTS is scoped to a host and not to a host
        // and port (RFC 6797 §8.3), so sending it from this page pins every raw TCP port published
        // on the same name (§8.4) to https as well -- and a raw port relays bytes with no TLS at
        // all, so a visitor whose browser has loaded this page once cannot reach one from a browser
        // for a year, with no click-through and no way for the operator to withdraw it. #98 holds
        // the question; it is not a line of code but a promise about names, and somebody has to
        // decide it is worth that.
    };

    /**
     * The icon, which until now was a 404 in {@code text/plain} on every tab and every bookmark of
     * every hub. Two nodes and the hop between them, drawn rather than fetched: a file would be a
     * build step and a byte array in the binary, and this is under three hundred bytes of markup
     * that also follows the reader's colour scheme, which no {@code .ico} can do.
     */
    private static final String FAVICON =
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\">"
        + "<style>*{fill:#0b57d0}@media(prefers-color-scheme:dark){*{fill:#8ab4f8}}</style>"
        + "<circle cx=\"6\" cy=\"16\" r=\"5\"/><rect x=\"9\" y=\"13\" width=\"14\" height=\"6\" rx=\"3\"/>"
        + "<circle cx=\"26\" cy=\"16\" r=\"5\"/></svg>";

    /**
     * How a page asks for {@link #FAVICON}. A constant and not a literal in each frame because there
     * are two frames on this name -- {@link #page} here and {@link AdminWeb}'s own -- and the second
     * one is how the icon came to be missing from half the hub in the first place, exactly as
     * {@link #NOINDEX} is shared for the same reason.
     */
    static final String ICON = "<link rel=\"icon\" href=\"/favicon.svg\">";

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
                // The request never became one, so the method comes off the exception: it was read
                // before the line that was rejected, and an error is still an answer to a HEAD.
                write(HttpResponse.text(e.status(), e.getMessage()), out, e.isHead());
                return;
            } catch (EOFException e) {
                return;
            }
            LOG.debug("{} {} from {}", req.method(), req.path(), ip);
            boolean headOnly = req.isHead();
            String path = req.path();
            if (path.equals("/v1/noise")) {
                if (!req.method().equals("POST") || !req.wantsUpgrade(UPGRADE_PROTOCOL)) {
                    write(HttpResponse.text(426, "expected Upgrade: " + UPGRADE_PROTOCOL), out, headOnly);
                    return;
                }
                if (!handshakes.allow(ip)) {
                    LOG.warn("too many handshakes from {}, refusing", ip);
                    write(HttpResponse.text(429, "too many handshakes"), out, headOnly);
                    return;
                }
                HttpResponse.upgrade(UPGRADE_PROTOCOL).writeTo(out);
                new NodeSession(hub, socket, ip).run(in, out);
                return;
            }
            HttpResponse resp;
            try {
                // Only the building is guarded, not the write: a throw here has put no byte on the
                // wire yet, so the answer below is the connection's first and only response. With
                // the write inside the try, an unchecked throw partway through one would append a
                // second whole response to the first and the client would read the pair as one.
                resp = route(req);
            } catch (RuntimeException e) {
                // Every handler below here runs on this connection's virtual thread, and nothing
                // above catches anything but IOException: an unchecked throw used to close the
                // socket with no response and kill the thread printing a stack trace outside Log.
                // One handler doing that was found in review; this is so the next one answers.
                LOG.warn("error serving {}: {}", req.path(), e.toString());
                // Through the frame, like the other answers a person can arrive at -- but not
                // through page(), which is what may have just thrown. A literal, so this handler
                // cannot be the second thing to fail on the same connection.
                resp = HttpResponse.html(500, ERROR_PAGE);
            }
            write(resp, out, headOnly);
        } catch (IOException e) {
            LOG.debug("connection error: {}", e.toString());
        }
    }

    /**
     * The one place a response leaves this front, the 101 that hands the connection to Noise aside.
     * Every answer goes out through here, so a route added later cannot be written without the
     * headers, which is the point of applying them at the write and not at each handler.
     */
    private static void write(HttpResponse r, OutputStream out, boolean headOnly) throws IOException {
        // headOnly rather than each route dropping its own body: the response to a HEAD carries the
        // header fields a GET would have, Content-Length included (RFC 9110 §9.3.2), so the body has
        // to exist here to be described and not be written.
        secured(r).writeTo(out, headOnly);
    }

    /**
     * Whether what asked for this path is a machine rather than somebody with a browser: the JSON
     * under {@code /v1}, the metrics path a scraper may still be pointed at, and the file a crawler
     * fetches. Those are answered in text, because a frame is bytes each of them has to skip. It is
     * a list here and not a property of the route because the method guard runs above the dispatch;
     * a path added to {@link #route} is a path this has to be told about.
     */
    private static boolean machinePath(String path) {
        return path.startsWith("/v1/") || path.equals("/metrics") || path.equals("/robots.txt");
    }

    /**
     * The headers themselves, for the one answer on this hub that is not written by {@link #write}:
     * {@link SniRouter} writes the wildcard's page on a socket of its own. {@code set} and not
     * {@code add}, so this says the same thing whether it runs once or twice and a handler that has
     * set one of these itself gets replaced rather than doubled -- two policies on one response are
     * intersected by the browser, so the looser one a handler asked for would silently not apply.
     */
    static HttpResponse secured(HttpResponse r) {
        for (String[] h : SECURITY_HEADERS) {
            r.headers().set(h[0], h[1]);
        }
        return r;
    }

    /**
     * The last-resort page, held as a literal because it is written when something else threw:
     * {@link #page} builds every other page here, and a 500 handler that calls the machinery that
     * just failed is a handler that fails twice and answers nothing.
     */
    private static final String ERROR_PAGE = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        + NOINDEX + ICON + "<title>Something went wrong</title>"
        + "<style>body{font-family:system-ui,sans-serif;max-width:48rem;margin:4rem auto;padding:0 1.5rem;"
        + "line-height:1.65;color-scheme:light dark}</style></head><body><h1>Something went wrong</h1>"
        + "<p>The hub could not answer that. It is still running: <a href=\"/\">the hub's page</a> says"
        + " how it is doing.</p></body></html>";

    HttpResponse route(HttpRequest req) throws IOException {
        String path = req.path();
        if (path.equals("/admin") || path.startsWith("/admin/")) {
            return hub.adminWeb().handle(req);
        }
        if (!req.method().equals("GET") && !req.method().equals("HEAD")) {
            // The guard is above the dispatch, so it answers for paths of both kinds and has to
            // pick the shape the way each of them would: a POST to /v1/key is a client that got
            // the method wrong, and a page is bytes it has to skip to find that out.
            // Allow, because a 405 without it is the one thing RFC 9110 §15.5.6 requires of this
            // status, and /admin -- the only path here that takes anything else -- never arrives.
            return (machinePath(path) ? HttpResponse.text(405, "method not allowed")
                : errorPage(405, "Not that way", "That method is not one this page answers."
                    + " Everything here is a GET.")).header("Allow", "GET, HEAD");
        }
        if (path.equals("/favicon.svg") || path.equals("/favicon.ico")) {
            // Both names: the link element in the frame asks for the first, and a browser that was
            // given no link element, or a bookmark, asks for the second. One drawing answers both,
            // and it is the same on every page, so unlike the rest of this front it is cacheable.
            return new HttpResponse(200).header("Content-Type", "image/svg+xml")
                .header("Cache-Control", "public, max-age=86400").body(FAVICON);
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
            // In text, and not through the frame: what polls this path is a scraper still pointed
            // at where metrics used to be, and four kilobytes of HTML per poll to say "not here" is
            // exactly the machine answer this branch's own rule says not to frame.
            return HttpResponse.text(404, "metrics are not served on this name; see --metrics-listen");
        }
        if (path.equals("/robots.txt")) {
            return HttpResponse.text(200, ROBOTS);
        }
        if (path.startsWith("/join/")) {
            String token = path.substring("/join/".length());
            if (token.isEmpty() || token.contains("/")) {
                return errorPage(404, "Not found", "That is not an invitation.");
            }
            // Viewing the page never consumes the invite (ARCHITECTURE.md §10).
            String url = hub.config().baseUrl() + "/join/" + escape(token);
            return HttpResponse.html(200, page("jailscale invitation",
                "<p>Run this on the machine you want to join:</p>"
                + "<pre>jailscale up --invite " + url + "</pre>"
                + "<p>Install jailscale first if you do not have it. Opening this page does not use "
                + "the invitation up.</p>", false))
                // The one page here whose body is a credential, and until now the only 200 on this
                // route without it: the two pages that carry nothing secret said no-store and the
                // invitation did not.
                .header("Cache-Control", "no-store");
        }
        if (path.equals("/")) {
            return HttpResponse.html(200, page("jailscale hub", preview(), home(req), true))
                .header("Cache-Control", "no-store");
        }
        if (path.equals("/links")) {
            return HttpResponse.html(200, page("Open links", directory(req), false)).header("Cache-Control", "no-store");
        }
        return errorPage(404, "Not found", "There is no page at <code>" + escape(path)
            + "</code> on this hub.");
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
            String when = bucketLabel(end, bucketMs);
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

    /**
     * What a graded row is: one of the three states the strip's colours already name. A row with no
     * threshold has no {@code Health} at all rather than a permanent {@link #OK}, because "this row
     * cannot be wrong" and "this row is currently right" are different claims.
     */
    enum Health {
        OK(GOOD, ""),
        WARNING(HttpFront.WARNING, "Warning"),
        CRITICAL(HttpFront.CRITICAL, "Critical");

        private final String colour;
        private final String word;

        Health(String colour, String word) {
            this.colour = colour;
            this.word = word;
        }

        /** The dot, and the word beside it, because colour is never the only channel (§13.2). */
        String mark() {
            return this == OK ? "" : "<span class=\"sw\" style=\"background:" + colour + "\"></span><b>" + word + "</b>: ";
        }
    }

    /** A thing the page grades: its state, and how the verdict line says it in words. */
    record Problem(Health level, String says) {}

    /**
     * One reading of the certificate, taken once per page: whether one is loaded, when it ends, and
     * how long that is from now. The grade above the table and the row inside it are two statements
     * about the same certificate, and reading it twice lets a renewal land between them -- a row
     * showing ninety days under a mark that says the certificate expired.
     */
    private record Cert(boolean loaded, String notAfter, long left) {}

    /**
     * The wildcard's remaining life as a grade. It is the one row on this page whose number decides
     * whether every name under the hub keeps working, and until now 85 days left and 5 days left
     * were the same sentence in the same grey. Fourteen days is roughly two renewal attempts plus a
     * weekend; three is little enough that a person has to be told now.
     *
     * <p>Package-private and taking the milliseconds rather than reading the hub, so the thresholds
     * can be tested at values no fixture can hold: a certificate that expires in six days is not
     * something a test resource can be, since it would have to be reissued to stay six days away.
     */
    static Health certificateHealth(boolean loaded, long msLeft) {
        if (!loaded) {
            return Health.WARNING;
        }
        long day = 86_400_000L;
        if (msLeft < 3 * day) {
            return Health.CRITICAL;
        }
        return msLeft < 14 * day ? Health.WARNING : Health.OK;
    }

    /**
     * The one line above the table, and the reason the table is worth grading at all: a reader who
     * does not know that 85 days of certificate is fine and 5 is not can now be told which this is
     * without reading a row. The worst grade decides the word and the dot; every problem at that
     * grade and below is named, because "Degraded" without saying what is degraded sends the reader
     * back to the table this line exists to save them from.
     */
    static String verdict(List<Problem> checks) {
        Health worst = Health.OK;
        StringBuilder says = new StringBuilder();
        for (Health h : List.of(Health.CRITICAL, Health.WARNING)) {
            for (Problem p : checks) {
                if (p.level() == h) {
                    if (worst == Health.OK) {
                        worst = h;
                    }
                    says.append(says.length() > 0 ? "; " : "").append(p.says());
                }
            }
        }
        String word = worst == Health.OK ? "All systems operational"
            : (worst == Health.CRITICAL ? "Critical" : "Degraded") + " &mdash; " + says;
        return "<p class=\"verdict\"><span class=\"sw\" style=\"background:" + worst.colour + "\"></span>" + word + "</p>";
    }

    /** The one reading of the certificate that both the grade and the row are made from. */
    private Cert certState() {
        if (!hub.tls().isLoaded()) {
            return new Cert(false, null, 0);
        }
        java.util.Date notAfter = hub.tls().leaf().getNotAfter();
        return new Cert(true, notAfter.toString(), notAfter.getTime() - System.currentTimeMillis());
    }

    /** The certificate's grade and how the verdict says it. {@link #certificateRow} says it in the row. */
    private static Problem certificateProblem(Cert c) {
        Health h = certificateHealth(c.loaded(), c.left());
        if (h == Health.OK) {
            return new Problem(h, "");
        }
        return new Problem(h, !c.loaded() ? "no certificate is loaded yet"
            : c.left() <= 0 ? "the certificate expired " + Resources.humanDuration(-c.left()) + " ago"
            : "the certificate expires in " + Resources.humanDuration(c.left()));
    }

    /**
     * Redundancy as a grade. A primary that was never given a peer is a single hub **by choice**
     * and is not missing anything, so it is not graded at all -- a status line that says "Degraded"
     * about every one-host deployment is one an operator learns to ignore, which costs more than
     * the row it was meant to explain. Being given a peer and not having it is the fault.
     */
    private Problem roleProblem(Peer peer) {
        if (peer.following()) {
            return peer.synced() ? new Problem(Health.OK, "")
                : new Problem(Health.WARNING, peer.connected() ? "not in sync with the primary yet"
                    // A hub that stood down to another primary (§13.5) without having been given
                    // a --peer of its own has no peer client at all, so it is not merely out of
                    // touch with a primary, it has none to be out of touch with.
                    : peer.primary() == null ? "standing by with no primary to follow"
                    : "not connected to the primary");
        }
        // Connected, and not more: the primary has no acknowledgement to grade, and a standby that
        // stops reading is dropped by Peers at MAX_QUEUED and becomes the absence this does grade.
        // That cap is reached by events being appended, though, so on a hub where nothing is
        // happening there is no bound on the wait at all. Between the two it reads as connected,
        // which is the limit of what this side knows.
        return hub.config().peer() != null && peer.standbys().isEmpty()
            ? new Problem(Health.WARNING, "no standby is connected")
            : new Problem(Health.OK, "");
    }

    /**
     * One reading of the hub-to-hub state, taken once per page. {@code following} is this hub being
     * a standby: then the other fields describe the primary it follows, and {@code standbys} is
     * empty -- {@code primary} is null when it has no peer client, which is a hub that stood down
     * (§13.5) and is following nothing. Otherwise it holds the sessions standbys have open to this
     * one. {@code synced} implies {@code connected}, which is why the two are sampled in that order.
     */
    private record Peer(boolean following, boolean connected, boolean synced, String primary,
                        String lastError, List<Peers.Session> standbys) {}

    /**
     * What a bucket is called, with the hour on it even for a day-wide one. Buckets are measured
     * back from the moment the page was built, not from midnight, so a day bucket runs from
     * 08:05 to 08:05 and naming it by date alone puts an outage on the wrong date for anyone
     * reading a printed list -- tolerable in a tooltip, not in a table of dates. Used by the
     * picture and by the list under it, so the two cannot disagree about which bucket a number
     * belongs to.
     */
    private static String bucketLabel(long end, long bucketMs) {
        return escape(java.time.Instant.ofEpochMilli(end - bucketMs).toString()
            .substring(0, 16).replace('T', ' ')) + (bucketMs >= 86_400_000L ? " +24h" : "");
    }

    /**
     * The same numbers as the strip, in text, for every reader the tooltip has nothing for: there is
     * no hover on a phone, nothing in the strip can be reached by keyboard, and {@code role="img"}
     * with a label is a reason for an assistive reader not to descend into the bars at all. The
     * sentence under the strip says "each bar says its minutes", and until now that was true of one
     * kind of reader.
     *
     * <p>Only the buckets that were not green, which is what anybody is looking for and which keeps
     * this bounded at 30 or 24 rows while usually being empty. A bucket from before the record
     * began is not listed: it is not a bucket this hub was down for, it is one it cannot speak
     * about, and thirty rows of "no record" on a new hub would bury the two rows that matter.
     */
    private static String notGreen(long[] minutes, long now, long bucketMs, String unit, String of) {
        StringBuilder rows = new StringBuilder();
        int n = 0;
        for (int i = 0; i < minutes.length; i++) {
            if (minutes[i] <= 0) {
                continue;
            }
            n++;
            rows.append("<tr><td>").append(bucketLabel(now - (minutes.length - 1 - i) * bucketMs, bucketMs))
                .append("</td><td>").append(minutes[i]).append(" min down</td></tr>");
        }
        if (n == 0) {
            return "";
        }
        // "not green" would put the state in the colour alone, on the line that is collapsed --
        // which is the one channel §13.2 says never to rely on, and the reason this list exists.
        return "<details><summary>" + n + " " + unit + (n == 1 ? "" : "s") + " with " + escape(of)
            + ", of the last " + minutes.length + "</summary><table>" + rows + "</table></details>";
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
        // Sampled once for the whole page, for the reason the status section below already gives:
        // the role is live state, and a hub promoted between two readings of it renders a page that
        // contradicts itself -- here, "it is the standby" above a table that says primary.
        boolean standby = hub.isStandby();
        b.append("<p><code>").append(host).append("</code> is a jailscale hub. It publishes a port on your")
            .append(" machine over HTTPS without opening an inbound port: the hub relays the bytes and your")
            .append(" machine terminates the TLS. <a href=\"").append(REPO).append("\">What this is</a>.</p>");

        // In the order someone has to do it. The page used to say how to join and stop there, which
        // leaves out both where the binary comes from and what joining was for.
        b.append("<h2>Publish a port</h2>");
        b.append("<p><a href=\"").append(REPO).append("/releases/latest\">Download <code>jailscale</code></a>")
            .append(" for Linux, Apple-silicon macOS or Windows: one file, no runtime to install")
            .append(" underneath it, no root. Intel Macs run <code>jailscale.jar</code> on a JVM.</p>");
        // "latest" is a moving target and this hub is not: it can say which copies it will talk to,
        // and what happens to one it will not, so nobody has to find that out from a failed join.
        // What it must not say is that any recent release will do: the floor is enforced from both
        // ends -- a jailscale has its own minimum hub protocol and refuses a hub below it -- and
        // this page can only speak for this end of it.
        b.append("<p>This hub speaks <b>protocol ")
            .append(Message.PROTO).append("</b> and takes ").append(TAKES)
            .append(". One that is too old is turned away at the handshake with a line saying so and")
            .append(" which version this hub runs, rather than half-working; a jailscale newer than")
            .append(" this hub decides for itself whether it will still talk to it.")
            // Naming the number is only half of it: the reader also has to get the same number out
            // of the copy they hold. #140 gave them the command; this names it, because the
            // paragraph is the only place the two numbers meet and it stated one of them (#168).
            // "a current copy", not "your copy": every jailscale released before #140 prints the
            // build alone, and that reader -- holding an existing copy, checking it against this
            // hub's floor -- is this paragraph's whole audience. Telling them their binary does
            // something it does not is the mistake the comment above is about, in the other
            // direction: this page can only speak for its own end.
            .append(" <code>jailscale version</code> prints the protocol a current copy speaks,")
            .append(" beside its build. A copy that prints no protocol is older than the release")
            .append(" this hub came from.</p>");
        // The page already says how to check the hub's binary. It said nothing about the file the
        // reader is about to download, which is the one they can actually do something about.
        b.append("<p>The releases are signed. Once you have <code>jailscale</code>,")
            .append(" <code>jailscale update --download</code> checks the signature of everything it")
            .append(" fetches after that, so this is the one copy you check by hand: the signature is")
            .append(" over <code>RELEASE.txt</code>, which names the tag and carries the digest of")
            .append(" <code>SHA256SUMS.txt</code>, and your download's hash is in that.")
            .append(" <a href=\"").append(REPO).append("/blob/main/docs/release-verification.md\">")
            .append("How to check it</a> is one command from a clone, or four by hand. The first copy")
            .append(" is the one nothing of ours can vouch for yet; every copy after it is checked")
            .append(" against a key this one pinned.</p>");
        if (standby) {
            // A standby answers Goodbye{standby} to every control connection (§13.4), so the join
            // below is not printed here at all rather than printed beside a warning: a page that
            // invites a join it will refuse is worse than one that says nothing, and while the
            // primary is down the apex this would tell them to type resolves to nothing.
            b.append("<p><b>Not on this host, though:</b> it is the standby. It serves links that are")
                .append(" already open and takes no joins; the primary is where joining happens.</p>");
        } else {
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
        }

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

        // Who runs this hub, and what it keeps. Drawn only when the operator has said so: a hub
        // somebody runs for themselves has nobody to name and no terms to point at, and a section
        // that appeared on every hub to say "not configured" would be a worse page for the case
        // that needs it least (#99).
        // Stripped where it is read and not only where it is written (AdminIpc): a value arrives
        // here from the replication stream as well, so a primary running a build without that rule
        // would otherwise have this page draw the section around a blank name -- and, worse, drop
        // the closing warning below on the strength of it.
        String operator = hub.store().setting(Store.SETTING_OPERATOR, "").strip();
        String contact = hub.store().setting(Store.SETTING_CONTACT, "").strip();
        String terms = hub.store().setting(Store.SETTING_TERMS, "").strip();
        // One boolean and not the same three tests written twice: the closing sentence under
        // Limits turns on exactly this, and a hand-written negation of it down there is a link to
        // an anchor that was never drawn, waiting for somebody to edit one of the two.
        boolean named = !operator.isEmpty() || !contact.isEmpty() || !terms.isEmpty();
        if (named) {
            b.append("<h2 id=\"who\">Who runs this hub</h2><p>");
            if (!operator.isEmpty()) {
                b.append("Run by <b>").append(escape(operator)).append("</b>. ");
            }
            if (!contact.isEmpty()) {
                // The scheme was checked when it was set (AdminIpc.SETTING_TEXT), which is what
                // makes it safe to put in an href; escaped here as well, for the quotes.
                b.append("<a href=\"").append(escape(contact)).append("\">Contact</a>");
            }
            if (!contact.isEmpty() && !terms.isEmpty()) {
                b.append(" &middot; ");
            }
            if (!terms.isEmpty()) {
                b.append("<a href=\"").append(escape(terms)).append("\">What is allowed here</a>");
            }
            b.append("</p>");
            // The retention sentence belongs here and not in "What this hub can see", which is
            // about the traffic while it is moving. These are what stays afterwards, and the last
            // line is the important one: the process can speak for the process and no further.
            b.append("<p>What it keeps: the node list -- who joined, the hostname and system each")
                .append(" machine reported, the names they hold and when -- for as long as a node is")
                .append(" registered; the address a machine knocked from, and the hostname and system")
                .append(" it gave, while its join is waiting to be approved or denied; the addresses the")
                .append(" operator has barred; and thirty days of uptime record. A visit to a link is relayed and")
                .append(" not recorded: the hub counts visitors and keeps no list of them, and at its")
                .append(" default log level it names nodes, not visitors. What the machine underneath")
                .append(" keeps -- the system journal, a proxy in front, a backup of the state")
                .append(" directory -- is the operator's and not something this page can answer for.</p>");
        }

        int online = hub.registry().size();
        int registered = hub.store().nodes().size();
        long rss = Resources.rssBytes();

        // The rows that have a threshold, graded before any of them is written, because the verdict
        // goes above the table and is the worst of them. Everything else on this page is a fact with
        // no good or bad about it -- a version, a key, a memory figure -- and stays ungraded.
        PeerClient pc = hub.peerClient();
        // Sampled once, at the top of this method, and used by every part of the page that depends
        // on the role. The grade and the Role row are two readings of the same live state, and
        // taken separately a standby that connects or drops between them puts a verdict on the page
        // that contradicts the row directly under it. The role is read on its own and not through
        // `pc != null`: a hub that stood down without a --peer of its own is a standby with no peer
        // client, and reading it as a primary would have this page call it healthy.
        Peer peerState;
        if (standby) {
            // isSynced() is already "connected and synced", so it is sampled first and connected is
            // widened to match; the other order can leave synced true beside connected false, which
            // the row would print as "in sync" for a hub that is not.
            boolean synced = pc != null && pc.isSynced();
            peerState = new Peer(true, synced || (pc != null && pc.isConnected()), synced,
                pc == null ? null : pc.primaryHost(), pc == null ? null : pc.lastError(), List.of());
        } else {
            peerState = new Peer(false, false, false, null, null, hub.peers().all());
        }
        Cert certState = certState();
        Problem cert = certificateProblem(certState);
        Problem role = roleProblem(peerState);
        // A hub nobody has joined yet is not a hub in trouble; one whose nodes have all gone is.
        // Only a primary grades it, for the same reason it cannot grade a standby as in sync: a
        // standby takes no control connections, so what it counts online is the relay connections
        // nodes have opened to it (§13.4), and a node that has not opened one yet is not a node
        // that is down.
        Problem nodes = !peerState.following() && registered > 0 && online == 0
            ? new Problem(Health.WARNING, registered == 1 ? "the one registered node is offline"
                : "none of the " + registered + " registered nodes are online")
            : new Problem(Health.OK, "");
        b.append("<h2>Status</h2>").append(verdict(List.of(cert, role, nodes))).append("<table>");
        // Said plainly when it is not a release, because the string alone does not say so to
        // anyone who does not read Maven: a hub built from main reports the pom's version, which
        // only a tag build replaces (`versions:set` in release.yml), so every source, `edge` and
        // workflow_dispatch build carries a number that reads like a release. One of them served
        // this page as "0.1.0-SNAPSHOT" long after v0.1.2 shipped, and the operator reading it had
        // no way to tell from here that it was neither 0.1.0 nor current.
        row(b, "Version", escape(Hub.version()) + (released(Hub.version()) ? "" : " (not a release build)"));
        // Beside the version, because it is the other half of "will my copy work here": a version
        // says what this hub is, the protocol says what it will talk to (§5.4).
        row(b, "Protocol", Message.PROTO + ", and takes " + TAKES);
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
        // The arrays are built once and used twice over: the picture, and the list of what is in
        // it that a tooltip cannot tell anybody.
        long[] byDay = downMinutes(avail::processDownBetween, now, day, 30);
        long[] byHour = downMinutes(avail::processDownBetween, now, hour, 24);
        row(b, "Availability", "by this process's own record" + sinceNote
            + strip(byDay, now, day, 60, "Uptime per day, last 30 days")
            + ends("30 days ago", avail.processFraction(30 * day, now), "Today")
            + notGreen(byDay, now, day, "day", "downtime")
            + strip(byHour, now, hour, 15, "Uptime per hour, last 24 hours")
            + ends("24 hours ago", avail.processFraction(day, now), "Now")
            + notGreen(byHour, now, hour, "hour", "downtime") + LEGEND);
        for (String peer : avail.peerNames()) {
            long[] peerByDay = downMinutes((f, t) -> avail.peerDownBetween(peer, f, t), now, day, 30);
            row(b, "Seen from here", "<code>" + escape(peer) + "</code>"
                + strip(peerByDay, now, day, 60, "The channel to " + peer + " per day, last 30 days")
                + ends("30 days ago", avail.peerFraction(peer, 30 * day, now), "Today")
                + notGreen(peerByDay, now, day, "day", "the channel down"));
        }
        if (peerState.following()) {
            row(b, "Role", role.level().mark()
                + (peerState.primary() == null ? "standby, following no primary"
                    : "standby of <code>" + escape(peerState.primary()) + "</code>") + ", "
                + (peerState.synced() ? "in sync" : peerState.connected() ? "connected, not yet in sync" : "not connected"
                    + (peerState.lastError() == null ? "" : " (" + escape(peerState.lastError()) + ")"))
                + ", epoch " + hub.epoch());
        } else {
            StringBuilder r = new StringBuilder("primary");
            if (peerState.standbys().isEmpty()) {
                r.append(", no standby connected");
            } else {
                r.append(", standby");
                for (Peers.Session ps : peerState.standbys()) {
                    r.append(" <code>").append(escape(ps.name())).append("</code>");
                }
                // Not "in sync", which this side cannot say: a standby acknowledges nothing, so all
                // the primary knows is that the channel is open and what it has written to it. The
                // standby is the side that knows, and its own page is where it says so.
                r.append(" connected");
            }
            r.append(", epoch ").append(hub.epoch());
            row(b, "Role", role.level().mark() + r);
        }
        row(b, "Nodes", nodes.level().mark() + online + " online of " + registered + " registered");
        row(b, "Certificate", cert.level().mark() + certificateRow(certState));
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
            .append("</a> it claims to be -- checked through <code>RELEASE.txt</code>'s signature the same way as")
            .append(" above, since an unchecked checksum list says nothing about which release it belongs to --")
            .append(" and remembering that a container or source build is its own binary. Both are")
            .append(" what this hub says about itself, so they tell you an operator is running what they think they")
            .append(" are; a dishonest hub prints whatever it likes here.</small></p>");

        // A taste of what this hub is serving, and the directory for the rest. The whole list used
        // to be here, which made the one section that grows without bound the one a visitor
        // scrolled through to reach the limits: every other section on this page has a fixed
        // length. The rows are the directory's rows, so the two pages are one list and not two
        // designs; what /links adds is the rest of them and what they mean.
        b.append("<h2>Open links</h2>");
        List<Keyed> links = sortedLinks();
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
        // The closing sentence is the one #99 exists to replace, and only for a hub that has
        // replaced it: naming an operator and a contact is what turns "do not depend on this" into
        // "here is who to ask". A hub that has named nobody keeps the warning, because for that one
        // it is still true.
        b.append(named
            ? "<p>The operator can remove a node or bar an address. Who that is, and on what terms,"
                + " is under <a href=\"#who\">Who runs this hub</a> above.</p>"
            : "<p>The operator can remove a node or bar an address, so treat an open hub you do not run"
                + " as a place to try this rather than one to depend on.</p>");

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
     * <p>Three facts per link: the address, which is public by construction because a visitor
     * reaches it by typing it; its kind; and how long it has been open. Nothing here is fetched
     * from the link itself.
     *
     * <p><b>And none of it is for a search index.</b> "Public by construction" is an argument
     * about the visitor who types the address, not about a result that hands the whole list to
     * somebody who never heard of this hub and keeps saying "open 3 days" after the node has gone,
     * so this page says {@link #NOINDEX} and {@link #ROBOTS} deliberately leaves it fetchable --
     * a page named in {@code Disallow} is never fetched, so its {@code noindex} is never read.
     *
     * <p><b>Not how many visitors a link is serving</b>, although the hub has that number and this
     * page carried it for a while. That the name exists was already public; that somebody is using
     * it right now was not, and a page anyone can poll turns it into a live activity feed for a
     * machine that belongs to somebody else. It is also the one figure {@link AdminWeb} keeps for
     * the operator in as many words -- "how close a particular node is to its bound ... is the
     * operator's business and nobody else's" -- and §6.3 refuses the same shape on {@code
     * /metrics}, which listens on loopback and so has a narrower audience than this. The reader
     * here loses little: a visitor deciding whether to click a link learns more by clicking it. A thumbnail or a favicon would mean
     * the hub connecting to a node's app as a visitor and republishing what came back on its own
     * front page -- which is the one thing the front page tells people it does not do -- and would
     * put whatever anyone who can join chooses to serve on the operator's page. Who owns a name and
     * which local port it reaches stay behind the admin session, as the node list does.
     */
    private String directory(HttpRequest req) {
        return directory(req, LINKS_SHOWN);
    }

    /** Package-private with the page size, so a test can reach the second page without 201 links. */
    String directory(HttpRequest req, int pageSize) {
        StringBuilder b = new StringBuilder(nav("/links"));
        List<Keyed> links = sortedLinks();
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
        // The list is already sorted by exactly this key, so the cursor is a binary search rather
        // than a walk: the walk rebuilt a key per row it skipped, which is the cost sortedLinks
        // exists to avoid, and on a long list it made paging to the end quadratic.
        int start = from == null ? 0 : firstAtOrAfter(links, from);
        if (start == links.size()) {
            // The cursor names a point past the last row, which is what a bookmarked or forwarded
            // one becomes once the links it started from close. Saying so beats an empty table
            // under a sentence that has just counted the links this hub is serving.
            b.append("<p>Nothing is open at that point in the list any more. ")
                .append("<a href=\"/links\">Start from the first</a>.</p>");
        } else {
            int end = Math.min(start + pageSize, links.size());
            linkRows(b, links.subList(start, end));
            if (end < links.size()) {
                // The next row's own key, never the cursor the caller sent, so nothing a visitor
                // typed is echoed back into the page; and percent-encoded, because it is going
                // into a query string that URLDecoder reads back, not only into an attribute.
                b.append("<p><a href=\"/links?from=").append(escape(urlEncode(links.get(end).key()))).append("\">The next ")
                    .append(Math.min(pageSize, links.size() - end)).append(" of ").append(links.size() - end)
                    .append(" remaining &rarr;</a></p>");
            }
            if (start > 0) {
                // What the first page actually holds, not the cap: a hub with nine links offered
                // to take the reader "back to the first 200".
                b.append("<p><a href=\"/links\">&larr; Back to the first ").append(Math.min(pageSize, links.size()))
                    .append("</a></p>");
            }
        }
        b.append("<p><small>How busy a link is is not on this page: that a name is open is public,")
            .append(" and who is using it at this moment is not. \"Open\" is since the link was opened:")
            .append(" a node that restarts or hands its name to another machine opens a new one, so")
            .append(" this counts the current one, not the name.</small></p>");
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
    private void linkRows(StringBuilder b, List<Keyed> links) {
        long now = System.currentTimeMillis();
        b.append("<table class=\"links\">");
        for (Keyed k : links) {
            Links.Link l = k.link();
            row(b, address(l), escape(l.kind()) + " &middot; open " + Resources.humanDuration(now - l.openedAt()));
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
    private List<Keyed> sortedLinks() {
        List<Keyed> keyed = new ArrayList<>();
        for (Links.Link l : hub.links().all()) {
            keyed.add(new Keyed(sortKey(l), l));
        }
        keyed.sort(Comparator.comparing(Keyed::key));
        return keyed;
    }

    /** A link beside the key it sorts and pages by, so that key is built once per request. */
    private record Keyed(String key, Links.Link link) {}

    /** The first index whose key is not before {@code from}, by binary search on the sorted keys. */
    private static int firstAtOrAfter(List<Keyed> links, String from) {
        int lo = 0;
        int hi = links.size();
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (links.get(mid).key().compareTo(from) < 0) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    /** For a value going into a query string, which {@link #escape} does not cover. */
    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * What the row will actually say, which is what a reader scans and so what the list is
     * ordered by. Sorting by {@code name()} put a raw port among the names beginning with its
     * kind -- {@code tcp/2001} sorts under "t" while the row reads {@code <hub>:2001} -- so raw
     * rows landed at a position matching nothing on the page. The port is padded because this key
     * is compared as text and 9000 belongs before 20000, not after it; that also makes every
     * link's key distinct, which is what lets it serve as the paging cursor. {@code Locale.ROOT}
     * because of that second job: a JVM whose default locale numbers in Arabic-Indic or Devanagari
     * digits would put those code points in the cursor and in the URL carrying it, and the hub that
     * read it back -- a standby, or the same hub under a different {@code LANG} -- would not match
     * them. The hub's own listen port is left off the key although the row shows it, because it is
     * the same on every row and so cannot change the order.
     */
    private String sortKey(Links.Link l) {
        return l.raw()
            ? hub.config().hostname() + ":" + String.format(java.util.Locale.ROOT, "%05d", l.port())
            : l.host(hub.config());
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
        // With the port the hub is answering on, which is what the node was told when the link
        // opened (Links.portSuffix). Without it every row on a hub that is not on 443 is a link
        // to nothing, which matters more now that the rows are a page meant to be handed around.
        String suffix = hub.links().portSuffix();
        // rel=nofollow, not for ranking but because the other end is somebody else's machine and
        // the hub does not fetch what is behind a link (§6.3). The directory says nofollow for the
        // whole page; the home page is indexable, so its eight rows have to say it themselves --
        // and say it more weakly, since the robots meta's nofollow is a directive while the rel
        // attribute has been a hint since 2020, and neither keeps the eight addresses themselves
        // out of an index, because they are text on a page that says it may be listed. §5.1 names
        // that as the gap this leaves rather than one it closes.
        return "<a rel=\"nofollow\" href=\"https://" + host + suffix + "\">" + host + suffix + "</a>";
    }

    /**
     * The wildcard's remaining life, not just "loaded". Its expiry takes every name under the hub
     * down at once, and until now the only place that number appeared was a log line at install
     * time (ARCHITECTURE.md §15).
     */
    private static String certificateRow(Cert c) {
        if (!c.loaded()) {
            return "not loaded yet";
        }
        return c.left() <= 0
            ? "EXPIRED " + Resources.humanDuration(-c.left()) + " ago"
            : escape(c.notAfter()) + " (" + Resources.humanDuration(c.left()) + " left)";
    }

    private static void row(StringBuilder b, String label, String value) {
        b.append("<tr><td>").append(label).append("</td><td>").append(value).append("</td></tr>");
    }

    /** The frame, for a page a search engine is welcome to list. Only {@code /} is one. */
    private static String page(String title, String body, boolean indexable) {
        return page(title, "", body, indexable);
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
     *
     * <p>{@code indexable} is false for the pages that are served to whoever holds their URL -- the
     * directory and an invitation. {@link #ROBOTS} explains why those are left fetchable rather
     * than disallowed: this meta is the thing that actually keeps them out of an index, and a
     * crawler has to be allowed to read it.
     */
    private static String page(String title, String head, String body, boolean indexable) {
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            + (indexable ? "" : NOINDEX)
            + ICON
            + head
            + "<title>" + escape(title) + "</title><style>"
            + ":root{color-scheme:light dark;--bg:#fff;--ink:#15171a;--dim:#70757c;--rule:#e7e8ea;--wash:#f5f6f7;--link:#0b57d0}"
            + "body{font-family:system-ui,-apple-system,sans-serif;max-width:48rem;margin:4rem auto 6rem;"
            + "padding:0 1.5rem;line-height:1.65;color:var(--ink);background:var(--bg);overflow-wrap:break-word}"
            + "h1{font-size:1.5rem;letter-spacing:-.01em;margin:0 0 1rem}"
            + "h2{font-size:.75rem;text-transform:uppercase;letter-spacing:.09em;color:var(--dim);"
            + "font-weight:600;margin:2.75rem 0 .5rem}"
            + "p{margin:.75rem 0}a{color:var(--link)}"
            + "p.verdict{font-weight:600;margin:.25rem 0 1rem}"
            + "details{margin:.5rem 0;font-size:.85rem}summary{cursor:pointer;color:var(--dim)}"
            + "details table{margin:.25rem 0 .5rem}details td:first-child{width:9rem}"
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
     * What a chat client, a search result or anything else that unfurls a URL is given. Only the
     * hub's own page has it: it is the one page here meant to be handed to somebody who has not
     * seen this hub, and the others are an invitation whose URL is a credential and a directory
     * that carries other people's names -- neither wants a card made of it.
     */
    private String preview() {
        String host = escape(hub.config().hostname());
        String desc = host + " is a jailscale hub: it publishes a port on your machine over HTTPS,"
            + " without opening an inbound port.";
        return "<meta name=\"description\" content=\"" + desc + "\">"
            + "<meta property=\"og:type\" content=\"website\">"
            + "<meta property=\"og:title\" content=\"" + host + "\">"
            + "<meta property=\"og:description\" content=\"" + desc + "\">"
            // resolve("/") and not the base URL with a slash stuck on: --base-url is taken as given
            // as long as it is https with a host, so an operator who wrote a trailing slash would
            // otherwise have this hub name itself with a doubled one.
            + "<meta property=\"og:url\" content=\"" + escape(hub.config().baseUrl().resolve("/").toString()) + "\">"
            + "<meta name=\"twitter:card\" content=\"summary\">";
    }

    /**
     * An answer a person can arrive at by mistyping, and until now the only thing they got was
     * {@code not found} in the browser's default serif with no way back to the page that would say
     * what this host even is. The machine answers on this front -- the 426 and 429 to a node's
     * control connection, the JSON under {@code /v1} -- stay as they were: their reader is not a
     * browser and a frame would be bytes it has to skip.
     */
    private static HttpResponse errorPage(int status, String title, String says) {
        return HttpResponse.html(status, page(title, nav("") + "<p>" + says + "</p>", false));
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
