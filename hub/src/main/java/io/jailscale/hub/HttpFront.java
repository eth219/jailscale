package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Clock;
import io.jailscale.proto.util.Log;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/**
 * The hub's own HTTP endpoints on its name (ARCHITECTURE.md §5.1): {@code /v1/key}, {@code /v1/noise}
 * (Upgrade), {@code /join/<token>}, {@code /robots.txt} and a root page. {@link SniRouter} hands
 * over connections whose SNI is the hub's own name,
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
     * <p>There is nothing left to disallow. {@code /admin} was the one entry, and it was there for
     * a different reason than secrecy: a login link was one-shot and the admin page consumed it on
     * the GET, so a machine that fetched one to see what was there burned it. The page is gone
     * (#253) and the path now 404s, so the file keeps its empty {@code Disallow} -- the canonical
     * way to say "all of it" -- rather than naming a route that no longer exists.
     *
     * <p>All of it is advice a crawler may ignore, so this raises the floor and is not a control.
     * The one part here that is not advice is that {@code /} names no link at all (§6.3): an
     * address is kept out of an index by not being on the page that asks to be indexed, not by
     * what the markup around it says about itself.
     */
    private static final String ROBOTS = "User-agent: *\nDisallow:\n";

    /**
     * {@code nofollow} as well as {@code noindex}: an invitation and the wildcard's "not open" page
     * are served to whoever holds the URL, and neither is a place a crawler should walk on from.
     */
    static final String NOINDEX = "<meta name=\"robots\" content=\"noindex,nofollow\">";

    /**
     * What every answer on this name carries. The front end's own shape is what makes the policy
     * exact rather than aspirational: there is no script, no external stylesheet, no font, and
     * nothing is ever fetched from a node, so {@code default-src 'none'} is the truth and not an
     * aspiration. {@code form-action} and {@code frame-ancestors} are kept although the admin page
     * that needed them is gone (#253) and no page here posts anything any more: they cost a header
     * either way, and the next form to appear should find the policy already in front of it rather
     * than have to remember to bring it. Applied to every response rather than only to the pages.
     *
     * <p>{@code img-src 'self'} for the icon, which is a route here and not a data URI; if it ever
     * becomes one this has to say {@code data:} instead. {@code Referrer-Policy: no-referrer}
     * because an invitation URL is a credential in a path, and a Referer header is the one way a
     * path travels somewhere nobody chose to send it.
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
     * How a page asks for {@link #FAVICON}. A constant and not a literal because this name used to
     * carry two frames -- {@link #page} here and the admin page's own -- and the second one is how
     * the icon came to be missing from half the hub in the first place. The admin page is gone
     * (#253) and {@link #page} is the only frame left, but the constant stays for the reason
     * {@link #NOINDEX} is shared: the next frame should not have to rediscover this.
     */
    static final String ICON = "<link rel=\"icon\" href=\"/favicon.svg\">";

    private final Hub hub;
    private final RateLimiter handshakes;

    HttpFront(Hub hub) {
        this.hub = hub;
        this.handshakes = new RateLimiter(HANDSHAKE_BURST, HANDSHAKE_PER_SECOND,
            hub.config().tuning().rateLimitPruneMs(), Clock::millis);
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
            } catch (EOFException _) {
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
     * under {@code /v1}, and the file a crawler fetches. Those are answered in text, because a
     * frame is bytes each of them has to skip. It is
     * a list here and not a property of the route because the method guard runs above the dispatch;
     * a path added to {@link #route} is a path this has to be told about.
     */
    private static boolean machinePath(String path) {
        return path.startsWith("/v1/") || path.equals("/robots.txt");
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
    static final String ERROR_PAGE = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        + NOINDEX + ICON + "<title>Something went wrong</title>"
        + "<style>body{font-family:system-ui,sans-serif;max-width:48rem;margin:4rem auto;padding:0 1.5rem;"
        + "line-height:1.65;color-scheme:light dark}</style></head><body><h1>Something went wrong</h1>"
        + "<p>The hub could not answer that. It is still running: <a href=\"/\">the hub's page</a> says"
        + " how it is doing.</p></body></html>";

    HttpResponse route(HttpRequest req) throws IOException {
        String path = req.path();
        if (!req.method().equals("GET") && !req.method().equals("HEAD")) {
            // The guard is above the dispatch, so it answers for paths of both kinds and has to
            // pick the shape the way each of them would: a POST to /v1/key is a client that got
            // the method wrong, and a page is bytes it has to skip to find that out.
            // Allow, because a 405 without it is the one thing RFC 9110 §15.5.6 requires of this
            // status. Since #253 removed the admin page, every path here is a GET or a HEAD, so
            // this now answers for all of them rather than for all but one.
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
                // route without it: the hub page, which carries nothing secret, said no-store and
                // the invitation did not.
                .header("Cache-Control", "no-store");
        }
        if (path.equals("/")) {
            return HttpResponse.html(200, page("jailscale hub", preview(), home(), true))
                .header("Cache-Control", "no-store");
        }
        return errorPage(404, "Not found", "There is no page at <code>" + escape(path)
            + "</code> on this hub.");
    }

    /**
     * Liveness, for something that is not a person and has no credential: is this hub up, which
     * build answered, what it will talk to, how long it has been up, and when the certificate runs
     * out -- the last being the one that takes every name down at once and the one worth alerting
     * on. That is the whole list. It used to carry the counters and the hub's state as well, which
     * made the public name's health check an export of everything the hub knew; the per-node detail
     * is on the {@code jailhub} socket CLI, which is the one admin surface (ARCHITECTURE.md §6.3).
     * Fields may be added; a monitor that reads the ones it knows keeps working (§5.4).
     */
    private JsonObject status() {
        JsonObject.Builder b = JsonObject.builder()
            .put("ok", true)
            .put("hostname", hub.config().hostname())
            .put("version", Hub.version())
            // Beside the version for the reason the status table puts them beside each other: a
            // version says what this hub is, the protocol says what it will talk to (§5.4). The
            // page says it twice and this endpoint said it nowhere, so the one consumer that
            // cannot read the HTML -- a fleet monitor, which is who this endpoint is for -- had to
            // hardcode a version-to-protocol mapping that no release note carries, or scrape the
            // page. Both constants, so the answer cannot drift from what the handshake enforces.
            .put("proto", Message.PROTO)
            .put("minProto", NodeSession.MIN_PROTO)
            .put("uptimeSeconds", Resources.uptimeMillis() / 1000)
            .put("certificateNotAfter", hub.tls().isLoaded() ? hub.tls().leaf().getNotAfter().getTime() / 1000 : null);
        return b.build();
    }

    /** The status colours (good, warning, critical), validated for colour-vision separation as a set. */
    private static final String GOOD = "#0ca30c";
    private static final String WARNING = "#fab219";
    private static final String CRITICAL = "#d03b3b";

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

        /** The dot, and the word beside it, because colour is never the only channel (§6.3). */
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
     * Whether a stored URL is a page this hub will link to. Schemes are case-insensitive, so
     * {@code HTTPS://} is a URL and refusing it would be an error whose difference from what the
     * operator typed is invisible.
     */
    static boolean https(String url) {
        return url.toLowerCase(java.util.Locale.ROOT).startsWith("https://");
    }

    /**
     * Whether a stored URL may be put in an {@code href}: a page, or an address to write to. Used
     * where the value is set ({@link AdminIpc}) <b>and</b> where it is read: a value arrives by
     * replication too, from a peer that may be running a build older than this rule, and a check
     * that only guards the front door is not a check.
     */
    static boolean linkable(String url) {
        return https(url) || url.toLowerCase(java.util.Locale.ROOT).startsWith("mailto:");
    }

    /**
     * A stored setting, or nothing at all when it is not a value this page will link to. The rule
     * is {@link AdminIpc#SETTING_TEXT}'s own and not a second reading of it: a rule written twice
     * is a rule that parts, and it had -- {@code terms} refuses {@code mailto:} where it is set,
     * so a page that asked only "is this linkable" would have published as terms of use an
     * address a peer replicated in. Empty is not a URL, so a cleared setting falls out here too.
     */
    private String linkOrNothing(String key) {
        String url = hub.store().setting(key, "").strip();
        return AdminIpc.SETTING_TEXT.get(key).test(url) ? url : "";
    }

    /**
     * The hub's own page: what it is, how to join it, and how it is doing. Counts and resource
     * use are public; they describe the service, not the people on it. Per-node detail and the
     * controls over it are not here at all: since #253 they are the {@code jailhub} socket CLI's,
     * whose file permissions are the authorisation.
     */
    private String home() {
        StringBuilder b = new StringBuilder();
        String host = escape(hub.config().hostname());
        b.append("""
            <p><code>%s</code> is a jailscale hub. It publishes a port on your \
            machine over HTTPS without opening an inbound port: the hub relays the bytes and your \
            machine terminates the TLS. <a href="%s">What this is</a>.</p>""".formatted(host, REPO));

        // In the order someone has to do it. The page used to say how to join and stop there, which
        // leaves out both where the binary comes from and what joining was for.
        b.append("<h2>Publish a port</h2>");
        b.append("""
            <p><a href="%s/releases/latest">Download <code>jailscale</code></a> \
            for Linux, Apple-silicon macOS or Windows: one file, no runtime to install \
            underneath it, no root. Intel Macs run <code>jailscale.jar</code> on a JVM.</p>""".formatted(REPO));
        // "latest" is a moving target and this hub is not: it can say which copies it will talk to,
        // and what happens to one it will not, so nobody has to find that out from a failed join.
        // What it must not say is that any recent release will do: the floor is enforced from both
        // ends -- a jailscale has its own minimum hub protocol and refuses a hub below it -- and
        // this page can only speak for this end of it.
        // The second half of the paragraph names the command, because the reader also has to get
        // the same number out of the copy they hold. #140 gave them the command; this names it,
        // because the paragraph is the only place the two numbers meet and it stated one of them
        // (#168). "a current copy", not "your copy": every jailscale released before #140 prints
        // the build alone, and that reader -- holding an existing copy, checking it against this
        // hub's floor -- is this paragraph's whole audience. Telling them their binary does
        // something it does not is the mistake the comment above is about, in the other direction:
        // this page can only speak for its own end.
        b.append("""
            <p>This hub speaks <b>protocol %d</b> and takes %s. One that is too old is turned away \
            at the handshake with a line saying so and which version this hub runs, rather than \
            half-working; a jailscale newer than this hub decides for itself whether it will still \
            talk to it. <code>jailscale version</code> prints the protocol a current copy speaks, \
            beside its build. A copy that prints no protocol is older than the release this hub \
            came from.</p>""".formatted(Message.PROTO, TAKES));
        // The page already says how to check the hub's binary. It said nothing about the file the
        // reader is about to download, which is the one they can actually do something about.
        b.append("""
            <p>The releases are signed. Once you have <code>jailscale</code>, \
            <code>jailscale update --download</code> checks the signature of everything it \
            fetches after that, so this is the one copy you check by hand: the signature is \
            over <code>RELEASE.txt</code>, which names the tag and carries the digest of \
            <code>SHA256SUMS.txt</code>, and your download's hash is in that. \
            <a href="%s/blob/main/docs/release-verification.md">How to check it</a> is one command \
            from a clone, or four by hand. The first copy is the one nothing of ours can vouch for \
            yet; every copy after it is checked against a key this one pinned.</p>""".formatted(REPO));
        {
            // Say what this hub actually accepts rather than assuming a default.
            boolean open = "open".equals(hub.store().setting(Store.SETTING_REGISTRATION, "invite"));
            if (open) {
                // Not a text block with formatted(), which the paragraph above and below both are:
                // the <pre> needs a real newline, and a newline in a format string is
                // VA_FORMAT_STRING_USES_NEWLINE. SpotBugs wants %n there, and %n is the platform's
                // separator -- CRLF on Windows -- which would change the bytes this hub serves
                // depending on where it runs. So the host goes in by append instead.
                b.append("<p>Registration is open, so joining takes effect immediately:</p>")
                    .append("<pre>jailscale up --hub ").append(host).append("\njailscale open 3000</pre>");
            } else {
                b.append("""
                    <p>Joining needs an invitation. Members create them with <code>jailscale invite</code>; \
                    with one in hand:</p><pre>jailscale up --invite &lt;url&gt;
                    jailscale open 3000</pre>""");
            }
            b.append("""
                <p>That serves <code>127.0.0.1:3000</code> at <code>https://&lt;name&gt;.%s</code>, with a \
                certificate your own machine terminates. <code>--name myapp</code> asks for a particular \
                name.</p>""".formatted(host));
        }

        // A public hub is asking people to route their traffic through a stranger's machine. What it
        // can and cannot do with that traffic belongs on its own front page, not only in the docs.
        b.append("<h2>What this hub can see</h2>");
        b.append("""
            <p>Not the traffic. It reads the TLS SNI to pick a node and forwards the rest untouched; the \
            session key belongs to the machine at the other end. It does hold the wildcard private key for \
            <code>*.%s</code> and signs one handshake digest per visitor, so a dishonest hub could point a \
            name at a machine of its own instead. That is what <code>jailscale verify</code> checks from \
            your side, and what the daemon re-checks on its own every half hour.</p>""".formatted(host));

        // Who runs this hub, and what it keeps. Drawn only when the operator has said so: a hub
        // somebody runs for themselves has nobody to name and no terms to point at, and a section
        // that appeared on every hub to say "not configured" would be a worse page for the case
        // that needs it least (#99).
        // Stripped where it is read and not only where it is written (AdminIpc): a value arrives
        // here from the replication stream as well, so a primary running a build without that rule
        // would otherwise have this page draw the section around a blank name -- and, worse, drop
        // the closing warning below on the strength of it.
        String operator = hub.store().setting(Store.SETTING_OPERATOR, "").strip();
        // And checked again here, not only where they are set: these two go into an href, and the
        // store is written by replication as well as by an admin on this host.
        String contact = linkOrNothing(Store.SETTING_CONTACT);
        String terms = linkOrNothing(Store.SETTING_TERMS);
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
            // Not an inventory. Three attempts at one were each found short -- the pending
            // record's address, then the hostname and system, then the invites,
            // raw-port targets and notices -- and a list that has to be complete to be
            // honest is a list that goes stale the next time anything is added to the store. So:
            // the shape of it, the part a visitor is actually asking about, and where it stops.
            b.append("""
                <p>What it keeps is what an operator administers: the nodes and who owns them, the names \
                they hold, the invitations that let them in, and what each machine said \
                about itself when it joined -- its hostname, its system, and the address it knocked from. \
                That stays until the operator removes it. Beside it, thirty days of uptime record and the \
                addresses they have barred.</p>\
                <p><b>Not the visitors.</b> A visit to a link is relayed and not recorded: the hub counts \
                them and keeps no list, and at its default log level it names nodes, not visitors. And what \
                the machine underneath keeps -- the system journal, a proxy in front, a backup of the state \
                directory -- is the operator's and not something this page can answer for.</p>""");
        }

        int online = hub.registry().size();
        int registered = hub.store().nodes().size();
        long rss = Resources.rssBytes();

        // The rows that have a threshold, graded before any of them is written, because the verdict
        // goes above the table and is the worst of them. Everything else on this page is a fact with
        // no good or bad about it -- a version, a key, a memory figure -- and stays ungraded.
        Cert certState = certState();
        Problem cert = certificateProblem(certState);
        // A hub nobody has joined yet is not a hub in trouble; one whose nodes have all gone is.
        Problem nodes = registered > 0 && online == 0
            ? new Problem(Health.WARNING, registered == 1 ? "the one registered node is offline"
                : "none of the " + registered + " registered nodes are online")
            : new Problem(Health.OK, "");
        b.append("<h2>Status</h2>").append(verdict(List.of(cert, nodes))).append("<table>");
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
        b.append("""
            <p><small>The hub key is the one a node pins when it joins, and <code>jailscale status</code> \
            prints the one yours pinned. The binary hash is of the file this process is running: compare it \
            with <code>SHA256SUMS.txt</code> in <a href="%s/releases">the release</a> it claims to be -- \
            checked through <code>RELEASE.txt</code>'s signature the same way as above, since an unchecked \
            checksum list says nothing about which release it belongs to -- and remembering that a container \
            or source build is its own binary. Both are what this hub says about itself, so they tell you an \
            operator is running what they think they are; a dishonest hub prints whatever it likes \
            here.</small></p>""".formatted(REPO));

        // How many, and not which. This page is the one page here a crawler is asked to index
        // (ROBOTS, NOINDEX), and an address on it is text on a page that says it may be listed;
        // the directory that used to list them at /links was a public enumeration of every name on
        // the hub and went with #252. The count is not a name. §6.3 has the argument.
        b.append("<h2>Open links</h2>");
        // count() and not all(): all() copies every live link into a new ArrayList, and this page
        // is served to everyone who visits the hub's own name, for a number the three maps already
        // know. openLinks and not `open`, which in this method already means "registration is open".
        int openLinks = hub.links().count();
        if (openLinks == 0) {
            b.append("<p>None open right now.</p>");
        } else {
            b.append("<p>").append(openLinks).append(openLinks == 1 ? " link is" : " links are")
                .append(" open right now.</p>");
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
            ? """
                <p>The operator can remove a node or bar an address. Who that is, and on what terms, is \
                under <a href="#who">Who runs this hub</a> above.</p>"""
            : """
                <p>The operator can remove a node or bar an address, so treat an open hub you do not run as \
                a place to try this rather than one to depend on.</p>""");

        return b.toString();
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
     * <p>{@code indexable} is true for {@code /} alone. It is false for an invitation, which is
     * served to whoever holds its URL, and for the error pages, which nobody should find by
     * searching; the wildcard's "not open" page says the same meta from {@link SniRouter}.
     * {@link #ROBOTS} explains why those are left fetchable rather than disallowed: this meta is
     * the thing that actually keeps them out of an index, and a crawler has to be allowed to read
     * it.
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
            + "pre{background:var(--wash);padding:.9rem 1rem;overflow-x:auto;border-radius:.5rem;line-height:1.5}"
            + "table{border-collapse:collapse;width:100%;margin:.25rem 0}"
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
        // The way back the nav used to be: the page that says what this host is.
        return HttpResponse.html(status, page(title, "<p>" + says + "</p><p><a href=\"/\">Hub</a></p>", false));
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
