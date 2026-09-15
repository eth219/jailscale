package io.jailscale.proto.http;

import io.jailscale.proto.tls.Tls;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.util.Locale;
import javax.net.ssl.SSLContext;

/**
 * One-request HTTP/1.1 client over the same request/response code the hub and node already
 * carry (ARCHITECTURE.md §5.1): http or https (platform roots), no keep-alive. Used for ACME so
 * neither binary needs {@code java.net.http}, and for release downloads (§9.4), which is the one
 * caller that follows a redirect and the one that streams rather than buffers.
 */
public final class HttpCall {

    /**
     * GitHub makes one hop from a release asset to the object store; a few more are allowed so a
     * CDN in front of it does not break the download, and a loop is cut off soon after.
     */
    public static final int MAX_REDIRECTS = 5;

    private static volatile SSLContext system;

    private HttpCall() {}

    private static SSLContext systemContext() throws IOException {
        SSLContext c = system;
        if (c == null) {
            try {
                c = Tls.clientContext(null, false);
            } catch (GeneralSecurityException e) {
                throw new IOException("TLS: " + e.getMessage(), e);
            }
            system = c;
        }
        return c;
    }

    /** Sends {@code method url} with the given headers and body; returns the full response. */
    public static HttpResponse send(String method, URI url, Headers headers, byte[] body, int timeoutMs, int maxBody)
        throws IOException, HttpException {
        try (Socket s = connect(url, timeoutMs)) {
            Http.writeRequest(s.getOutputStream(), method, hostHeader(url), target(url),
                headers == null ? new Headers() : headers, body);
            return Http.readResponse(s.getInputStream(), maxBody, method.equals("HEAD"));
        }
    }

    /**
     * GETs {@code url}, following redirects, and writes the body to {@code out} without holding it
     * in memory. Returns how many bytes it wrote. A status that is neither 200 nor a redirect is an
     * {@link HttpException} carrying it; a redirect chain longer than {@link #MAX_REDIRECTS} is an
     * {@code IOException}.
     *
     * <p>{@code out} is written to only for the 200: a redirect's own body is never read -- the
     * connection is closed under it, there being no keep-alive to preserve -- so a caller that
     * passes a file has nothing in it until the real response arrives.
     */
    public static long get(URI url, Headers headers, OutputStream out, int timeoutMs, long maxBody)
        throws IOException, HttpException {
        URI at = url;
        for (int hop = 0; ; hop++) {
            try (Socket s = connect(at, timeoutMs)) {
                Http.writeRequest(s.getOutputStream(), "GET", hostHeader(at), target(at),
                    headers == null ? new Headers() : headers, null);
                InputStream in = s.getInputStream();
                HttpResponse head = Http.readResponseHead(in);
                if (!isRedirect(head.status())) {
                    if (head.status() != 200) {
                        // An HttpException rather than an IOException: a caller that treats 404
                        // ("this release has nothing signed") differently from 503 ("try again")
                        // should not have to read the status back out of a sentence.
                        throw new HttpException(head.status(), at.getHost() + " answered HTTP " + head.status());
                    }
                    return Http.copyBody(in, head.headers(), out, maxBody);
                }
                if (hop >= MAX_REDIRECTS) {
                    throw new IOException("more than " + MAX_REDIRECTS + " redirects from " + url);
                }
                at = redirect(at, head.headers().get("Location"));
            }
        }
    }

    static boolean isRedirect(int status) {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    /**
     * Where a {@code Location} points, resolved against the response it came with.
     *
     * <p><b>A redirect may not leave TLS.</b> Everything here that follows one starts at an https
     * URL compiled into the binary, and a server that answers "same thing, over http" is asking for
     * the rest of the exchange in the clear; the host is allowed to change, because a release asset
     * really is served from an object store on another name, but the scheme is not. Public so the
     * rule can be held against a table of cases rather than only against a live server.
     */
    public static URI redirect(URI from, String location) throws IOException {
        if (location == null || location.isBlank()) {
            throw new IOException("a redirect from " + from.getHost() + " named no Location");
        }
        URI next;
        try {
            next = from.resolve(new URI(location.trim()));
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw new IOException("a redirect from " + from.getHost() + " named " + location);
        }
        String scheme = next.getScheme() == null ? "" : next.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new IOException("a redirect to " + scheme + " is not something this follows");
        }
        if (scheme.equals("http") && "https".equalsIgnoreCase(from.getScheme())) {
            throw new IOException("a redirect from https to http (" + next + ") is a downgrade");
        }
        if (next.getHost() == null) {
            throw new IOException("a redirect to " + next + " names no host");
        }
        return next;
    }

    private static Socket connect(URI url, int timeoutMs) throws IOException {
        String scheme = url.getScheme() == null ? "http" : url.getScheme().toLowerCase(Locale.ROOT);
        String host = url.getHost();
        if (host == null) {
            throw new IOException("bad URL " + url);
        }
        boolean tls = scheme.equals("https");
        int port = url.getPort() > 0 ? url.getPort() : tls ? 443 : 80;
        if (tls) {
            return Tls.connect(systemContext(), host, port, true, timeoutMs);
        }
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
        } catch (IOException e) {
            s.close();
            throw e;
        }
        return s;
    }

    private static String target(URI url) {
        return (url.getRawPath() == null || url.getRawPath().isEmpty() ? "/" : url.getRawPath())
            + (url.getRawQuery() != null ? "?" + url.getRawQuery() : "");
    }

    private static String hostHeader(URI url) {
        boolean tls = "https".equalsIgnoreCase(url.getScheme());
        return url.getPort() > 0 && url.getPort() != (tls ? 443 : 80)
            ? url.getHost() + ":" + url.getPort() : url.getHost();
    }
}
