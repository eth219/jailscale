package io.jailscale.proto.http;

import io.jailscale.proto.tls.Tls;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.security.GeneralSecurityException;
import javax.net.ssl.SSLContext;

/**
 * One-request HTTP/1.1 client over the same request/response code the hub and node already
 * carry (DESIGN.md §6.1): http or https (platform roots), no redirects, no keep-alive. Used for
 * ACME so neither binary needs {@code java.net.http}.
 */
public final class HttpCall {

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
        String scheme = url.getScheme() == null ? "http" : url.getScheme().toLowerCase(java.util.Locale.ROOT);
        String host = url.getHost();
        if (host == null) {
            throw new IOException("bad URL " + url);
        }
        boolean tls = scheme.equals("https");
        int port = url.getPort() > 0 ? url.getPort() : tls ? 443 : 80;
        String target = (url.getRawPath() == null || url.getRawPath().isEmpty() ? "/" : url.getRawPath())
            + (url.getRawQuery() != null ? "?" + url.getRawQuery() : "");
        String hostHeader = url.getPort() > 0 && url.getPort() != (tls ? 443 : 80) ? host + ":" + url.getPort() : host;
        Socket s;
        if (tls) {
            s = Tls.connect(systemContext(), host, port, true, timeoutMs);
        } else {
            s = new Socket();
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
        }
        try (s) {
            Http.writeRequest(s.getOutputStream(), method, hostHeader, target, headers == null ? new Headers() : headers, body);
            return Http.readResponse(s.getInputStream(), maxBody, method.equals("HEAD"));
        }
    }
}
