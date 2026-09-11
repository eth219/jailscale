package io.jailscale.proto.http;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * The minimal HTTP/1.1 the hub serves on its own name and the node speaks to it
 * (ARCHITECTURE.md §5.1). Request line + headers + Content-Length body, and the 101 Upgrade. No
 * chunked encoding, no pipelining, no keep-alive: one request per connection, then either an
 * upgrade or close.
 *
 * <p>Limits: 8 KB request line, 16 KB of headers, 64 headers, bodies capped by the caller.
 */
public final class Http {

    public static final int MAX_LINE = 8 * 1024;
    public static final int MAX_HEADER_BYTES = 16 * 1024;
    public static final int MAX_HEADERS = 64;

    private Http() {}

    // --- server side ------------------------------------------------------------------------

    public static HttpRequest readRequest(InputStream in, int maxBody) throws IOException, HttpException {
        String line = readLine(in, MAX_LINE, 431);
        if (line == null) {
            throw new EOFException("no request");
        }
        String[] parts = line.split(" ");
        if (parts.length != 3 || !parts[2].startsWith("HTTP/1.")) {
            throw new HttpException(400, "bad request line");
        }
        String method = parts[0];
        String target = parts[1];
        if (!target.startsWith("/")) {
            throw new HttpException(400, "bad request target");
        }
        Headers headers = readHeaders(in);
        byte[] body = readBody(in, headers, maxBody);
        return new HttpRequest(method, target, parts[2], headers, body);
    }

    // --- client side ------------------------------------------------------------------------

    /** Writes a request. {@code body} may be null. */
    public static void writeRequest(OutputStream out, String method, String host, String target, Headers headers,
        byte[] body) throws IOException {
        StringBuilder sb = new StringBuilder(256);
        sb.append(method).append(' ').append(target).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(host).append("\r\n");
        boolean hasLen = false;
        if (headers != null) {
            for (String[] h : headers.entries()) {
                sb.append(h[0]).append(": ").append(h[1]).append("\r\n");
                if (h[0].equalsIgnoreCase("Content-Length")) {
                    hasLen = true;
                }
            }
        }
        if (body != null && !hasLen) {
            sb.append("Content-Length: ").append(body.length).append("\r\n");
        }
        sb.append("\r\n");
        out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
        if (body != null && body.length > 0) {
            out.write(body);
        }
        out.flush();
    }

    /** Reads a response; body by Content-Length, chunked, or (if neither and not 101/204) until EOF. */
    public static HttpResponse readResponse(InputStream in, int maxBody) throws IOException, HttpException {
        return readResponse(in, maxBody, false);
    }

    /** {@code headOnly}: the request was HEAD, so the response has headers but no body. */
    public static HttpResponse readResponse(InputStream in, int maxBody, boolean headOnly) throws IOException, HttpException {
        String line = readLine(in, MAX_LINE, 502);
        if (line == null) {
            throw new EOFException("no response");
        }
        if (!line.startsWith("HTTP/1.")) {
            throw new HttpException(502, "bad status line");
        }
        int sp = line.indexOf(' ');
        int status;
        try {
            status = Integer.parseInt(line.substring(sp + 1, sp + 4));
        } catch (RuntimeException e) {
            throw new HttpException(502, "bad status line");
        }
        HttpResponse resp = new HttpResponse(status);
        Headers headers = readHeaders(in);
        for (String[] h : headers.entries()) {
            resp.header(h[0], h[1]);
        }
        if (status == 101 || status == 204 || status == 304 || headOnly) {
            return resp;
        }
        String te = headers.get("Transfer-Encoding");
        if (te != null && te.toLowerCase(Locale.ROOT).contains("chunked")) {
            resp.body(readChunked(in, maxBody));
        } else if (headers.contains("Content-Length")) {
            resp.body(readBody(in, headers, maxBody));
        } else {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] tmp = new byte[4096];
            int n;
            while ((n = in.read(tmp)) > 0) {
                if (buf.size() + n > maxBody) {
                    throw new HttpException(502, "response too large");
                }
                buf.write(tmp, 0, n);
            }
            resp.body(buf.toByteArray());
        }
        return resp;
    }

    /** Responses only (RFC 9112 §7.1): chunk-size [;ext] CRLF data CRLF ... 0 CRLF trailers CRLF. */
    static byte[] readChunked(InputStream in, int maxBody) throws IOException, HttpException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        while (true) {
            String line = readLine(in, MAX_LINE, 502);
            if (line == null) {
                throw new EOFException("truncated chunked body");
            }
            int semi = line.indexOf(';');
            String hex = (semi >= 0 ? line.substring(0, semi) : line).trim();
            int size;
            try {
                size = Integer.parseInt(hex, 16);
            } catch (NumberFormatException e) {
                throw new HttpException(502, "bad chunk size");
            }
            if (size < 0 || buf.size() + size > maxBody) {
                throw new HttpException(502, "response too large");
            }
            if (size == 0) {
                while (true) { // trailers up to the empty line
                    String t = readLine(in, MAX_LINE, 502);
                    if (t == null || t.isEmpty()) {
                        break;
                    }
                }
                return buf.toByteArray();
            }
            byte[] chunk = new byte[size];
            int off = 0;
            while (off < size) {
                int n = in.read(chunk, off, size - off);
                if (n < 0) {
                    throw new EOFException("truncated chunk");
                }
                off += n;
            }
            buf.write(chunk, 0, size);
            String crlf = readLine(in, 2, 502);
            if (crlf == null || !crlf.isEmpty()) {
                throw new HttpException(502, "bad chunk terminator");
            }
        }
    }

    // --- shared -----------------------------------------------------------------------------

    static Headers readHeaders(InputStream in) throws IOException, HttpException {
        Headers headers = new Headers();
        int total = 0;
        while (true) {
            String line = readLine(in, MAX_LINE, 431);
            if (line == null) {
                throw new EOFException("truncated headers");
            }
            if (line.isEmpty()) {
                return headers;
            }
            total += line.length() + 2;
            if (total > MAX_HEADER_BYTES || headers.size() >= MAX_HEADERS) {
                throw new HttpException(431, "headers too large");
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                throw new HttpException(400, "bad header line");
            }
            String name = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            if (name.isEmpty() || hasCtl(name)) {
                throw new HttpException(400, "bad header name");
            }
            headers.add(name, value);
        }
    }

    static byte[] readBody(InputStream in, Headers headers, int maxBody) throws IOException, HttpException {
        String te = headers.get("Transfer-Encoding");
        if (te != null && !te.toLowerCase(Locale.ROOT).equals("identity")) {
            throw new HttpException(411, "chunked bodies not supported");
        }
        String cl = headers.get("Content-Length");
        if (cl == null) {
            return new byte[0];
        }
        long len;
        try {
            len = Long.parseLong(cl.trim());
        } catch (NumberFormatException e) {
            throw new HttpException(400, "bad Content-Length");
        }
        if (len < 0) {
            throw new HttpException(400, "bad Content-Length");
        }
        if (len > maxBody) {
            throw new HttpException(413, "body too large");
        }
        byte[] body = new byte[(int) len];
        int off = 0;
        while (off < body.length) {
            int n = in.read(body, off, body.length - off);
            if (n < 0) {
                throw new EOFException("truncated body");
            }
            off += n;
        }
        return body;
    }

    /** Reads one CRLF (or bare LF) terminated line as ISO-8859-1. Returns null at EOF before any byte. */
    static String readLine(InputStream in, int max, int overflowStatus) throws IOException, HttpException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(128);
        int c;
        boolean any = false;
        while ((c = in.read()) >= 0) {
            any = true;
            if (c == '\n') {
                break;
            }
            if (c != '\r') {
                if (buf.size() >= max) {
                    throw new HttpException(overflowStatus, "line too long");
                }
                buf.write(c);
            }
        }
        if (!any) {
            return null;
        }
        return buf.toString(StandardCharsets.ISO_8859_1);
    }

    private static boolean hasCtl(String s) {
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch < 0x21 || ch > 0x7e) {
                return true;
            }
        }
        return false;
    }
}
