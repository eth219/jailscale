package io.jailscale.proto.http;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** An HTTP/1.1 response to write, or one that was read from a server. */
public final class HttpResponse {

    private final int status;
    private final Headers headers = new Headers();
    private byte[] body = new byte[0];

    public HttpResponse(int status) {
        this.status = status;
    }

    public static HttpResponse ok() {
        return new HttpResponse(200);
    }

    public static HttpResponse text(int status, String text) {
        return new HttpResponse(status).header("Content-Type", "text/plain; charset=utf-8").body(text);
    }

    public static HttpResponse html(int status, String html) {
        return new HttpResponse(status).header("Content-Type", "text/html; charset=utf-8").body(html);
    }

    public static HttpResponse json(int status, String json) {
        return new HttpResponse(status).header("Content-Type", "application/json").body(json);
    }

    public static HttpResponse redirect(String location) {
        return new HttpResponse(302).header("Location", location);
    }

    /** The 101 that hands the connection over to another protocol. */
    public static HttpResponse upgrade(String protocol) {
        return new HttpResponse(101).header("Connection", "Upgrade").header("Upgrade", protocol);
    }

    public int status() {
        return status;
    }

    public Headers headers() {
        return headers;
    }

    public byte[] body() {
        return body;
    }

    public String bodyText() {
        return new String(body, StandardCharsets.UTF_8);
    }

    public HttpResponse header(String name, String value) {
        headers.add(name, value);
        return this;
    }

    public HttpResponse body(byte[] bytes) {
        this.body = bytes;
        return this;
    }

    public HttpResponse body(String text) {
        return body(text.getBytes(StandardCharsets.UTF_8));
    }

    /** Writes status line, headers and body. Adds Content-Length unless this is a 101. */
    public void writeTo(OutputStream out) throws IOException {
        StringBuilder sb = new StringBuilder(256);
        sb.append("HTTP/1.1 ").append(status).append(' ').append(reason(status)).append("\r\n");
        if (status != 101 && !headers.contains("Content-Length")) {
            headers.add("Content-Length", Integer.toString(body.length));
        }
        if (!headers.contains("Connection") && status != 101) {
            headers.add("Connection", "close");
        }
        for (String[] h : headers.entries()) {
            sb.append(h[0]).append(": ").append(h[1]).append("\r\n");
        }
        sb.append("\r\n");
        out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
        if (status != 101 && body.length > 0) {
            out.write(body);
        }
        out.flush();
    }

    static String reason(int status) {
        return switch (status) {
            case 101 -> "Switching Protocols";
            case 200 -> "OK";
            case 204 -> "No Content";
            case 302 -> "Found";
            case 400 -> "Bad Request";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 408 -> "Request Timeout";
            case 411 -> "Length Required";
            case 413 -> "Payload Too Large";
            case 426 -> "Upgrade Required";
            case 429 -> "Too Many Requests";
            case 431 -> "Request Header Fields Too Large";
            case 500 -> "Internal Server Error";
            case 502 -> "Bad Gateway";
            case 503 -> "Service Unavailable";
            default -> "Status";
        };
    }
}
