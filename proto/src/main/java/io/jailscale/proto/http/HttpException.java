package io.jailscale.proto.http;

/** A malformed or over-limit HTTP message. {@link #status()} is the response to send if any. */
public final class HttpException extends Exception {

    private static final long serialVersionUID = 1L;

    private final int status;
    private final String method;

    public HttpException(int status, String message) {
        this(status, message, null);
    }

    /**
     * {@code method} is the request method, when the request line had already been parsed when this
     * was thrown. The error response is still a response to that method, so a server that answers a
     * rejected HEAD has to know not to write a body (RFC 9110 §9.3.2); without this the method is
     * lost with the request that was never built.
     */
    public HttpException(int status, String message, String method) {
        super(message);
        this.status = status;
        this.method = method;
    }

    public int status() {
        return status;
    }

    /** The method of the request that failed, or null if it was not read before the failure. */
    public String method() {
        return method;
    }

    /**
     * Whether the request this answers was a HEAD -- false when the method was never read, which
     * is the only answer available then. {@link HttpRequest#isHead()} for a request that parsed.
     */
    public boolean isHead() {
        return "HEAD".equals(method);
    }
}
