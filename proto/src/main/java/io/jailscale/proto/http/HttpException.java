package io.jailscale.proto.http;

/** A malformed or over-limit HTTP message. {@link #status()} is the response to send if any. */
public final class HttpException extends Exception {

    private static final long serialVersionUID = 1L;

    private final int status;

    public HttpException(int status, String message) {
        super(message);
        this.status = status;
    }

    public int status() {
        return status;
    }
}
