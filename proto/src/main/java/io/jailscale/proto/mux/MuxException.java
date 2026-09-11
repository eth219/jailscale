package io.jailscale.proto.mux;

/** A malformed frame or a protocol violation on the multiplexed channel. */
public final class MuxException extends Exception {

    private static final long serialVersionUID = 1L;

    public MuxException(String message) {
        super(message);
    }

    public MuxException(String message, Throwable cause) {
        super(message, cause);
    }
}
