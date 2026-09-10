package io.jailscale.crypto;

/** A Noise handshake or transport message was rejected: bad tag, wrong length, wrong state. */
public final class NoiseException extends Exception {

    private static final long serialVersionUID = 1L;

    public NoiseException(String message) {
        super(message);
    }

    public NoiseException(String message, Throwable cause) {
        super(message, cause);
    }
}
