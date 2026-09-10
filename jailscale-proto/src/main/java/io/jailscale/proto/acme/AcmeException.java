package io.jailscale.proto.acme;

/** An ACME problem document (RFC 7807) or a transport failure talking to the CA. */
public final class AcmeException extends Exception {

    private static final long serialVersionUID = 1L;

    private final String type;
    private final int status;

    public AcmeException(String type, int status, String detail) {
        super(detail == null ? type : detail + " (" + type + ")");
        this.type = type == null ? "" : type;
        this.status = status;
    }

    public AcmeException(String message, Throwable cause) {
        super(message, cause);
        this.type = "";
        this.status = 0;
    }

    /** The urn:ietf:params:acme:error:* type, or empty. */
    public String type() {
        return type;
    }

    public int status() {
        return status;
    }

    public boolean isBadNonce() {
        return type.endsWith(":badNonce");
    }
}
