package io.jailscale.proto.json;

/** Malformed JSON, or a field that is missing or has the wrong type. */
public final class JsonException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public JsonException(String message) {
        super(message);
    }
}
