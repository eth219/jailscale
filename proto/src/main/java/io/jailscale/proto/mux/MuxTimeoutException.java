package io.jailscale.proto.mux;

import java.io.IOException;

/**
 * A read on a {@link MuxStream} that passed the deadline set with {@link MuxStream#readDeadline}.
 *
 * <p>An {@link IOException}, unlike {@link MuxException}, because it surfaces out of
 * {@code in().read()} and the callers of that are relays which already treat an
 * {@code IOException} as "this visitor is over". A type of its own so the one caller that wants to
 * say something more useful than that -- the node, which knows the deadline was a visitor's
 * handshake (ARCHITECTURE.md §9.3) -- can tell it apart from the peer hanging up.
 */
public final class MuxTimeoutException extends IOException {

    private static final long serialVersionUID = 1L;

    MuxTimeoutException(String message) {
        super(message);
    }
}
