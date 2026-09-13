package io.jailscale.proto.mux;

/**
 * One multiplexer frame (ARCHITECTURE.md §5.3): {@code [4B streamId][1B type][1B flags][2B len][payload]}.
 * Exactly one frame travels inside one Noise transport message.
 */
public record Frame(long streamId, int type, int flags, byte[] payload) {

    public static final int HEADER_LEN = 8;
    /** DATA payload cap so that no stream monopolises the channel. */
    public static final int MAX_DATA = 16 * 1024;
    /** Any frame must fit a Noise message with its tag: 65535 - 16 - header. */
    public static final int MAX_PAYLOAD = 65535 - 16 - HEADER_LEN;

    public static final int OPEN = 1;
    public static final int DATA = 2;
    public static final int WINDOW = 3;
    public static final int CLOSE = 4;
    public static final int RST = 5;
    public static final int CTRL = 6;
    public static final int KEEPALIVE = 7;

    /** Flag: DATA frames on this stream are datagrams (one frame = one UDP packet). */
    public static final int FLAG_DGRAM = 0x01;

    // RST reasons the multiplexer sends for itself, above the range an application picks from. The
    // byte is diagnostic only -- a peer fails the stream whatever it says -- and the low numbers are
    // each end's own local vocabulary: the hub's 1 and the node's 1 already mean different things,
    // so naming those here would claim a shared namespace that does not exist. These two do belong
    // to the protocol, because no caller chooses them.
    /** Reclaimed: this stream held receive bytes the process could not afford (§5.3). */
    public static final int RST_NO_BUDGET = 100;
    /** The peer sent past the window it had been granted on this stream. */
    public static final int RST_WINDOW_OVERRUN = 101;

    public static final long CONTROL_STREAM = 0;

    public Frame {
        if (streamId < 0 || streamId > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("streamId out of range");
        }
        // A type this build has no case for is still a well-formed frame (ARCHITECTURE.md §5.4):
        // it must fit the one byte the header gives it, and whether it means anything is the
        // dispatcher's business. Rejecting it here would make every frame type a newer peer adds a
        // flag day, because the rejection happens in Frame.decode, before anyone can skip it.
        if (type < OPEN || type > 0xFF) {
            throw new IllegalArgumentException("frame type out of range: " + type);
        }
        if (flags < 0 || flags > 0xFF) {
            throw new IllegalArgumentException("flags out of range");
        }
        if (payload == null) {
            payload = new byte[0];
        }
        if (payload.length > MAX_PAYLOAD) {
            throw new IllegalArgumentException("payload too large: " + payload.length);
        }
        if (type == DATA && payload.length > MAX_DATA) {
            throw new IllegalArgumentException("DATA payload exceeds " + MAX_DATA);
        }
    }

    public static Frame ctrl(byte[] json) {
        return new Frame(CONTROL_STREAM, CTRL, 0, json);
    }

    public static Frame keepalive() {
        return new Frame(CONTROL_STREAM, KEEPALIVE, 0, null);
    }

    public static Frame data(long streamId, byte[] bytes) {
        return new Frame(streamId, DATA, 0, bytes);
    }

    public static Frame close(long streamId) {
        return new Frame(streamId, CLOSE, 0, null);
    }

    public static Frame rst(long streamId, int reason) {
        return new Frame(streamId, RST, 0, new byte[] {(byte) reason});
    }

    public static Frame window(long streamId, int delta) {
        if (delta <= 0) {
            throw new IllegalArgumentException("window delta must be positive");
        }
        return new Frame(streamId, WINDOW, 0, new byte[] {
            (byte) (delta >>> 24), (byte) (delta >>> 16), (byte) (delta >>> 8), (byte) delta});
    }

    /** Delta carried by a WINDOW frame. */
    public int windowDelta() {
        if (type != WINDOW || payload.length != 4) {
            throw new IllegalStateException("not a WINDOW frame");
        }
        return ((payload[0] & 0xff) << 24) | ((payload[1] & 0xff) << 16)
            | ((payload[2] & 0xff) << 8) | (payload[3] & 0xff);
    }

    public byte[] encode() {
        byte[] out = new byte[HEADER_LEN + payload.length];
        out[0] = (byte) (streamId >>> 24);
        out[1] = (byte) (streamId >>> 16);
        out[2] = (byte) (streamId >>> 8);
        out[3] = (byte) streamId;
        out[4] = (byte) type;
        out[5] = (byte) flags;
        out[6] = (byte) (payload.length >>> 8);
        out[7] = (byte) payload.length;
        System.arraycopy(payload, 0, out, HEADER_LEN, payload.length);
        return out;
    }

    public static Frame decode(byte[] buf) throws MuxException {
        return decode(buf, 0, buf.length);
    }

    public static Frame decode(byte[] buf, int off, int len) throws MuxException {
        if (len < HEADER_LEN) {
            throw new MuxException("frame shorter than header");
        }
        long streamId = ((long) (buf[off] & 0xff) << 24) | ((buf[off + 1] & 0xff) << 16)
            | ((buf[off + 2] & 0xff) << 8) | (buf[off + 3] & 0xff);
        int type = buf[off + 4] & 0xff;
        int flags = buf[off + 5] & 0xff;
        int plen = ((buf[off + 6] & 0xff) << 8) | (buf[off + 7] & 0xff);
        if (plen != len - HEADER_LEN) {
            throw new MuxException("frame length mismatch: header says " + plen + ", got " + (len - HEADER_LEN));
        }
        byte[] payload = new byte[plen];
        System.arraycopy(buf, off + HEADER_LEN, payload, 0, plen);
        try {
            return new Frame(streamId, type, flags, payload);
        } catch (IllegalArgumentException e) {
            throw new MuxException(e.getMessage());
        }
    }

    @Override
    public String toString() {
        return "Frame[stream=" + streamId + " type=" + typeName(type) + " flags=" + flags + " len=" + payload.length + "]";
    }

    public static String typeName(int type) {
        return switch (type) {
            case OPEN -> "OPEN";
            case DATA -> "DATA";
            case WINDOW -> "WINDOW";
            case CLOSE -> "CLOSE";
            case RST -> "RST";
            case CTRL -> "CTRL";
            case KEEPALIVE -> "KEEPALIVE";
            default -> "?" + type;
        };
    }
}
