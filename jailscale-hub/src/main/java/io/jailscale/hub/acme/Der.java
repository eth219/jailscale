package io.jailscale.hub.acme;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * The minimal DER writer DESIGN.md §6.3 budgets: enough to build a PKCS#10 request. Every method
 * returns a complete TLV.
 */
public final class Der {

    private Der() {}

    public static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + 6);
        out.write(tag);
        int len = content.length;
        if (len < 0x80) {
            out.write(len);
        } else {
            int n = len > 0xFFFF ? 3 : len > 0xFF ? 2 : 1;
            out.write(0x80 | n);
            for (int i = n - 1; i >= 0; i--) {
                out.write((len >>> (8 * i)) & 0xff);
            }
        }
        out.writeBytes(content);
        return out.toByteArray();
    }

    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    public static byte[] sequence(byte[]... items) {
        return tlv(0x30, concat(items));
    }

    public static byte[] set(byte[]... items) {
        return tlv(0x31, concat(items));
    }

    public static byte[] integer(long v) {
        return integer(BigInteger.valueOf(v));
    }

    public static byte[] integer(BigInteger v) {
        return tlv(0x02, v.toByteArray()); // two's complement, minimal, as DER wants
    }

    public static byte[] nul() {
        return new byte[] {0x05, 0x00};
    }

    public static byte[] bool(boolean b) {
        return new byte[] {0x01, 0x01, (byte) (b ? 0xff : 0x00)};
    }

    public static byte[] octetString(byte[] b) {
        return tlv(0x04, b);
    }

    /** BIT STRING with zero unused bits. */
    public static byte[] bitString(byte[] b) {
        return tlv(0x03, concat(new byte[] {0}, b));
    }

    public static byte[] utf8(String s) {
        return tlv(0x0c, s.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] ia5(String s) {
        return tlv(0x16, s.getBytes(StandardCharsets.US_ASCII));
    }

    public static byte[] printable(String s) {
        return tlv(0x13, s.getBytes(StandardCharsets.US_ASCII));
    }

    /** Context-specific tag: constructed [n] or implicit primitive [n]. */
    public static byte[] context(int n, boolean constructed, byte[] content) {
        return tlv(0x80 | (constructed ? 0x20 : 0) | n, content);
    }

    /** OBJECT IDENTIFIER from dotted form. */
    public static byte[] oid(String dotted) {
        String[] parts = dotted.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int first = Integer.parseInt(parts[0]) * 40 + Integer.parseInt(parts[1]);
        writeBase128(out, first);
        for (int i = 2; i < parts.length; i++) {
            writeBase128(out, Long.parseLong(parts[i]));
        }
        return tlv(0x06, out.toByteArray());
    }

    private static void writeBase128(ByteArrayOutputStream out, long v) {
        byte[] tmp = new byte[10];
        int n = 0;
        do {
            tmp[n++] = (byte) (v & 0x7f);
            v >>>= 7;
        } while (v != 0);
        for (int i = n - 1; i >= 0; i--) {
            out.write(tmp[i] | (i > 0 ? 0x80 : 0));
        }
    }
}
