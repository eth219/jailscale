package io.jailscale.proto.tls;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.KeyAgreement;

/**
 * The little of TLS 1.3 (RFC 8446) that hub-side signing needs to see (ARCHITECTURE.md §9.2): the
 * handshake messages a server's {@code CertificateVerify} transcript is made of, and the wire
 * encodings of the ones the node has to reconstruct because JSSE does not show them to it.
 *
 * <p>Both ends use this. The node rebuilds ServerHello, EncryptedExtensions and Certificate and
 * checks its own reconstruction against the hash JSSE asked it to sign; the hub rebuilds the
 * transcript from the ClientHello it delivered plus what the node sent, and signs only when the
 * hash comes out the same. That is what ties a signature to one visitor's handshake.
 */
public final class Tls13 {

    /** Handshake message types this touches. */
    public static final int CLIENT_HELLO = 1;
    public static final int SERVER_HELLO = 2;
    public static final int ENCRYPTED_EXTENSIONS = 8;
    public static final int CERTIFICATE = 11;
    public static final int MESSAGE_HASH = 254;

    /** Extension types. */
    public static final int EXT_SUPPORTED_GROUPS = 10;
    public static final int EXT_ALPN = 16;
    public static final int EXT_SUPPORTED_VERSIONS = 43;
    public static final int EXT_KEY_SHARE = 51;

    public static final int GROUP_X25519 = 0x001d;

    /** The 98 bytes every server CertificateVerify signature begins with (RFC 8446 §4.4.3). */
    public static final byte[] CERT_VERIFY_CONTEXT = certVerifyContext();

    /** The fixed ServerHello.random that marks a HelloRetryRequest (RFC 8446 §4.1.3). */
    private static final byte[] HRR_RANDOM = java.util.HexFormat.of()
        .parseHex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c");

    private static final int RECORD_HANDSHAKE = 22;
    private static final int RECORD_APPLICATION_DATA = 23;
    /** More than any ClientHello pair; a tap that reaches it stops collecting. */
    private static final int MAX_TAP_BYTES = 64 * 1024;

    private Tls13() {}

    private static byte[] certVerifyContext() {
        byte[] label = "TLS 1.3, server CertificateVerify".getBytes(StandardCharsets.US_ASCII);
        byte[] c = new byte[64 + label.length + 1];
        Arrays.fill(c, 0, 64, (byte) 0x20);
        System.arraycopy(label, 0, c, 64, label.length);
        return c;
    }

    /**
     * The hash a CertificateVerify content ends in: {@code SHA-256} for a 32-byte tail,
     * {@code SHA-384} for 48, null when the content is not a server CertificateVerify at all.
     */
    public static String hashAlgorithmOf(byte[] content) {
        int tail = content.length - CERT_VERIFY_CONTEXT.length;
        if (tail != 32 && tail != 48
            || !Arrays.equals(content, 0, CERT_VERIFY_CONTEXT.length, CERT_VERIFY_CONTEXT, 0, CERT_VERIFY_CONTEXT.length)) {
            return null;
        }
        return tail == 32 ? "SHA-256" : "SHA-384";
    }

    /** The transcript hash inside a CertificateVerify content. */
    public static byte[] transcriptHashIn(byte[] content) {
        return Arrays.copyOfRange(content, CERT_VERIFY_CONTEXT.length, content.length);
    }

    // --- the transcript -----------------------------------------------------------------------

    /**
     * {@code Hash(ClientHello || ServerHello || EncryptedExtensions || Certificate)}, or with a
     * HelloRetryRequest in between, {@code Hash(message_hash(ClientHello1) || HelloRetryRequest ||
     * ClientHello2 || ServerHello || ...)} (RFC 8446 §4.4.1). {@code clientHellos} is what the
     * visitor sent, in order; {@code hrr} is null unless the server sent one.
     *
     * @throws IllegalArgumentException when the pieces do not fit together: a HelloRetryRequest
     *     without a second ClientHello or the other way round, or a message of the wrong type
     */
    public static byte[] transcriptHash(String hashAlg, List<byte[]> clientHellos, byte[] hrr, byte[] serverHello,
        byte[] encryptedExtensions, byte[] certificate) throws GeneralSecurityException {
        expect(serverHello, SERVER_HELLO, "ServerHello");
        expect(encryptedExtensions, ENCRYPTED_EXTENSIONS, "EncryptedExtensions");
        expect(certificate, CERTIFICATE, "Certificate");
        if (isHelloRetryRequest(serverHello)) {
            throw new IllegalArgumentException("ServerHello is a HelloRetryRequest");
        }
        MessageDigest md = MessageDigest.getInstance(hashAlg);
        if (hrr == null) {
            if (clientHellos.size() != 1) {
                throw new IllegalArgumentException(clientHellos.size() + " ClientHellos but no HelloRetryRequest");
            }
            expect(clientHellos.get(0), CLIENT_HELLO, "ClientHello");
            md.update(clientHellos.get(0));
        } else {
            if (!isHelloRetryRequest(hrr)) {
                throw new IllegalArgumentException("not a HelloRetryRequest");
            }
            if (clientHellos.size() != 2) {
                throw new IllegalArgumentException(clientHellos.size() + " ClientHellos with a HelloRetryRequest");
            }
            expect(clientHellos.get(0), CLIENT_HELLO, "ClientHello");
            expect(clientHellos.get(1), CLIENT_HELLO, "ClientHello");
            md.update(message(MESSAGE_HASH, MessageDigest.getInstance(hashAlg).digest(clientHellos.get(0))));
            md.update(hrr);
            md.update(clientHellos.get(1));
        }
        md.update(serverHello);
        md.update(encryptedExtensions);
        md.update(certificate);
        return md.digest();
    }

    private static void expect(byte[] m, int type, String what) {
        if (m == null || m.length < 4 || (m[0] & 0xff) != type || length24(m, 1) != m.length - 4) {
            throw new IllegalArgumentException("not a " + what);
        }
    }

    public static boolean isHelloRetryRequest(byte[] serverHello) {
        return serverHello != null && serverHello.length >= 38 && (serverHello[0] & 0xff) == SERVER_HELLO
            && Arrays.equals(serverHello, 6, 38, HRR_RANDOM, 0, 32);
    }

    // --- taking handshake messages off the wire -----------------------------------------------

    /**
     * Collects the plaintext handshake messages at the start of one direction of a TLS 1.3
     * connection: everything in handshake records before the first application-data record. On
     * the visitor's side that is the ClientHello (two of them after a HelloRetryRequest); on the
     * server's side the ServerHello or HelloRetryRequest. Change-cipher-spec records are skipped,
     * and a record may split a message or carry several.
     */
    public static final class Tap {
        private final ByteArrayOutputStream handshake = new ByteArrayOutputStream(600);
        private final ByteArrayOutputStream pending = new ByteArrayOutputStream(0);
        private boolean done;
        private int seen;

        public synchronized void accept(byte[] b, int off, int len) {
            if (done) {
                return;
            }
            seen += len;
            if (seen > MAX_TAP_BYTES) {
                done = true;
                return;
            }
            pending.write(b, off, len);
            byte[] buf = pending.toByteArray();
            int i = 0;
            while (i + 5 <= buf.length) {
                int type = buf[i] & 0xff;
                int rl = ((buf[i + 3] & 0xff) << 8) | (buf[i + 4] & 0xff);
                if (type == RECORD_APPLICATION_DATA) {
                    done = true;
                    break;
                }
                if (i + 5 + rl > buf.length) {
                    break; // wait for the rest of this record
                }
                if (type == RECORD_HANDSHAKE) {
                    handshake.write(buf, i + 5, rl);
                }
                i += 5 + rl;
            }
            pending.reset();
            if (!done && i < buf.length) {
                pending.write(buf, i, buf.length - i);
            }
        }

        public void accept(byte[] b) {
            accept(b, 0, b.length);
        }

        /** Whether the plaintext part of the handshake has ended (an application-data record was seen). */
        public synchronized boolean done() {
            return done;
        }

        /** The complete handshake messages collected so far. */
        public synchronized List<byte[]> messages() {
            return Tls13.messages(handshake.toByteArray());
        }
    }

    /** Splits concatenated handshake messages; a trailing partial message is dropped. */
    public static List<byte[]> messages(byte[] hs) {
        List<byte[]> l = new ArrayList<>(2);
        int i = 0;
        while (i + 4 <= hs.length) {
            int len = length24(hs, i + 1);
            if (i + 4 + len > hs.length) {
                break;
            }
            l.add(Arrays.copyOfRange(hs, i, i + 4 + len));
            i += 4 + len;
        }
        return l;
    }

    // --- what the node reconstructs -----------------------------------------------------------

    /** The TLS 1.3 Certificate message for a chain: empty request context, no per-certificate extensions. */
    public static byte[] certificateMessage(List<X509Certificate> chain) throws CertificateEncodingException {
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        for (X509Certificate c : chain) {
            byte[] der = c.getEncoded();
            list.write(u24(der.length), 0, 3);
            list.write(der, 0, der.length);
            list.write(0);
            list.write(0);
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0);
        body.write(u24(list.size()), 0, 3);
        write(body, list.toByteArray());
        return message(CERTIFICATE, body.toByteArray());
    }

    /**
     * EncryptedExtensions as JSSE writes it for a server configured with {@code groups} and one ALPN
     * protocol: {@code supported_groups} (the server's whole list) when the client sent that
     * extension, then {@code application_layer_protocol_negotiation} when the client offered
     * {@code alpn}. Nothing else, SNI acknowledgement included.
     */
    public static byte[] encryptedExtensions(boolean clientSentGroups, int[] groups, String alpn, boolean clientOfferedAlpn) {
        ByteArrayOutputStream exts = new ByteArrayOutputStream();
        if (clientSentGroups) {
            ByteArrayOutputStream g = new ByteArrayOutputStream();
            g.write(u16(groups.length * 2), 0, 2);
            for (int id : groups) {
                g.write(u16(id), 0, 2);
            }
            write(exts, extension(EXT_SUPPORTED_GROUPS, g.toByteArray()));
        }
        if (clientOfferedAlpn && alpn != null) {
            byte[] name = alpn.getBytes(StandardCharsets.US_ASCII);
            ByteArrayOutputStream a = new ByteArrayOutputStream();
            a.write(u16(name.length + 1), 0, 2);
            a.write(name.length);
            a.write(name, 0, name.length);
            write(exts, extension(EXT_ALPN, a.toByteArray()));
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(u16(exts.size()), 0, 2);
        write(body, exts.toByteArray());
        return message(ENCRYPTED_EXTENSIONS, body.toByteArray());
    }

    /**
     * A TLS 1.3 ServerHello: legacy version, {@code random}, the client's session id echoed,
     * {@code cipherSuite}, no compression, {@code supported_versions} then an X25519
     * {@code key_share}, which is the order JSSE writes them in.
     */
    public static byte[] serverHello(byte[] random, byte[] sessionIdEcho, int cipherSuite, byte[] x25519PublicKey) {
        ByteArrayOutputStream exts = new ByteArrayOutputStream();
        write(exts, extension(EXT_SUPPORTED_VERSIONS, u16(0x0304)));
        ByteArrayOutputStream ks = new ByteArrayOutputStream();
        ks.write(u16(GROUP_X25519), 0, 2);
        ks.write(u16(x25519PublicKey.length), 0, 2);
        write(ks, x25519PublicKey);
        write(exts, extension(EXT_KEY_SHARE, ks.toByteArray()));
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(u16(0x0303), 0, 2);
        write(body, random);
        body.write(sessionIdEcho.length);
        write(body, sessionIdEcho);
        body.write(u16(cipherSuite), 0, 2);
        body.write(0);
        body.write(u16(exts.size()), 0, 2);
        write(body, exts.toByteArray());
        return message(SERVER_HELLO, body.toByteArray());
    }

    /** The X25519 public key for a 32-byte private scalar, as the key share carries it. */
    public static byte[] x25519PublicKey(byte[] scalar) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("XDH");
        PrivateKey priv = kf.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, scalar));
        PublicKey base = kf.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, BigInteger.valueOf(9)));
        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(priv);
        ka.doPhase(base, true);
        return ka.generateSecret();
    }

    /** The code point of a TLS 1.3 cipher suite by its JSSE name, or -1. */
    public static int cipherSuiteCode(String name) {
        return switch (name) {
            case "TLS_AES_128_GCM_SHA256" -> 0x1301;
            case "TLS_AES_256_GCM_SHA384" -> 0x1302;
            case "TLS_CHACHA20_POLY1305_SHA256" -> 0x1303;
            default -> -1;
        };
    }

    // --- reading a ClientHello ----------------------------------------------------------------

    /** The legacy session id a ClientHello carries (echoed by the ServerHello). */
    public static byte[] sessionId(byte[] clientHello) {
        int i = 4 + 2 + 32;
        int len = clientHello[i] & 0xff;
        return Arrays.copyOfRange(clientHello, i + 1, i + 1 + len);
    }

    /** The extensions of a ClientHello by type, in order; data is the extension body. */
    public static Map<Integer, byte[]> extensions(byte[] ch) {
        Map<Integer, byte[]> m = new LinkedHashMap<>();
        int i = 4 + 2 + 32;
        i += 1 + (ch[i] & 0xff); // session id
        i += 2 + u16At(ch, i); // cipher suites
        i += 1 + (ch[i] & 0xff); // compression methods
        if (i + 2 > ch.length) {
            return m;
        }
        int end = Math.min(ch.length, i + 2 + u16At(ch, i));
        i += 2;
        while (i + 4 <= end) {
            int type = u16At(ch, i);
            int len = u16At(ch, i + 2);
            if (i + 4 + len > end) {
                break;
            }
            m.put(type, Arrays.copyOfRange(ch, i + 4, i + 4 + len));
            i += 4 + len;
        }
        return m;
    }

    /** Whether an ALPN extension body offers {@code protocol}. */
    public static boolean alpnOffers(byte[] alpnExt, String protocol) {
        if (alpnExt == null || alpnExt.length < 2) {
            return false;
        }
        byte[] want = protocol.getBytes(StandardCharsets.US_ASCII);
        int i = 2;
        int end = Math.min(alpnExt.length, 2 + u16At(alpnExt, 0));
        while (i < end) {
            int len = alpnExt[i] & 0xff;
            if (len == want.length && Arrays.equals(alpnExt, i + 1, i + 1 + len, want, 0, want.length)) {
                return true;
            }
            i += 1 + len;
        }
        return false;
    }

    // --- encoding helpers ---------------------------------------------------------------------

    public static byte[] message(int type, byte[] body) {
        byte[] m = new byte[4 + body.length];
        m[0] = (byte) type;
        System.arraycopy(u24(body.length), 0, m, 1, 3);
        System.arraycopy(body, 0, m, 4, body.length);
        return m;
    }

    static byte[] extension(int type, byte[] data) {
        byte[] e = new byte[4 + data.length];
        System.arraycopy(u16(type), 0, e, 0, 2);
        System.arraycopy(u16(data.length), 0, e, 2, 2);
        System.arraycopy(data, 0, e, 4, data.length);
        return e;
    }

    static byte[] u16(int n) {
        return new byte[] {(byte) (n >> 8), (byte) n};
    }

    static byte[] u24(int n) {
        return new byte[] {(byte) (n >> 16), (byte) (n >> 8), (byte) n};
    }

    private static int u16At(byte[] b, int i) {
        return ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff);
    }

    private static int length24(byte[] b, int i) {
        return ((b[i] & 0xff) << 16) | ((b[i + 1] & 0xff) << 8) | (b[i + 2] & 0xff);
    }

    private static void write(ByteArrayOutputStream o, byte[] b) {
        o.write(b, 0, b.length);
    }
}
