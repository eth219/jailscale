package io.jailscale.node;

import io.jailscale.proto.tls.Tls13;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Rebuilds, at the moment JSSE asks for a CertificateVerify signature, the handshake messages the
 * transcript hash in that request covers (ARCHITECTURE.md §9.2). JSSE signs before it has written
 * a byte of its flight, and shows neither its ServerHello nor its EncryptedExtensions, so the
 * node works them out from what it does have:
 *
 * <ul>
 *   <li>the ClientHello(s), and a HelloRetryRequest if one went out: plaintext, taken off the wire
 *       by {@link TlsEndpoint};
 *   <li>the ServerHello: its random and its X25519 key share are the only unknowns, and both came
 *       out of the {@code SecureRandom} the node handed the {@code SSLContext}, which
 *       {@link RemoteSigning#RANDOM} records; the cipher suite is on the handshake session, the
 *       session id is echoed from the ClientHello;
 *   <li>the EncryptedExtensions: a function of the ClientHello and the server's fixed
 *       configuration (one group, one ALPN protocol);
 *   <li>the Certificate: the chain the hub sent.
 * </ul>
 *
 * The reconstruction is checked here, against the hash JSSE handed over, before anything is
 * sent: a wrong guess fails this handshake with a clear reason instead of asking the hub to sign
 * something it will refuse. A JDK that changes how it writes these messages shows up as every
 * visitor handshake failing, which the end-to-end tests catch.
 */
final class Transcript {

    /** What the hub needs beside the ClientHello it already holds. */
    record Reconstructed(byte[] serverHello, byte[] encryptedExtensions, byte[] helloRetryRequest) {}

    private Transcript() {}

    /**
     * @param clientMessages the visitor's plaintext handshake messages so far (one or two ClientHellos)
     * @param serverMessages the node's plaintext handshake messages so far (a HelloRetryRequest, or nothing)
     * @param randomChunks every {@code nextBytes} JSSE drew for this handshake, in order
     * @param cipherSuite the negotiated suite, from the handshake session
     * @param certificate the Certificate message for the chain in use
     * @param content what JSSE asked to have signed
     * @throws GeneralSecurityException when no reconstruction hashes to what JSSE wants signed
     */
    static Reconstructed reconstruct(List<byte[]> clientMessages, List<byte[]> serverMessages, List<byte[]> randomChunks,
        String cipherSuite, byte[] certificate, byte[] content) throws GeneralSecurityException {
        String hashAlg = Tls13.hashAlgorithmOf(content);
        if (hashAlg == null) {
            throw new GeneralSecurityException("asked to sign something that is not a server CertificateVerify");
        }
        byte[] want = Tls13.transcriptHashIn(content);
        byte[] hrr = null;
        for (byte[] m : serverMessages) {
            if (Tls13.isHelloRetryRequest(m)) {
                hrr = m;
            }
        }
        if (clientMessages.isEmpty() || hrr != null && clientMessages.size() < 2) {
            throw new GeneralSecurityException("no ClientHello to bind the signature to");
        }
        byte[] clientHello = clientMessages.get(clientMessages.size() - 1);
        List<byte[]> hellos = hrr == null ? List.of(clientHello) : List.of(clientMessages.get(0), clientHello);
        int suite = Tls13.cipherSuiteCode(cipherSuite == null ? "" : cipherSuite);
        if (suite < 0) {
            throw new GeneralSecurityException("cannot reconstruct a ServerHello for cipher suite " + cipherSuite);
        }
        Map<Integer, byte[]> exts = Tls13.extensions(clientHello);
        byte[] ee = Tls13.encryptedExtensions(exts.containsKey(Tls13.EXT_SUPPORTED_GROUPS), TlsEndpoint.GROUP_IDS,
            TlsEndpoint.ALPN, Tls13.alpnOffers(exts.get(Tls13.EXT_ALPN), TlsEndpoint.ALPN));
        byte[] sessionId = Tls13.sessionId(clientHello);

        // JSSE draws a session id, then the ServerHello random, then the X25519 scalar, each 32
        // bytes; the order is not something to rely on, so every pairing is tried, likeliest first.
        List<byte[]> c32 = new ArrayList<>(3);
        for (byte[] c : randomChunks) {
            if (c.length == 32) {
                c32.add(c);
            }
        }
        List<int[]> order = new ArrayList<>();
        if (c32.size() >= 3) {
            order.add(new int[] {1, 2});
        }
        for (int r = 0; r < c32.size(); r++) {
            for (int k = 0; k < c32.size(); k++) {
                if (r != k) {
                    order.add(new int[] {r, k});
                }
            }
        }
        byte[][] pub = new byte[c32.size()][];
        for (int[] rk : order) {
            if (pub[rk[1]] == null) {
                pub[rk[1]] = Tls13.x25519PublicKey(c32.get(rk[1]));
            }
            byte[] sh = Tls13.serverHello(c32.get(rk[0]), sessionId, suite, pub[rk[1]]);
            byte[] got = Tls13.transcriptHash(hashAlg, hellos, hrr, sh, ee, certificate);
            if (Arrays.equals(got, want)) {
                return new Reconstructed(sh, ee, hrr);
            }
        }
        throw new GeneralSecurityException("could not reconstruct the handshake transcript JSSE wants signed ("
            + c32.size() + " random draws, " + clientMessages.size() + " ClientHello(s), " + (hrr == null ? "no" : "a")
            + " HelloRetryRequest, " + cipherSuite + ")");
    }
}
