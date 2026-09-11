package io.jailscale.proto.tls;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** PEM reading for certificates and PKCS#8 private keys, and PEM writing for certificates. */
public final class Pem {

    private Pem() {}

    /** All CERTIFICATE blocks in {@code pem}, in order. */
    public static List<X509Certificate> certificates(String pem) throws GeneralSecurityException {
        List<X509Certificate> out = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (byte[] der : blocks(pem, "CERTIFICATE")) {
            out.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
        }
        if (out.isEmpty()) {
            throw new GeneralSecurityException("no CERTIFICATE block in PEM");
        }
        return out;
    }

    /** The first PRIVATE KEY (PKCS#8) block; EC and RSA are tried in that order. */
    public static PrivateKey privateKey(String pem) throws GeneralSecurityException {
        List<byte[]> blocks = blocks(pem, "PRIVATE KEY");
        if (blocks.isEmpty()) {
            throw new GeneralSecurityException("no PKCS#8 PRIVATE KEY block in PEM (legacy EC/RSA PRIVATE KEY formats are not supported)");
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(blocks.get(0));
        GeneralSecurityException last = null;
        for (String alg : new String[] {"EC", "RSA", "EdDSA"}) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(spec);
            } catch (GeneralSecurityException e) {
                last = e;
            }
        }
        throw last;
    }

    public static String encode(X509Certificate cert) throws GeneralSecurityException {
        return encodeBlock("CERTIFICATE", cert.getEncoded());
    }

    public static String encodeBlock(String label, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
    }

    static List<byte[]> blocks(String pem, String label) {
        List<byte[]> out = new ArrayList<>();
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        int pos = 0;
        while (true) {
            int b = pem.indexOf(begin, pos);
            if (b < 0) {
                return out;
            }
            int e = pem.indexOf(end, b);
            if (e < 0) {
                return out;
            }
            String body = pem.substring(b + begin.length(), e).replaceAll("\\s", "");
            out.add(Base64.getDecoder().decode(body));
            pos = e + end.length();
        }
    }
}
