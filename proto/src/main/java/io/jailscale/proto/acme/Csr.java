package io.jailscale.proto.acme;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;
import java.util.List;

/**
 * PKCS#10 (RFC 2986) for an EC P-256 key with a subjectAltName extension request, signed
 * ecdsa-with-SHA256. The JDK has no public CSR API (ARCHITECTURE.md §7.2).
 */
public final class Csr {

    private static final String OID_CN = "2.5.4.3";
    private static final String OID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14";
    private static final String OID_SAN = "2.5.29.17";
    private static final String OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";

    private Csr() {}

    /** DER-encoded CertificationRequest with CN = first name and all names as dNSName SANs. */
    public static byte[] build(KeyPair key, List<String> dnsNames) throws GeneralSecurityException {
        if (dnsNames.isEmpty()) {
            throw new IllegalArgumentException("at least one name");
        }
        byte[] subject = Der.sequence(Der.set(Der.sequence(Der.oid(OID_CN), Der.utf8(dnsNames.get(0)))));
        byte[] spki = key.getPublic().getEncoded(); // X.509 SubjectPublicKeyInfo, already DER
        byte[] generalNames = Der.sequence(dnsNames.stream()
            .map(n -> Der.context(2, false, n.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) // dNSName
            .toArray(byte[][]::new));
        byte[] extensions = Der.sequence(Der.sequence(Der.oid(OID_SAN), Der.octetString(generalNames)));
        byte[] attributes = Der.context(0, true, Der.sequence(Der.oid(OID_EXTENSION_REQUEST), Der.set(extensions)));
        byte[] info = Der.sequence(Der.integer(0), subject, spki, attributes);

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(key.getPrivate());
        sig.update(info);
        byte[] signature = sig.sign(); // DER ECDSA-Sig-Value, which is what the BIT STRING holds
        byte[] algorithm = Der.sequence(Der.oid(OID_ECDSA_SHA256));
        return Der.sequence(info, algorithm, Der.bitString(signature));
    }
}
