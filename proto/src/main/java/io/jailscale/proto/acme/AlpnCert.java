package io.jailscale.proto.acme;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * The self-signed certificate that answers a {@code tls-alpn-01} challenge (RFC 8737).
 *
 * <p>The ACME server opens a TLS connection to port 443 with the name being validated in SNI and
 * {@code acme-tls/1} in ALPN, and the only thing it looks at is the certificate: a SAN of
 * {@code dNSName} equal to that name, and a <b>critical</b> {@code id-pe-acmeIdentifier} extension
 * whose value is the SHA-256 of the key authorization. Nothing else about the handshake matters,
 * which is why the certificate can be self-signed and live for an hour.
 *
 * <p>Here rather than in the JDK because the JDK has no public API for building a certificate, the
 * same reason {@link Csr} exists (ARCHITECTURE.md §7.2). The pieces are the same as a CSR's, plus a
 * validity window and an issuer, which for a self-signed certificate is the subject.
 *
 * <p>What this buys is port 80. The {@code http-01} relay is the only path implemented, so a
 * domain a node brings itself needs the hub to hold 80 as well as 443; on a host where 80 is taken
 * that feature is simply off. This challenge is answered inside a handshake on 443, which the hub
 * already terminates for every visitor.
 */
public final class AlpnCert {

    /** RFC 8737 §3: the ALPN protocol an ACME server offers for this challenge. */
    public static final String ALPN_PROTOCOL = "acme-tls/1";

    private static final String OID_CN = "2.5.4.3";
    private static final String OID_SAN = "2.5.29.17";
    /** id-pe-acmeIdentifier, RFC 8737 §3. */
    private static final String OID_ACME_IDENTIFIER = "1.3.6.1.5.5.7.1.31";
    private static final String OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
    private static final DateTimeFormatter UTC_TIME =
        DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

    private AlpnCert() {}

    /**
     * A DER certificate for {@code dnsName} carrying {@code keyAuthorization}, valid from a minute
     * ago until {@code validForSeconds} from now.
     *
     * <p>A minute ago because a validation server's clock is not this one's, and a certificate that
     * is not valid yet is refused as firmly as one that expired.
     */
    public static byte[] certificate(KeyPair key, String dnsName, String keyAuthorization, long validForSeconds)
        throws GeneralSecurityException {
        if (dnsName == null || dnsName.isBlank()) {
            throw new IllegalArgumentException("a tls-alpn-01 certificate needs the name it is for");
        }
        byte[] digest = MessageDigest.getInstance("SHA-256")
            .digest(keyAuthorization.getBytes(StandardCharsets.UTF_8));

        byte[] name = Der.sequence(Der.set(Der.sequence(Der.oid(OID_CN), Der.utf8(dnsName))));
        byte[] spki = key.getPublic().getEncoded(); // X.509 SubjectPublicKeyInfo, already DER
        byte[] algorithm = Der.sequence(Der.oid(OID_ECDSA_SHA256));

        Instant now = Instant.now();
        byte[] validity = Der.sequence(
            utcTime(now.minusSeconds(60)),
            utcTime(now.plusSeconds(validForSeconds)));

        // The SAN is not critical: the name is also the subject CN, so a reader that ignores the
        // extension still sees it. The acmeIdentifier one is critical because RFC 8737 §3 says a
        // client that does not understand it must not accept the certificate -- this certificate
        // means one thing and it is not "this host is that name".
        byte[] san = Der.sequence(Der.oid(OID_SAN), Der.octetString(
            Der.sequence(Der.context(2, false, dnsName.getBytes(StandardCharsets.US_ASCII)))));
        byte[] acme = Der.sequence(Der.oid(OID_ACME_IDENTIFIER), Der.bool(true),
            Der.octetString(Der.octetString(digest)));
        byte[] extensions = Der.context(3, true, Der.sequence(san, acme));

        byte[] serial = Der.integer(new java.math.BigInteger(64, new SecureRandom()).add(java.math.BigInteger.ONE));
        byte[] tbs = Der.sequence(
            Der.context(0, true, Der.integer(2)),  // version v3
            serial,
            algorithm,
            name,                                   // issuer: itself
            validity,
            name,                                   // subject
            spki,
            extensions);

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(key.getPrivate());
        sig.update(tbs);
        return Der.sequence(tbs, algorithm, Der.bitString(sig.sign()));
    }

    /** UTCTime, which is what a certificate valid before 2050 carries (RFC 5280 §4.1.2.5.1). */
    private static byte[] utcTime(Instant at) {
        return Der.tlv(0x17, UTC_TIME.format(at).getBytes(StandardCharsets.US_ASCII));
    }
}
