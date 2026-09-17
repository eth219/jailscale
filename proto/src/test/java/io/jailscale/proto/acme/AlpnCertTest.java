package io.jailscale.proto.acme;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The certificate that answers a tls-alpn-01 challenge (RFC 8737 §3). Everything here is read back
 * with the JDK's own X.509 parser rather than by comparing bytes: what has to be true is that a
 * validation server can read it, and a byte comparison would pass just as well for a structure only
 * this file understands.
 */
@Timeout(30)
class AlpnCertTest {

    private static final String OID_ACME_IDENTIFIER = "1.3.6.1.5.5.7.1.31";

    private static KeyPair key() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    private static X509Certificate parse(byte[] der) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(der));
    }

    @Test
    void theJdkReadsItAndItSaysWhatRfc8737AsksFor() throws Exception {
        KeyPair k = key();
        X509Certificate c = parse(AlpnCert.certificate(k, "app.example.com", "token.thumbprint", 3600));

        assertEquals(3, c.getVersion(), "v3, or the extensions are not there at all");
        assertEquals(c.getSubjectX500Principal(), c.getIssuerX500Principal(), "self-signed");
        assertEquals(List.of(List.of(2, "app.example.com")), List.copyOf(c.getSubjectAlternativeNames()),
            "one dNSName SAN, which is the name being validated");

        byte[] want = MessageDigest.getInstance("SHA-256").digest("token.thumbprint".getBytes(StandardCharsets.UTF_8));
        byte[] ext = c.getExtensionValue(OID_ACME_IDENTIFIER);
        assertNotNull(ext, "no acmeIdentifier extension");
        // getExtensionValue hands back the extnValue OCTET STRING; RFC 8737 puts another one
        // inside it, so the digest starts four bytes in: 04 22 04 20 <32 bytes>.
        assertEquals(0x04, ext[0] & 0xff);
        assertEquals(0x04, ext[2] & 0xff);
        assertEquals(32, ext[3] & 0xff);
        assertArrayEquals(want, java.util.Arrays.copyOfRange(ext, 4, 4 + 32), "the wrong key authorization digest");

        assertTrue(c.getCriticalExtensionOIDs().contains(OID_ACME_IDENTIFIER),
            "RFC 8737 §3: a client that does not understand this extension must refuse the certificate");
    }

    @Test
    void itIsValidNowAndNotForever() throws Exception {
        X509Certificate c = parse(AlpnCert.certificate(key(), "app.example.com", "ka", 3600));
        c.checkValidity();  // throws if not
        assertTrue(c.getNotBefore().toInstant().isBefore(Instant.now()),
            "a validation server's clock is not this one's, so it has to be valid already");
        long seconds = (c.getNotAfter().getTime() - c.getNotBefore().getTime()) / 1000;
        assertEquals(3660, seconds, "the window asked for, plus the minute of slack before it");
    }

    @Test
    void itVerifiesUnderItsOwnKey() throws Exception {
        KeyPair k = key();
        X509Certificate c = parse(AlpnCert.certificate(k, "app.example.com", "ka", 60));
        c.verify(k.getPublic());   // throws if the signature or the algorithm is wrong
    }

    @Test
    void twoCertificatesForOneNameAreNotTheSameCertificate() throws Exception {
        KeyPair k = key();
        X509Certificate a = parse(AlpnCert.certificate(k, "app.example.com", "ka", 60));
        X509Certificate b = parse(AlpnCert.certificate(k, "app.example.com", "ka", 60));
        assertTrue(!a.getSerialNumber().equals(b.getSerialNumber()), "a fixed serial is a certificate a cache can confuse");
    }

    @Test
    void aNameIsRequired() {
        assertThrows(IllegalArgumentException.class, () -> AlpnCert.certificate(key(), "", "ka", 60));
        assertThrows(IllegalArgumentException.class, () -> AlpnCert.certificate(key(), null, "ka", 60));
    }
}
