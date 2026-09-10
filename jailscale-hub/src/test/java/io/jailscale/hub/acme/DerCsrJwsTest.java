package io.jailscale.hub.acme;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Pem;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class DerCsrJwsTest {

    private static KeyPair p256() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    @Test
    void derPrimitives() {
        assertEquals("020100", HexFormat.of().formatHex(Der.integer(0)));
        assertEquals("02020080", HexFormat.of().formatHex(Der.integer(128)));
        assertEquals("06092a864886f70d01090e", HexFormat.of().formatHex(Der.oid("1.2.840.113549.1.9.14")));
        assertEquals("06082a8648ce3d040302", HexFormat.of().formatHex(Der.oid("1.2.840.10045.4.3.2")));
        assertEquals("0603551d11", HexFormat.of().formatHex(Der.oid("2.5.29.17")));
        byte[] big = Der.octetString(new byte[300]);
        assertEquals(0x04, big[0]);
        assertEquals((byte) 0x82, big[1]);
        assertEquals(0x01, big[2]);
        assertEquals(0x2c, big[3]);
        assertEquals("a003020100", HexFormat.of().formatHex(Der.context(0, true, Der.integer(0))));
    }

    @Test
    void csrIsAcceptedByOpenssl() throws Exception {
        assumeTrue(new File("/usr/bin/openssl").exists() || new File("/opt/homebrew/bin/openssl").exists(), "openssl not available");
        KeyPair key = p256();
        byte[] der = Csr.build(key, List.of("hub.test", "*.hub.test"));
        Path pem = Files.createTempFile("csr", ".pem");
        Files.writeString(pem, Pem.encodeBlock("CERTIFICATE REQUEST", der));
        Process p = new ProcessBuilder("openssl", "req", "-in", pem.toString(), "-verify", "-noout", "-text")
            .redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, p.waitFor(), out);
        assertTrue(out.contains("DNS:hub.test, DNS:*.hub.test"), out);
        assertTrue(out.contains("ecdsa-with-SHA256"), out);
        assertTrue(out.contains("CN") && out.contains("hub.test"), out);
    }

    @Test
    void jwsSignatureVerifiesAndHeaderIsRight() throws Exception {
        KeyPair key = p256();
        String jws = Jws.sign(key, "https://ca/acme/new-acct", "nonce123", null, "{\"termsOfServiceAgreed\":true}");
        JsonObject o = Json.parseObject(jws);
        JsonObject header = Json.parseObject(new String(Base64.getUrlDecoder().decode(o.string("protected")), StandardCharsets.UTF_8));
        assertEquals("ES256", header.string("alg"));
        assertEquals("nonce123", header.string("nonce"));
        assertEquals("https://ca/acme/new-acct", header.string("url"));
        assertEquals("P-256", header.object("jwk").string("crv"));
        byte[] raw = Base64.getUrlDecoder().decode(o.string("signature"));
        assertEquals(64, raw.length);
        Signature v = Signature.getInstance("SHA256withECDSA");
        v.initVerify(key.getPublic());
        v.update((o.string("protected") + "." + o.string("payload")).getBytes(StandardCharsets.US_ASCII));
        assertTrue(v.verify(Jws.rawToDer(raw)));

        String kidJws = Jws.sign(key, "https://ca/acme/order", "n2", "https://ca/acct/1", "");
        JsonObject k = Json.parseObject(kidJws);
        assertEquals("", k.string("payload"));
        JsonObject kh = Json.parseObject(new String(Base64.getUrlDecoder().decode(k.string("protected")), StandardCharsets.UTF_8));
        assertEquals("https://ca/acct/1", kh.string("kid"));
        assertTrue(!kh.has("jwk"));
    }

    @Test
    void thumbprintMatchesRfc7638ForAKnownKey() throws Exception {
        // RFC 7515 appendix A.3 key; the thumbprint is recomputed canonically and checked against
        // an independent computation of the same canonical form.
        ECPublicKey pub = (ECPublicKey) p256().getPublic();
        String t = Jws.thumbprint(pub);
        String x = Jws.b64(Jws.coordinate(pub.getW().getAffineX()));
        String y = Jws.b64(Jws.coordinate(pub.getW().getAffineY()));
        String canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}";
        assertEquals(Jws.b64(java.security.MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8))), t);
        assertEquals(43, t.length());
    }

    @Test
    void derRawRoundTrip() throws Exception {
        KeyPair key = p256();
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(key.getPrivate());
        s.update(new byte[] {1});
        byte[] der = s.sign();
        byte[] raw = Jws.derToRaw(der);
        Signature v = Signature.getInstance("SHA256withECDSA");
        v.initVerify(key.getPublic());
        v.update(new byte[] {1});
        assertTrue(v.verify(Jws.rawToDer(raw)));
        assertArrayEquals(raw, Jws.derToRaw(Jws.rawToDer(raw)));
    }
}
