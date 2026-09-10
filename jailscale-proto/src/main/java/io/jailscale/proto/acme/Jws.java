package io.jailscale.proto.acme;

import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

/** JWS (RFC 7515) with ES256 in the flattened JSON serialisation ACME requires (RFC 8555 §6.2). */
public final class Jws {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private Jws() {}

    /** The account's public key as a JWK (RFC 7517) with keys in the order the thumbprint needs. */
    public static JsonObject jwk(ECPublicKey pub) {
        return JsonObject.builder()
            .put("crv", "P-256")
            .put("kty", "EC")
            .put("x", b64(coordinate(pub.getW().getAffineX())))
            .put("y", b64(coordinate(pub.getW().getAffineY())))
            .build();
    }

    /** RFC 7638 thumbprint: SHA-256 of the canonical JWK with lexicographically ordered members. */
    public static String thumbprint(ECPublicKey pub) throws GeneralSecurityException {
        String canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + b64(coordinate(pub.getW().getAffineX()))
            + "\",\"y\":\"" + b64(coordinate(pub.getW().getAffineY())) + "\"}";
        return b64(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Signs {@code payload} (JSON text, or "" for POST-as-GET) for {@code url}. {@code kid} null
     * means the header carries the JWK instead (newAccount).
     */
    public static String sign(KeyPair account, String url, String nonce, String kid, String payload)
        throws GeneralSecurityException {
        JsonObject.Builder h = JsonObject.builder().put("alg", "ES256").put("nonce", nonce).put("url", url);
        if (kid != null) {
            h.put("kid", kid);
        } else {
            h.put("jwk", jwk((ECPublicKey) account.getPublic()));
        }
        String protectedB64 = b64(h.toJson().getBytes(StandardCharsets.UTF_8));
        String payloadB64 = payload.isEmpty() ? "" : b64(payload.getBytes(StandardCharsets.UTF_8));
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(account.getPrivate());
        sig.update((protectedB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII));
        byte[] raw = derToRaw(sig.sign());
        return JsonObject.builder().put("protected", protectedB64).put("payload", payloadB64).put("signature", b64(raw)).toJson();
    }

    /** DER ECDSA-Sig-Value → 64-byte R||S (JWS requires the raw form; JDK produces DER). */
    public static byte[] derToRaw(byte[] der) throws GeneralSecurityException {
        if (der.length < 8 || der[0] != 0x30) {
            throw new GeneralSecurityException("not a DER ECDSA signature");
        }
        int p = 2;
        if ((der[1] & 0x80) != 0) {
            p = 2 + (der[1] & 0x7f);
        }
        byte[] out = new byte[64];
        for (int i = 0; i < 2; i++) {
            if (der[p++] != 0x02) {
                throw new GeneralSecurityException("bad DER integer");
            }
            int len = der[p++] & 0xff;
            byte[] v = new byte[len];
            System.arraycopy(der, p, v, 0, len);
            p += len;
            byte[] c = coordinate(new BigInteger(1, v));
            System.arraycopy(c, 0, out, i * 32, 32);
        }
        return out;
    }

    /** 64-byte R||S → DER, for verification with the JDK. */
    public static byte[] rawToDer(byte[] raw) {
        BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(raw, 0, 32));
        BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(raw, 32, 64));
        return Der.sequence(Der.integer(r), Der.integer(s));
    }

    static byte[] coordinate(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        if (b.length > 32) {
            System.arraycopy(b, b.length - 32, out, 0, 32);
        } else {
            System.arraycopy(b, 0, out, 32 - b.length, b.length);
        }
        return out;
    }

    public static String b64(byte[] b) {
        return B64.encodeToString(b);
    }

    static String json(Object o) {
        return Json.write(o);
    }
}
