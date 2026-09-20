package io.jailscale.proto.acme;

import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.EnumSet;

/** P-256 key files shared by the hub's wildcard ACME and the node's user-domain ACME. */
public final class AcmeKeys {

    private static final Log LOG = Log.get("acme");

    private AcmeKeys() {}

    public static KeyPair generate() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    /** Loads {@code p} (+ its {@code .pub} companion) or creates a new key pair there. */
    public static KeyPair loadOrCreate(Path p) throws IOException, GeneralSecurityException {
        if (Files.exists(p)) {
            PrivateKey priv = Pem.privateKey(Files.readString(p));
            Path pub = p.resolveSibling(p.getFileName() + ".pub");
            if (Files.exists(pub)) {
                byte[] der = Base64.getMimeDecoder().decode(Files.readString(pub)
                    .replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", ""));
                return new KeyPair(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der)), priv);
            }
            LOG.warn("{} has no .pub companion; creating a new key", p.getFileName());
        }
        Files.createDirectories(p.toAbsolutePath().getParent());
        KeyPair kp = generate();
        writePrivate(p, Pem.encodeBlock("PRIVATE KEY", kp.getPrivate().getEncoded()));
        Files.writeString(p.resolveSibling(p.getFileName() + ".pub"), Pem.encodeBlock("PUBLIC KEY", kp.getPublic().getEncoded()));
        LOG.info("created key {}", p.getFileName());
        return kp;
    }

    /** Writes a PEM file readable by the owner only. */
    public static void writePrivate(Path p, String pem) throws IOException {
        Files.writeString(p, pem, StandardCharsets.UTF_8);
        try {
            Files.setPosixFilePermissions(p, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException _) {
            // Windows
        }
    }
}
