package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.acme.Der;
import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A node that cannot reach its hub is the one the expiry warning exists for (ARCHITECTURE.md §15),
 * and it is also the one that never runs {@code onConnected}, so nothing would load its certificates
 * until the renew loop first wakes an hour in. This pins that the warning comes from what is on disk,
 * with no hub and no waiting.
 */
class StartupExpiryWarningTest {

    private static final String DOMAIN = "app.example.test";

    @Test
    void aCertificateRunningOutIsReportedAtStartupWithNoHub(@TempDir Path dir) throws Exception {
        storeCertificate(dir, 5 * 24 + 12);   // five and a half days left
        storeLink(dir);

        String logged = startupLog(dir);

        assertTrue(logged.contains(DOMAIN), logged);
        assertTrue(logged.contains("expires in 5 days"), logged);
        assertTrue(logged.contains("connected to its hub"), logged);
    }

    @Test
    void aCertificateWithPlentyOfLifeIsNotMentioned(@TempDir Path dir) throws Exception {
        storeCertificate(dir, 60 * 24);       // sixty days left
        storeLink(dir);

        String logged = startupLog(dir);

        assertFalse(logged.contains(DOMAIN), logged);
    }

    /** Builds the daemon over {@code dir} and returns everything it logged during the startup pass. */
    private static String startupLog(Path dir) throws Exception {
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream previous = System.err;
        Log.setOutput(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try (Daemon daemon = new Daemon(NodeConfig.in(dir))) {
            daemon.warnAboutStoredCertificates();
        } finally {
            Log.setOutput(previous);
        }
        return captured.toString(StandardCharsets.UTF_8);
    }

    /** A node.json holding one domain link, as a node that had published {@link #DOMAIN} would have. */
    private static void storeLink(Path dir) throws Exception {
        NodeState state = NodeState.load(NodeConfig.in(dir).stateFile());
        NodeState.LinkRec rec = new NodeState.LinkRec("127.0.0.1", 3000, "abcde");
        rec.domain = DOMAIN;
        state.links.add(rec);
        state.save();
    }

    /**
     * A self-signed certificate for {@link #DOMAIN} expiring in {@code hours}, written where
     * {@code DomainCerts} looks. Self-signed is enough: the node only reads the expiry off it, and
     * the chain is validated by the hub, against public roots, on a claim this test does not make.
     */
    private static void storeCertificate(Path dir, int hours) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();

        DateTimeFormatter utc = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'");
        ZonedDateTime from = ZonedDateTime.now(ZoneOffset.UTC).minusDays(1);
        byte[] validity = Der.sequence(
            Der.tlv(0x17, utc.format(from).getBytes(StandardCharsets.US_ASCII)),
            Der.tlv(0x17, utc.format(ZonedDateTime.now(ZoneOffset.UTC).plusHours(hours)).getBytes(StandardCharsets.US_ASCII)));
        byte[] name = Der.sequence(Der.set(Der.sequence(Der.oid("2.5.4.3"), Der.utf8(DOMAIN))));
        byte[] san = Der.sequence(Der.context(2, false, DOMAIN.getBytes(StandardCharsets.US_ASCII)));
        byte[] extensions = Der.context(3, true, Der.sequence(Der.sequence(Der.oid("2.5.29.17"), Der.octetString(san))));
        byte[] sigAlg = Der.sequence(Der.oid("1.2.840.10045.4.3.2"));   // ecdsa-with-SHA256
        byte[] tbs = Der.sequence(
            Der.context(0, true, Der.integer(2)),                       // v3
            Der.integer(new BigInteger(63, new SecureRandom())),
            sigAlg,
            name,                                                       // issuer: itself
            validity,
            name,
            kp.getPublic().getEncoded(),
            extensions);
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(kp.getPrivate());
        s.update(tbs);
        byte[] cert = Der.sequence(tbs, sigAlg, Der.bitString(s.sign()));

        Path domains = dir.resolve("domains");
        Files.createDirectories(domains);
        Files.writeString(domains.resolve(DOMAIN + ".pem"), Pem.encodeBlock("CERTIFICATE", cert));
        Files.writeString(domains.resolve(DOMAIN + ".key"), Pem.encodeBlock("PRIVATE KEY", kp.getPrivate().getEncoded()));
    }
}
