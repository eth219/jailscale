package io.jailscale.node;

import io.jailscale.proto.acme.AcmeClient;
import io.jailscale.proto.acme.AcmeException;
import io.jailscale.proto.acme.AcmeKeys;
import io.jailscale.proto.acme.Csr;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;

/**
 * Certificates for user domains (ARCHITECTURE.md §8.3): the node's own key, obtained with ACME
 * http-01 where the hub answers the challenge on port 80. Files in {@code <config>/domains/}.
 */
final class DomainCerts {

    private static final Log LOG = Log.get("domain");
    static final long VALIDATION_TIMEOUT_MS = 90_000;
    private static final long ACK_TIMEOUT_MS = 10_000;

    /** A domain's chain and key as loaded from disk or freshly issued. */
    record Material(String domain, List<X509Certificate> chain, List<String> chainPem, PrivateKey key) {
        long notAfter() {
            return chain.get(0).getNotAfter().getTime();
        }

        /** ARCHITECTURE.md §8.3: renew when a third of the lifetime is left. */
        boolean dueForRenewal() {
            long notBefore = chain.get(0).getNotBefore().getTime();
            long remaining = notAfter() - System.currentTimeMillis();
            return remaining < (notAfter() - notBefore) / 3;
        }
    }

    private final Path dir;

    DomainCerts(Path configDir) {
        this.dir = configDir.resolve("domains");
    }

    /** The stored material for {@code domain}, or null when none (or unreadable). */
    Material load(String domain) {
        Path pem = dir.resolve(domain + ".pem");
        Path key = dir.resolve(domain + ".key");
        if (!Files.exists(pem) || !Files.exists(key)) {
            return null;
        }
        try {
            String chainPem = Files.readString(pem);
            List<X509Certificate> chain = Pem.certificates(chainPem);
            if (chain.isEmpty()) {
                return null;
            }
            return new Material(domain, chain, split(chainPem), Pem.privateKey(Files.readString(key)));
        } catch (IOException | GeneralSecurityException e) {
            LOG.warn("stored certificate for {} unreadable: {}", domain, e.getMessage());
            return null;
        }
    }

    /**
     * One http-01 order. The hub relays {@code /.well-known/acme-challenge/<token>} for as long
     * as the ChallengeSet stands; it is cleared afterwards whatever happened.
     */
    Material issue(String domain, URI directory, String email, HubLink link)
        throws IOException, GeneralSecurityException, AcmeException, InterruptedException {
        Files.createDirectories(dir);
        KeyPair account = AcmeKeys.loadOrCreate(dir.resolve("account.key"));
        AcmeClient client = new AcmeClient(directory, account, email, "jailscale/" + Version.string());
        LOG.info("requesting certificate for {} from {}", domain, directory);
        client.account();
        AcmeClient.Order order = client.newOrder(List.of(domain));
        List<AcmeClient.Challenge> challenges = new ArrayList<>();
        for (String authz : order.authorizations()) {
            challenges.add(client.http01(authz));
        }
        List<String> tokens = new ArrayList<>();
        try {
            for (AcmeClient.Challenge c : challenges) {
                Message r = ask(link, new Message.ChallengeSet(c.token(), client.keyAuthorization(c.token())));
                if (!(r instanceof Message.Ack)) {
                    throw new IOException("hub refused the challenge: " + (r instanceof Message.Error e ? e.reason() : r.type()));
                }
                tokens.add(c.token());
                if (!c.status().equals("valid")) {
                    client.respond(c);
                }
            }
            for (AcmeClient.Challenge c : challenges) {
                String status = client.awaitAuthorization(c.authzUrl(), VALIDATION_TIMEOUT_MS);
                if (!status.equals("valid")) {
                    throw new AcmeException("unauthorized", 0, "validation of " + c.identifier() + " ended " + status
                        + " (does " + domain + " point at the hub, and is the hub's port 80 reachable?)");
                }
            }
            KeyPair certKey = AcmeKeys.generate();
            AcmeClient.Order finalized = client.finalizeOrder(order, Csr.build(certKey, List.of(domain)));
            AcmeClient.Order valid = client.awaitOrder(finalized, VALIDATION_TIMEOUT_MS);
            String pem = client.certificate(valid.certificate());
            List<X509Certificate> chain = Pem.certificates(pem);
            store(domain, certKey.getPrivate(), pem);
            LOG.info("certificate for {} issued, valid until {}", domain, chain.get(0).getNotAfter());
            return new Material(domain, chain, split(pem), certKey.getPrivate());
        } finally {
            for (String t : tokens) {
                try {
                    ask(link, new Message.ChallengeClear(t));
                } catch (IOException | InterruptedException ignored) {
                    // the hub expires it anyway
                }
            }
        }
    }

    private static Message ask(HubLink link, Message m) throws IOException, InterruptedException {
        try {
            return link.request(m, "Ack", ACK_TIMEOUT_MS);
        } catch (TimeoutException e) {
            throw new IOException("hub did not answer " + m.type());
        }
    }

    private void store(String domain, PrivateKey key, String pem) throws IOException {
        Path keyTmp = dir.resolve(domain + ".key.tmp");
        AcmeKeys.writePrivate(keyTmp, Pem.encodeBlock("PRIVATE KEY", key.getEncoded()));
        Path pemTmp = dir.resolve(domain + ".pem.tmp");
        Files.writeString(pemTmp, pem, StandardCharsets.UTF_8);
        Files.move(keyTmp, dir.resolve(domain + ".key"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        Files.move(pemTmp, dir.resolve(domain + ".pem"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /** Splits a PEM bundle into one string per certificate block. */
    static List<String> split(String pem) {
        List<String> out = new ArrayList<>();
        int i = 0;
        while (true) {
            int b = pem.indexOf("-----BEGIN CERTIFICATE-----", i);
            if (b < 0) {
                break;
            }
            int e = pem.indexOf("-----END CERTIFICATE-----", b);
            if (e < 0) {
                break;
            }
            e += "-----END CERTIFICATE-----".length();
            out.add(pem.substring(b, e) + "\n");
            i = e;
        }
        return out;
    }
}
