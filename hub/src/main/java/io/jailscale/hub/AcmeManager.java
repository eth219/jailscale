package io.jailscale.hub;

import io.jailscale.proto.acme.AcmeClient;
import io.jailscale.proto.acme.AcmeException;
import io.jailscale.proto.acme.AcmeKeys;
import io.jailscale.proto.acme.Csr;
import io.jailscale.hub.dns.DnsQuery;
import io.jailscale.hub.dns.DnsResponder;
import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.util.Log;
import java.io.IOException;
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

/**
 * Certificate lifecycle (ARCHITECTURE.md §7): one wildcard certificate via dns-01 answered by the
 * hub's own {@link DnsResponder}, renewed when a third of its lifetime is left. Files live in
 * {@code <state>/tls/}.
 */
final class AcmeManager implements AutoCloseable {

    private static final Log LOG = Log.get("acme");
    private static final long SELF_CHECK_RETRY_MS = 60_000;
    private static final long RENEW_CHECK_MS = 24 * 3600 * 1000L;
    private static final long VALIDATION_TIMEOUT_MS = 120_000;

    private final HubConfig config;
    private final HubTls tls;
    private final Path dir;
    private final DnsResponder dns;
    private final Runnable onInstalled;
    private KeyPair account;
    private Thread renewer;
    private volatile boolean closed;

    AcmeManager(HubConfig config, HubTls tls, DnsResponder dns, Runnable onInstalled) {
        this.config = config;
        this.tls = tls;
        this.dir = config.stateDir().resolve("tls");
        this.dns = dns;
        this.onInstalled = onInstalled;
    }

    /**
     * Installs the stored certificate if it is still fresh, otherwise issues one (blocking, with
     * retries), then starts the renewal loop.
     */
    void start() throws IOException, GeneralSecurityException, InterruptedException {
        Files.createDirectories(dir);
        account = AcmeKeys.loadOrCreate(dir.resolve("account.key"));
        boolean installed = false;
        if (Files.exists(dir.resolve("wildcard.pem")) && Files.exists(dir.resolve("wildcard.key"))) {
            try {
                List<X509Certificate> chain = Pem.certificates(Files.readString(dir.resolve("wildcard.pem")));
                PrivateKey key = Pem.privateKey(Files.readString(dir.resolve("wildcard.key")));
                tls.install(chain, key);
                installed = true;
                if (needsRenewal(chain.get(0))) {
                    LOG.info("stored certificate is due for renewal");
                    issueWithRetries();
                }
            } catch (GeneralSecurityException | IOException e) {
                LOG.warn("stored certificate unusable, reissuing: {}", e.getMessage());
            }
        }
        if (!installed) {
            issueWithRetries();
        }
        renewer = Thread.ofVirtual().name("acme-renew").start(this::renewLoop);
    }

    static boolean needsRenewal(X509Certificate leaf) {
        long lifetime = leaf.getNotAfter().getTime() - leaf.getNotBefore().getTime();
        long left = leaf.getNotAfter().getTime() - System.currentTimeMillis();
        return left < lifetime / 3;
    }

    private void issueWithRetries() throws InterruptedException {
        long backoff = 60_000;
        while (!closed) {
            try {
                if (config.selfCheck()) {
                    String problem = selfCheck();
                    if (problem != null) {
                        LOG.error("self-check failed: {}. Retrying in {}s (skip with --no-selfcheck)", problem, SELF_CHECK_RETRY_MS / 1000);
                        Thread.sleep(SELF_CHECK_RETRY_MS);
                        continue;
                    }
                }
                issue();
                return;
            } catch (AcmeException | IOException | GeneralSecurityException e) {
                LOG.error("certificate issuance failed: {}. Retrying in {}s", e.getMessage(), backoff / 1000);
                Thread.sleep(backoff);
                backoff = Math.min(backoff * 2, 3600_000);
            }
        }
    }

    /**
     * ARCHITECTURE.md §7.2: prove the delegation reaches this process by asking public resolvers
     * for a value only we know. Returns null when fine, otherwise a diagnosis.
     */
    String selfCheck() {
        String probe = "selftest-" + Tokens.inviteToken();
        dns.setTxt(List.of(probe));
        try {
            String[] resolvers = {"1.1.1.1", "8.8.8.8"};
            String last = null;
            for (String r : resolvers) {
                try {
                    List<String> got = DnsQuery.txt(r, 53, dns.zone(), 5000);
                    if (got.contains(probe)) {
                        return null;
                    }
                    last = r + " answered " + (got.isEmpty() ? "no TXT" : got) + " instead of our probe: "
                        + "the NS delegation for " + dns.zone() + " does not reach this hub, or a stale answer is cached";
                } catch (IOException e) {
                    last = r + ": " + e.getMessage() + " (is UDP/TCP 53 open and is the NS record for " + dns.zone() + " in place?)";
                }
            }
            return last;
        } finally {
            dns.clearTxt();
        }
    }

    /** One full dns-01 order for {@code hub} and {@code *.hub}. */
    void issue() throws AcmeException, IOException, GeneralSecurityException, InterruptedException {
        String host = config.hostname();
        List<String> names = List.of(host, "*." + host);
        AcmeClient client = new AcmeClient(config.acmeDirectory(), account, config.acmeEmail(), "jailhub/" + Hub.version());
        LOG.info("requesting certificate for {} from {}", names, config.acmeDirectory());
        client.account();
        AcmeClient.Order order = client.newOrder(names);
        List<AcmeClient.Challenge> challenges = new ArrayList<>();
        List<String> txt = new ArrayList<>();
        for (String authz : order.authorizations()) {
            AcmeClient.Challenge c = client.dns01(authz);
            challenges.add(c);
            txt.add(client.dns01Value(c.token()));
        }
        dns.setTxt(txt);
        try {
            for (AcmeClient.Challenge c : challenges) {
                if (!c.status().equals("valid")) {
                    client.respond(c);
                }
            }
            for (AcmeClient.Challenge c : challenges) {
                client.awaitAuthorization(c.authzUrl(), VALIDATION_TIMEOUT_MS);
                LOG.info("validated {}", c.identifier());
            }
            KeyPair certKey = AcmeKeys.generate();
            AcmeClient.Order finalized = client.finalizeOrder(order, Csr.build(certKey, names));
            AcmeClient.Order valid = client.awaitOrder(finalized, VALIDATION_TIMEOUT_MS);
            String pem = client.certificate(valid.certificate());
            List<X509Certificate> chain = Pem.certificates(pem);
            store(chain, certKey.getPrivate(), pem);
            tls.install(chain, certKey.getPrivate());
            LOG.info("certificate issued, valid until {}", chain.get(0).getNotAfter());
            onInstalled.run();
        } finally {
            dns.clearTxt();
        }
    }

    private void store(List<X509Certificate> chain, PrivateKey key, String pem) throws IOException {
        Path keyTmp = dir.resolve("wildcard.key.tmp");
        AcmeKeys.writePrivate(keyTmp, Pem.encodeBlock("PRIVATE KEY", key.getEncoded()));
        Path pemTmp = dir.resolve("wildcard.pem.tmp");
        Files.writeString(pemTmp, pem, StandardCharsets.UTF_8);
        Path oldKey = dir.resolve("wildcard.key.prev");
        if (Files.exists(dir.resolve("wildcard.key"))) {
            Files.move(dir.resolve("wildcard.key"), oldKey, StandardCopyOption.REPLACE_EXISTING);
        }
        Files.move(keyTmp, dir.resolve("wildcard.key"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        Files.move(pemTmp, dir.resolve("wildcard.pem"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private void renewLoop() {
        while (!closed) {
            try {
                Thread.sleep(RENEW_CHECK_MS);
                if (closed) {
                    return;
                }
                if (tls.isLoaded() && needsRenewal(tls.leaf())) {
                    LOG.info("renewing certificate ({} left)", tls.leaf().getNotAfter());
                    issueWithRetries();
                }
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    @Override
    public void close() {
        closed = true;
        if (renewer != null) {
            renewer.interrupt();
        }
    }
}
