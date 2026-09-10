package io.jailscale.hub.acme;

import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonException;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The subset of ACME v2 (RFC 8555) DESIGN.md §6.3 needs: account, order with dns-01, finalize,
 * download. JWS-signed POSTs, nonce tracking with one badNonce retry, problem documents as
 * {@link AcmeException}.
 */
public final class AcmeClient {

    private static final Log LOG = Log.get("acme");
    private static final Duration TIMEOUT = Duration.ofSeconds(30);

    public record Directory(String newNonce, String newAccount, String newOrder) {}

    public record Order(String url, String status, List<String> authorizations, String finalizeUrl, String certificate) {}

    public record Challenge(String authzUrl, String identifier, String url, String token, String status) {}

    private final HttpClient http;
    private final URI directoryUrl;
    private final KeyPair account;
    private final String email;
    private final String userAgent;
    private Directory directory;
    private String kid;
    private String nonce;

    public AcmeClient(URI directoryUrl, KeyPair account, String email, String userAgent) {
        this.http = HttpClient.newBuilder().connectTimeout(TIMEOUT).followRedirects(HttpClient.Redirect.NEVER).build();
        this.directoryUrl = directoryUrl;
        this.account = account;
        this.email = email;
        this.userAgent = userAgent;
    }

    public String thumbprint() throws GeneralSecurityException {
        return Jws.thumbprint((ECPublicKey) account.getPublic());
    }

    /** TXT value for a dns-01 challenge token: base64url(SHA-256(keyAuthorization)). */
    public String dns01Value(String token) throws GeneralSecurityException {
        String keyAuth = token + "." + thumbprint();
        return Jws.b64(MessageDigest.getInstance("SHA-256").digest(keyAuth.getBytes(StandardCharsets.US_ASCII)));
    }

    public Directory directory() throws AcmeException {
        if (directory == null) {
            JsonObject d = Json.parseObject(get(directoryUrl).body());
            directory = new Directory(d.string("newNonce"), d.string("newAccount"), d.string("newOrder"));
        }
        return directory;
    }

    /** Creates the account or finds the existing one for this key; returns its URL (the kid). */
    public String account() throws AcmeException {
        if (kid != null) {
            return kid;
        }
        JsonObject.Builder body = JsonObject.builder().put("termsOfServiceAgreed", true);
        if (email != null && !email.isBlank()) {
            body.put("contact", List.of("mailto:" + email));
        }
        HttpResponse<String> r = post(directory().newAccount(), body.toJson(), true);
        kid = r.headers().firstValue("Location").orElseThrow(() -> new AcmeException("missing", r.statusCode(), "newAccount without Location"));
        LOG.info("ACME account {}", kid);
        return kid;
    }

    public Order newOrder(List<String> dnsNames) throws AcmeException {
        List<Object> ids = new ArrayList<>();
        for (String n : dnsNames) {
            ids.add(JsonObject.builder().put("type", "dns").put("value", n).build().asMap());
        }
        HttpResponse<String> r = post(directory().newOrder(), JsonObject.builder().put("identifiers", ids).toJson(), false);
        String url = r.headers().firstValue("Location").orElseThrow(() -> new AcmeException("missing", r.statusCode(), "newOrder without Location"));
        return order(url, r.body());
    }

    public Order order(String url) throws AcmeException {
        return order(url, postAsGet(url).body());
    }

    private static Order order(String url, String body) throws AcmeException {
        try {
            JsonObject o = Json.parseObject(body);
            return new Order(url, o.string("status"), o.stringArray("authorizations"), o.string("finalize"),
                o.optString("certificate", null));
        } catch (JsonException e) {
            throw new AcmeException("bad order object: " + e.getMessage(), e);
        }
    }

    /** The dns-01 challenge of an authorization. */
    public Challenge dns01(String authzUrl) throws AcmeException {
        JsonObject a = Json.parseObject(postAsGet(authzUrl).body());
        String identifier = a.object("identifier").string("value");
        for (Object c : a.array("challenges")) {
            @SuppressWarnings("unchecked")
            JsonObject ch = Json.parseObject(Json.write((Map<String, Object>) c));
            if ("dns-01".equals(ch.string("type"))) {
                return new Challenge(authzUrl, identifier, ch.string("url"), ch.string("token"), ch.string("status"));
            }
        }
        throw new AcmeException("unsupported", 0, "authorization for " + identifier + " offers no dns-01 challenge");
    }

    /** Tells the CA the challenge is ready to be validated. */
    public void respond(Challenge c) throws AcmeException {
        post(c.url(), "{}", false);
    }

    /** Polls an authorization until it leaves "pending"; returns the final status. */
    public String awaitAuthorization(String authzUrl, long timeoutMs) throws AcmeException, InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (true) {
            JsonObject a = Json.parseObject(postAsGet(authzUrl).body());
            String status = a.string("status");
            if (!status.equals("pending") && !status.equals("processing")) {
                if (!status.equals("valid")) {
                    String detail = errorDetail(a);
                    throw new AcmeException("authorization", 0, "authorization " + status + (detail == null ? "" : ": " + detail));
                }
                return status;
            }
            if (System.currentTimeMillis() > deadline) {
                throw new AcmeException("timeout", 0, "authorization still " + status + " after " + timeoutMs / 1000 + "s");
            }
            Thread.sleep(2000);
        }
    }

    private static String errorDetail(JsonObject authz) {
        for (Object c : authz.array("challenges")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) c;
            Object err = m.get("error");
            if (err instanceof Map<?, ?> em && em.get("detail") != null) {
                return String.valueOf(em.get("detail"));
            }
        }
        return null;
    }

    public Order finalizeOrder(Order o, byte[] csrDer) throws AcmeException {
        HttpResponse<String> r = post(o.finalizeUrl(), JsonObject.builder().put("csr", Jws.b64(csrDer)).toJson(), false);
        return order(o.url(), r.body());
    }

    /** Polls the order until valid; returns it with the certificate URL. */
    public Order awaitOrder(Order o, long timeoutMs) throws AcmeException, InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        Order cur = o;
        while (!cur.status().equals("valid")) {
            if (cur.status().equals("invalid")) {
                throw new AcmeException("order", 0, "order became invalid");
            }
            if (System.currentTimeMillis() > deadline) {
                throw new AcmeException("timeout", 0, "order still " + cur.status());
            }
            Thread.sleep(2000);
            cur = order(o.url());
        }
        return cur;
    }

    /** Downloads the certificate chain as PEM. */
    public String certificate(String url) throws AcmeException {
        HttpResponse<String> r = signed(url, "", false, "application/pem-certificate-chain");
        return r.body();
    }

    // --- transport ---------------------------------------------------------------------------

    private HttpResponse<String> get(URI uri) throws AcmeException {
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(uri).timeout(TIMEOUT).header("User-Agent", userAgent).GET().build(),
                HttpResponse.BodyHandlers.ofString());
            takeNonce(r);
            if (r.statusCode() >= 400) {
                throw problem(r);
            }
            return r;
        } catch (IOException | InterruptedException e) {
            throw new AcmeException("GET " + uri + " failed: " + e.getMessage(), e);
        }
    }

    private String freshNonce() throws AcmeException {
        if (nonce != null) {
            String n = nonce;
            nonce = null;
            return n;
        }
        try {
            HttpResponse<Void> r = http.send(HttpRequest.newBuilder(URI.create(directory().newNonce())).timeout(TIMEOUT)
                .header("User-Agent", userAgent).method("HEAD", HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.discarding());
            return r.headers().firstValue("Replay-Nonce").orElseThrow(() -> new AcmeException("nonce", r.statusCode(), "no Replay-Nonce"));
        } catch (IOException | InterruptedException e) {
            throw new AcmeException("newNonce failed: " + e.getMessage(), e);
        }
    }

    private void takeNonce(HttpResponse<?> r) {
        r.headers().firstValue("Replay-Nonce").ifPresent(n -> nonce = n);
    }

    private HttpResponse<String> postAsGet(String url) throws AcmeException {
        return signed(url, "", false, "application/json");
    }

    private HttpResponse<String> post(String url, String payload, boolean withJwk) throws AcmeException {
        return signed(url, payload, withJwk, "application/json");
    }

    private HttpResponse<String> signed(String url, String payload, boolean withJwk, String accept) throws AcmeException {
        for (int attempt = 0; ; attempt++) {
            String n = freshNonce();
            String body;
            try {
                body = Jws.sign(account, url, n, withJwk ? null : account(), payload);
            } catch (GeneralSecurityException e) {
                throw new AcmeException("signing failed", e);
            }
            HttpResponse<String> r;
            try {
                r = http.send(HttpRequest.newBuilder(URI.create(url)).timeout(TIMEOUT)
                    .header("Content-Type", "application/jose+json").header("Accept", accept).header("User-Agent", userAgent)
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
            } catch (IOException | InterruptedException e) {
                throw new AcmeException("POST " + url + " failed: " + e.getMessage(), e);
            }
            takeNonce(r);
            if (r.statusCode() >= 400) {
                AcmeException p = problem(r);
                if (p.isBadNonce() && attempt == 0) {
                    LOG.debug("bad nonce, retrying");
                    continue;
                }
                throw p;
            }
            return r;
        }
    }

    private static AcmeException problem(HttpResponse<String> r) {
        try {
            JsonObject p = Json.parseObject(r.body());
            return new AcmeException(p.optString("type", "unknown"), r.statusCode(), p.optString("detail", r.body()));
        } catch (RuntimeException e) {
            return new AcmeException("http", r.statusCode(), "HTTP " + r.statusCode() + ": " + r.body());
        }
    }
}
