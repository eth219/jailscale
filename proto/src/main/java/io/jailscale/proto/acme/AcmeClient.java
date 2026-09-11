package io.jailscale.proto.acme;

import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonException;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.HttpCall;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The subset of ACME v2 (RFC 8555) ARCHITECTURE.md §7.2 needs: account, order with dns-01, finalize,
 * download. JWS-signed POSTs, nonce tracking with one badNonce retry, problem documents as
 * {@link AcmeException}.
 */
public final class AcmeClient {

    private static final Log LOG = Log.get("acme");
    private static final int TIMEOUT_MS = 30_000;
    private static final int MAX_BODY = 1 << 20;

    public record Directory(String newNonce, String newAccount, String newOrder) {}

    public record Order(String url, String status, List<String> authorizations, String finalizeUrl, String certificate) {}

    public record Challenge(String authzUrl, String identifier, String url, String token, String status) {}

    private final URI directoryUrl;
    private final KeyPair account;
    private final String email;
    private final String userAgent;
    private Directory directory;
    private String kid;
    private String nonce;

    public AcmeClient(URI directoryUrl, KeyPair account, String email, String userAgent) {
        this.directoryUrl = directoryUrl;
        this.account = account;
        this.email = email;
        this.userAgent = userAgent;
    }

    public String thumbprint() throws GeneralSecurityException {
        return Jws.thumbprint((ECPublicKey) account.getPublic());
    }

    /** The http-01 response body: {@code token.thumbprint}. */
    public String keyAuthorization(String token) throws GeneralSecurityException {
        return token + "." + thumbprint();
    }

    /** TXT value for a dns-01 challenge token: base64url(SHA-256(keyAuthorization)). */
    public String dns01Value(String token) throws GeneralSecurityException {
        return Jws.b64(MessageDigest.getInstance("SHA-256").digest(keyAuthorization(token).getBytes(StandardCharsets.US_ASCII)));
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
        HttpResponse r = post(directory().newAccount(), body.toJson(), true);
        kid = r.headers().get("Location");
        if (kid == null) {
            throw new AcmeException("missing", r.status(), "newAccount without Location");
        }
        LOG.info("ACME account {}", kid);
        return kid;
    }

    public Order newOrder(List<String> dnsNames) throws AcmeException {
        List<Object> ids = new ArrayList<>();
        for (String n : dnsNames) {
            ids.add(JsonObject.builder().put("type", "dns").put("value", n).build().asMap());
        }
        HttpResponse r = post(directory().newOrder(), JsonObject.builder().put("identifiers", ids).toJson(), false);
        String url = r.headers().get("Location");
        if (url == null) {
            throw new AcmeException("missing", r.status(), "newOrder without Location");
        }
        return order(url, r.bodyText());
    }

    public Order order(String url) throws AcmeException {
        return order(url, postAsGet(url).bodyText());
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
        return challenge(authzUrl, "dns-01");
    }

    /** The http-01 challenge of an authorization (user domains, ARCHITECTURE.md §8.3). */
    public Challenge http01(String authzUrl) throws AcmeException {
        return challenge(authzUrl, "http-01");
    }

    private Challenge challenge(String authzUrl, String type) throws AcmeException {
        JsonObject a = Json.parseObject(postAsGet(authzUrl).body());
        String identifier = a.object("identifier").string("value");
        for (Object c : a.array("challenges")) {
            @SuppressWarnings("unchecked")
            JsonObject ch = Json.parseObject(Json.write((Map<String, Object>) c));
            if (type.equals(ch.string("type"))) {
                return new Challenge(authzUrl, identifier, ch.string("url"), ch.string("token"), ch.string("status"));
            }
        }
        throw new AcmeException("unsupported", 0, "authorization for " + identifier + " offers no " + type + " challenge");
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
        HttpResponse r = post(o.finalizeUrl(), JsonObject.builder().put("csr", Jws.b64(csrDer)).toJson(), false);
        return order(o.url(), r.bodyText());
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
        HttpResponse r = signed(url, "", false, "application/pem-certificate-chain");
        return r.bodyText();
    }

    // --- transport ---------------------------------------------------------------------------

    private HttpResponse get(URI uri) throws AcmeException {
        HttpResponse r = call("GET", uri, new Headers(), null);
        takeNonce(r);
        if (r.status() >= 400) {
            throw problem(r);
        }
        return r;
    }

    private HttpResponse call(String method, URI uri, Headers headers, byte[] body) throws AcmeException {
        headers.add("User-Agent", userAgent);
        try {
            return HttpCall.send(method, uri, headers, body, TIMEOUT_MS, MAX_BODY);
        } catch (IOException | HttpException e) {
            throw new AcmeException(method + " " + uri + " failed: " + e.getMessage(), e);
        }
    }

    private String freshNonce() throws AcmeException {
        if (nonce != null) {
            String n = nonce;
            nonce = null;
            return n;
        }
        HttpResponse r = call("HEAD", URI.create(directory().newNonce()), new Headers(), null);
        String n = r.headers().get("Replay-Nonce");
        if (n == null) {
            throw new AcmeException("nonce", r.status(), "no Replay-Nonce");
        }
        return n;
    }

    private void takeNonce(HttpResponse r) {
        String n = r.headers().get("Replay-Nonce");
        if (n != null) {
            nonce = n;
        }
    }

    private HttpResponse postAsGet(String url) throws AcmeException {
        return signed(url, "", false, "application/json");
    }

    private HttpResponse post(String url, String payload, boolean withJwk) throws AcmeException {
        return signed(url, payload, withJwk, "application/json");
    }

    private HttpResponse signed(String url, String payload, boolean withJwk, String accept) throws AcmeException {
        for (int attempt = 0; ; attempt++) {
            String n = freshNonce();
            String body;
            try {
                body = Jws.sign(account, url, n, withJwk ? null : account(), payload);
            } catch (GeneralSecurityException e) {
                throw new AcmeException("signing failed", e);
            }
            HttpResponse r = call("POST", URI.create(url), new Headers().add("Content-Type", "application/jose+json").add("Accept", accept),
                body.getBytes(StandardCharsets.UTF_8));
            takeNonce(r);
            if (r.status() >= 400) {
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

    private static AcmeException problem(HttpResponse r) {
        try {
            JsonObject p = Json.parseObject(r.bodyText());
            return new AcmeException(p.optString("type", "unknown"), r.status(), p.optString("detail", r.bodyText()));
        } catch (RuntimeException e) {
            return new AcmeException("http", r.status(), "HTTP " + r.status() + ": " + r.bodyText());
        }
    }
}
