package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.jailscale.proto.acme.Der;
import io.jailscale.proto.acme.Jws;
import io.jailscale.hub.dns.DnsQuery;
import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.IntSupplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The whole certificate loop offline: the hub, configured with no certificate, talks ACME to a
 * mock CA in this test, which validates dns-01 by querying the hub's own DNS responder, then
 * signs the hub's CSR with the test CA key. A node then publishes a link and a visitor who
 * trusts the test CA reaches it through the issued wildcard certificate.
 */
@Timeout(120)
class AcmeFlowTest {

    private static final Path CA_CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path CA_KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private MockCa ca;
    private final List<Daemon> daemons = new ArrayList<>();
    private ServerSocket localApp;

    @AfterEach
    void stop() throws Exception {
        for (Daemon d : daemons) {
            d.close();
        }
        if (localApp != null) {
            localApp.close();
        }
        if (hub != null) {
            hub.close();
        }
        if (ca != null) {
            ca.close();
        }
    }

    @Test
    void hubObtainsWildcardCertificateAndServesALink() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = Files.createTempDirectory(Path.of("/tmp"), "ja");
        int port;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        Hub[] hubRef = new Hub[1];
        ca = new MockCa(() -> hubRef[0].dnsPort());
        HubConfig cfg = new HubConfig(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            null, null, true, HubConfig.POLICY_MEMBERS, true, "hub.test",
            URI.create("http://127.0.0.1:" + ca.port() + "/directory"), "ops@hub.test", "127.0.0.1", 0, false, 0, 0, null, -1, null, false, List.of());
        hub = new Hub(cfg);
        hubRef[0] = hub;
        hub.start(); // issues the certificate through the mock CA before listening

        assertTrue(hub.tls().isLoaded());
        X509Certificate leaf = hub.tls().leaf();
        assertEquals("CN=hub.test", leaf.getSubjectX500Principal().getName());
        assertTrue(Files.exists(root.resolve("hub/tls/wildcard.pem")));
        assertTrue(Files.exists(root.resolve("hub/tls/account.key")));
        assertEquals(1, ca.orders);
        assertTrue(ca.validatedNames.contains("hub.test") && ca.validatedNames.contains("*.hub.test"), ca.validatedNames.toString());

        // A local app, a node, a link, a visitor trusting only the test CA.
        localApp = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            while (!localApp.isClosed()) {
                try (Socket c = localApp.accept()) {
                    HttpRequest r = Http.readRequest(c.getInputStream(), 4096);
                    HttpResponse.text(200, "ok " + r.path()).writeTo(c.getOutputStream());
                } catch (Exception e) {
                    return;
                }
            }
        });
        Daemon alice = new Daemon(NodeConfig.in(root.resolve("alice")));
        alice.start();
        daemons.add(alice);
        JsonObject up = Ipc.call(root.resolve("alice/jailscale.sock"), JsonObject.builder().put("cmd", "up").put("hub", "hub.test")
            .put("addr", "127.0.0.1").put("port", port).put("user", "alice").put("caFile", CA_CERT.toString()).build());
        assertTrue(up.optBool("ok", false), up.toString());
        long deadline = System.currentTimeMillis() + 10_000;
        while (!alice.hasCert(hub.tls().keyId()) && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        JsonObject open = Ipc.call(root.resolve("alice/jailscale.sock"), JsonObject.builder().put("cmd", "open")
            .put("port", localApp.getLocalPort()).put("name", "issued").build());
        assertTrue(open.optBool("ok", false), open.toString());

        SSLContext visitor = Tls.clientContext(CA_CERT, false);
        try (SSLSocket s = Tls.connect(visitor, "issued.hub.test", "127.0.0.1", port, true, 10_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", "issued.hub.test", "/via-acme", null, null);
            HttpResponse r = Http.readResponse(s.getInputStream(), 4096);
            assertEquals(200, r.status());
            assertEquals("ok /via-acme", r.bodyText());
        }

        // Restart: the stored certificate is fresh, so no new order is placed.
        hub.close();
        hub = new Hub(cfg);
        hubRef[0] = hub;
        hub.start();
        assertEquals(1, ca.orders);
        assertEquals(leaf.getSerialNumber(), hub.tls().leaf().getSerialNumber());
    }

    // ---------------------------------------------------------------------------------------------

    /**
     * Just enough of an ACME v2 CA: JWS verified, dns-01 checked against the hub's DNS or http-01
     * fetched from the hub's port 80, real X.509 issued for the order's names.
     */
    static final class MockCa implements AutoCloseable {
        final HttpServer server;
        final IntSupplier dnsPort;
        volatile IntSupplier httpPort = () -> -1;
        final Map<String, PublicKey> accounts = new ConcurrentHashMap<>();
        final Map<String, String> tokens = new ConcurrentHashMap<>();       // authz id -> token
        final Map<String, String> authzStatus = new ConcurrentHashMap<>();
        final Map<String, String> authzName = new ConcurrentHashMap<>();
        final List<String> validatedNames = new ArrayList<>();
        volatile String certPem;
        volatile int orders;
        final PrivateKey caKey;
        final X509Certificate caCert;
        final String base;

        MockCa(IntSupplier dnsPort) throws Exception {
            this.dnsPort = dnsPort;
            this.caKey = Pem.privateKey(Files.readString(CA_KEY));
            this.caCert = Pem.certificates(Files.readString(CA_CERT)).get(0);
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 8);
            base = "http://127.0.0.1:" + server.getAddress().getPort();
            server.createContext("/", this::handle);
            server.start();
        }

        int port() {
            return server.getAddress().getPort();
        }

        private void handle(HttpExchange ex) throws IOException {
            try {
                String path = ex.getRequestURI().getPath();
                ex.getResponseHeaders().add("Replay-Nonce", Long.toHexString(new SecureRandom().nextLong()));
                if (path.equals("/directory")) {
                    reply(ex, 200, JsonObject.builder().put("newNonce", base + "/new-nonce").put("newAccount", base + "/new-account")
                        .put("newOrder", base + "/new-order").toJson());
                    return;
                }
                if (path.equals("/new-nonce")) {
                    ex.sendResponseHeaders(200, -1);
                    return;
                }
                JsonObject jws = Json.parseObject(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                JsonObject header = Json.parseObject(new String(Base64.getUrlDecoder().decode(jws.string("protected")), StandardCharsets.UTF_8));
                assertEquals(base + path, header.string("url"));
                assertTrue(header.has("nonce"));
                PublicKey key = header.has("jwk") ? fromJwk(header.object("jwk")) : accounts.get(header.string("kid"));
                Signature v = Signature.getInstance("SHA256withECDSA");
                v.initVerify(key);
                v.update((jws.string("protected") + "." + jws.string("payload")).getBytes(StandardCharsets.US_ASCII));
                assertTrue(v.verify(Jws.rawToDer(Base64.getUrlDecoder().decode(jws.string("signature")))), "bad JWS signature");
                String payload = jws.string("payload").isEmpty() ? "" : new String(Base64.getUrlDecoder().decode(jws.string("payload")), StandardCharsets.UTF_8);

                switch (path) {
                    case "/new-account" -> {
                        String kid = base + "/acct/1";
                        accounts.put(kid, key);
                        ex.getResponseHeaders().add("Location", kid);
                        reply(ex, 201, "{\"status\":\"valid\"}");
                    }
                    case "/new-order" -> {
                        JsonObject o = Json.parseObject(payload);
                        List<Object> authzs = new ArrayList<>();
                        int i = 0;
                        for (Object id : o.array("identifiers")) {
                            @SuppressWarnings("unchecked")
                            String name = String.valueOf(((Map<String, Object>) id).get("value"));
                            String aid = "a" + (++i);
                            authzName.put(aid, name);
                            authzStatus.put(aid, "pending");
                            tokens.put(aid, Jws.b64(("tok-" + name).getBytes(StandardCharsets.UTF_8)));
                            authzs.add(base + "/authz/" + aid);
                        }
                        orders++;
                        ex.getResponseHeaders().add("Location", base + "/order/1");
                        reply(ex, 201, orderJson("pending", authzs));
                    }
                    case "/order/1" -> reply(ex, 200, orderJson(certPem == null ? "pending" : "valid", List.of()));
                    case "/finalize/1" -> {
                        JsonObject o = Json.parseObject(payload);
                        byte[] csr = Base64.getUrlDecoder().decode(o.string("csr"));
                        for (String st : authzStatus.values()) {
                            assertEquals("valid", st, "finalize before validation");
                        }
                        certPem = issue(csr);
                        reply(ex, 200, orderJson("valid", List.of()));
                    }
                    case "/cert/1" -> reply(ex, 200, certPem);
                    default -> {
                        if (path.startsWith("/authz/")) {
                            String aid = path.substring("/authz/".length());
                            reply(ex, 200, JsonObject.builder()
                                .put("status", authzStatus.get(aid))
                                .put("identifier", JsonObject.builder().put("type", "dns").put("value", authzName.get(aid)).build())
                                .put("challenges", List.of(
                                    JsonObject.builder().put("type", "dns-01").put("url", base + "/chall/" + aid)
                                        .put("token", tokens.get(aid)).put("status", authzStatus.get(aid)).build().asMap(),
                                    JsonObject.builder().put("type", "http-01").put("url", base + "/httpchall/" + aid)
                                        .put("token", tokens.get(aid)).put("status", authzStatus.get(aid)).build().asMap()))
                                .toJson());
                        } else if (path.startsWith("/httpchall/")) {
                            String aid = path.substring("/httpchall/".length());
                            // http-01 validation: GET http://<name>/.well-known/acme-challenge/<token>, served by the hub's port 80
                            String keyAuth = tokens.get(aid) + "." + Jws.thumbprint((java.security.interfaces.ECPublicKey) key);
                            String got = null;
                            try (Socket c = new Socket("127.0.0.1", httpPort.getAsInt())) {
                                c.setSoTimeout(3000);
                                Http.writeRequest(c.getOutputStream(), "GET", authzName.get(aid), "/.well-known/acme-challenge/" + tokens.get(aid),
                                    new io.jailscale.proto.http.Headers(), null);
                                HttpResponse r = Http.readResponse(c.getInputStream(), 4096);
                                if (r.status() == 200) {
                                    got = r.bodyText();
                                }
                            } catch (IOException e) {
                                got = null;
                            }
                            if (keyAuth.equals(got)) {
                                authzStatus.put(aid, "valid");
                                validatedNames.add(authzName.get(aid));
                            } else {
                                authzStatus.put(aid, "invalid");
                            }
                            reply(ex, 200, "{\"status\":\"" + authzStatus.get(aid) + "\"}");
                        } else if (path.startsWith("/chall/")) {
                            String aid = path.substring("/chall/".length());
                            // dns-01 validation against the hub's DNS responder
                            String keyAuth = tokens.get(aid) + "." + Jws.thumbprint((java.security.interfaces.ECPublicKey) key);
                            String expected = Jws.b64(MessageDigest.getInstance("SHA-256").digest(keyAuth.getBytes(StandardCharsets.US_ASCII)));
                            List<String> txt = DnsQuery.txt("127.0.0.1", dnsPort.getAsInt(), "_acme-challenge.hub.test", 3000);
                            if (txt.contains(expected)) {
                                authzStatus.put(aid, "valid");
                                validatedNames.add(authzName.get(aid));
                            } else {
                                authzStatus.put(aid, "invalid");
                            }
                            reply(ex, 200, "{\"status\":\"" + authzStatus.get(aid) + "\"}");
                        } else {
                            reply(ex, 404, "{\"type\":\"urn:ietf:params:acme:error:malformed\",\"detail\":\"no such path\"}");
                        }
                    }
                }
            } catch (Exception e) {
                reply(ex, 500, "{\"type\":\"urn:ietf:params:acme:error:serverInternal\",\"detail\":\"" + e + "\"}");
            }
        }

        private String orderJson(String status, List<Object> authzs) {
            JsonObject.Builder b = JsonObject.builder().put("status", status).put("finalize", base + "/finalize/1")
                .put("authorizations", authzs.isEmpty() ? List.of(base + "/authz/a1", base + "/authz/a2") : authzs);
            if (status.equals("valid")) {
                b.put("certificate", base + "/cert/1");
            }
            return b.toJson();
        }

        private static void reply(HttpExchange ex, int status, String body) throws IOException {
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(status, b.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(b);
            }
        }

        private static PublicKey fromJwk(JsonObject jwk) throws Exception {
            BigInteger x = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.string("x")));
            BigInteger y = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.string("y")));
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
            params.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y),
                params.getParameterSpec(java.security.spec.ECParameterSpec.class)));
        }

        /** Signs an X.509 v3 certificate for the CSR's public key with the test CA (leaf + CA chain PEM). */
        private String issue(byte[] csr) throws Exception {
            byte[] spki = spkiOf(csr);
            KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki)); // sanity: parses
            DateTimeFormatter utc = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'");
            ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(5);
            byte[] validity = Der.sequence(Der.tlv(0x17, utc.format(now).getBytes(StandardCharsets.US_ASCII)),
                Der.tlv(0x17, utc.format(now.plusDays(90)).getBytes(StandardCharsets.US_ASCII)));
            List<String> names = new ArrayList<>(new java.util.TreeSet<>(authzName.values()));
            names.sort(java.util.Comparator.comparing((String n) -> n.startsWith("*")).thenComparing(n -> n)); // CN = the plain name
            byte[] subject = Der.sequence(Der.set(Der.sequence(Der.oid("2.5.4.3"), Der.utf8(names.get(0)))));
            byte[][] sanEntries = new byte[names.size()][];
            for (int i = 0; i < names.size(); i++) {
                sanEntries[i] = Der.context(2, false, names.get(i).getBytes(StandardCharsets.US_ASCII));
            }
            byte[] san = Der.sequence(sanEntries);
            byte[] extensions = Der.context(3, true, Der.sequence(Der.sequence(Der.oid("2.5.29.17"), Der.octetString(san))));
            byte[] sigAlg = Der.sequence(Der.oid("1.2.840.10045.4.3.2"));
            byte[] tbs = Der.sequence(
                Der.context(0, true, Der.integer(2)),
                Der.integer(new BigInteger(63, new SecureRandom())),
                sigAlg,
                caCert.getSubjectX500Principal().getEncoded(),
                validity,
                subject,
                spki,
                extensions);
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(caKey);
            s.update(tbs);
            byte[] cert = Der.sequence(tbs, sigAlg, Der.bitString(s.sign()));
            return Pem.encodeBlock("CERTIFICATE", cert) + Pem.encode(caCert);
        }

        /** CertificationRequest → CertificationRequestInfo → [version, subject, SPKI]. */
        private static byte[] spkiOf(byte[] csr) {
            int[] outer = tlv(csr, 0);             // CertificationRequest
            int[] info = tlv(csr, outer[2]);       // CertificationRequestInfo
            int p = info[2];
            int[] version = tlv(csr, p);
            p = version[2] + version[1];
            int[] subject = tlv(csr, p);
            p = subject[2] + subject[1];
            int[] spki = tlv(csr, p);
            return java.util.Arrays.copyOfRange(csr, p, spki[2] + spki[1]);
        }

        /** Returns {tag, length, contentOffset} of the TLV at {@code off}. */
        private static int[] tlv(byte[] b, int off) {
            int tag = b[off] & 0xff;
            int len = b[off + 1] & 0xff;
            int p = off + 2;
            if ((len & 0x80) != 0) {
                int n = len & 0x7f;
                len = 0;
                for (int i = 0; i < n; i++) {
                    len = (len << 8) | (b[p++] & 0xff);
                }
            }
            return new int[] {tag, len, p};
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
