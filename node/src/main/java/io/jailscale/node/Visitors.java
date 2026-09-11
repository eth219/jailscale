package io.jailscale.node;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.net.ProxyProtocol;
import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import io.jailscale.proto.mux.Frame;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.security.KeyStore;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 * Visitor streams on the node (ARCHITECTURE.md §9.2, §9.3): terminate TLS with the hub's
 * certificate and a remote key, connect to the local target, copy bytes both ways.
 */
final class Visitors {

    private static final Log LOG = Log.get("visitor");
    private static final int LOCAL_CONNECT_TIMEOUT_MS = 5_000;
    static final long UDP_IDLE_MS = 60_000;

    private final NodeState state;
    private final SelfProbe probe = new SelfProbe();
    private final Map<String, SSLContext> contexts = new ConcurrentHashMap<>();
    private final Map<String, SSLContext> domainContexts = new ConcurrentHashMap<>();

    Visitors(NodeState state) {
        this.state = state;
        RemoteSigning.install();
    }

    /** Builds the SSLContext for a certificate the hub sent. */
    void onCert(Message.CertUpdate cert) {
        try {
            StringBuilder pem = new StringBuilder();
            for (String p : cert.chainPem()) {
                pem.append(p);
            }
            List<X509Certificate> chain = Pem.certificates(pem.toString());
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(new KeyManager[] {new RemoteSigning.RemoteKeyManager(chain, cert.keyId())}, null, RemoteSigning.RANDOM);
            contexts.put(cert.keyId(), ctx);
            if (contexts.size() > 3) {
                contexts.keySet().stream().filter(k -> !k.equals(cert.keyId())).findFirst().ifPresent(contexts::remove);
            }
            LOG.info("certificate {} installed ({} until {})", cert.keyId(), chain.get(0).getSubjectX500Principal(),
                chain.get(0).getNotAfter());
        } catch (GeneralSecurityException e) {
            LOG.warn("bad certificate from hub", e);
        }
    }

    boolean hasCert(String keyId) {
        return contexts.containsKey(keyId);
    }

    /** ARCHITECTURE.md §9.2: a user domain terminates with the node's real key under keyId {@code domain:<name>}. */
    void installDomain(DomainCerts.Material m) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        char[] pw = new char[0];
        ks.setKeyEntry("domain", m.key(), pw, m.chain().toArray(new X509Certificate[0]));
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pw);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        domainContexts.put("domain:" + m.domain(), ctx);
    }

    SelfProbe probe() {
        return probe;
    }

    void removeDomain(String domain) {
        domainContexts.remove("domain:" + domain);
    }

    /** Serves one visitor stream to completion on the calling (virtual) thread. */
    void serve(HubLink link, HubLink.Session session, MuxStream stream) {
        int conn = session.conn;
        String linkId = stream.meta().optString("linkId", null);
        String kind = stream.meta().optString("kind", Message.LinkOpen.HTTPS);
        if (!Message.LinkOpen.HTTPS.equals(kind)) {
            serveRaw(kind, stream, state.linkById(linkId));
            return;
        }
        byte[] proxyLine = proxyLine(stream, state.linkById(linkId));
        String keyId = stream.meta().optString("keyId", null);
        String sni = stream.meta().optString("sni", "?");
        NodeState.LinkRec target = state.linkById(linkId);
        SSLContext ctx = keyId == null ? null : keyId.startsWith("domain:") ? domainContexts.get(keyId) : contexts.get(keyId);
        if (target == null || ctx == null) {
            LOG.warn("visitor for {} refused: {}", sni, target == null ? "unknown link" : "no certificate " + keyId);
            stream.reset(4);
            return;
        }
        TlsEndpoint tls = new TlsEndpoint(ctx, stream.in(), stream.out());
        try {
            // Remember that this node, and not the hub or another node, terminated it (§11.3).
            // Not after handshake(): on the server side of TLS 1.3 the exporter is not usable
            // until the peer's Finished has been processed, and that has not necessarily happened
            // when the handshake loop returns. Recording nothing would later read as a compromised
            // hub, so this waits for the first application bytes instead.
            tls.onFirstApplicationRead(() -> probe.record(SelfProbe.material(tls.session())));
            RemoteSigning.enter(new RemoteSigning.Context(link, session, HubLink.fullStreamId(conn, stream.id()), keyId, tls));
            try {
                tls.handshake();
            } finally {
                RemoteSigning.exit();
            }
        } catch (IOException e) {
            LOG.debug("TLS handshake for {} failed: {}", sni, e.getMessage());
            stream.reset(5);
            return;
        }
        byte[] replay = null;
        if (target.gateHash != null) {
            try {
                boolean expired = target.gateExpiresAt > 0 && System.currentTimeMillis() > target.gateExpiresAt;
                Gate.Decision d = Gate.decide(tls.plainIn(), target.gateHash, expired);
                switch (d) {
                    case Gate.Decision.Pass p -> replay = p.head();
                    case Gate.Decision.SetCookie sc -> {
                        HttpResponse.redirect(sc.location())
                            .header("Set-Cookie", Gate.COOKIE + "=" + sc.token() + "; Path=/; Secure; HttpOnly; SameSite=Lax")
                            .writeTo(tls.plainOut());
                        tls.close();
                        stream.close();
                        return;
                    }
                    case Gate.Decision.Refuse r -> {
                        HttpResponse.html(403, "<!doctype html><meta charset=utf-8><title>jailscale</title>"
                            + "<p>This link needs a visit link to open.</p>").writeTo(tls.plainOut());
                        tls.close();
                        stream.close();
                        return;
                    }
                }
            } catch (IOException e) {
                stream.reset(6);
                return;
            }
        }
        Socket local;
        try {
            local = connectLocal(target);
        } catch (IOException e) {
            LOG.warn("{}: local target {}:{} unreachable: {}", sni, target.host(), target.port(), e.getMessage());
            badGateway(tls, target);
            try {
                stream.close();
            } catch (IOException ignored) {
                // closing
            }
            return;
        }
        relay(tls, local, stream, concat(proxyLine, replay));
    }

    /** ARCHITECTURE.md §9.3: {@code --proxy-protocol} tells the local app who the visitor is, HAProxy style. */
    private static byte[] proxyLine(MuxStream stream, NodeState.LinkRec target) {
        if (target == null || !target.proxyProtocol) {
            return null;
        }
        String ip = stream.meta().optString("visitorAddr", "0.0.0.0");
        int port = stream.meta().optInt("visitorPort", 0);
        return ProxyProtocol.v1Line(ip, port, target.host(), target.port()).getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** ARCHITECTURE.md §8.4 / §9.3: raw TCP copies bytes; raw UDP maps one DGRAM stream to one local socket. */
    private static void serveRaw(String kind, MuxStream stream, NodeState.LinkRec target) {
        if (target == null || !target.kind.equals(kind)) {
            LOG.warn("{} visitor refused: unknown link", kind);
            stream.reset(4);
            return;
        }
        if (Message.LinkOpen.UDP.equals(kind) && stream.isDatagram()) {
            serveUdp(stream, target);
            return;
        }
        Socket local;
        try {
            local = connectLocal(target);
        } catch (IOException e) {
            LOG.warn("tcp: local target {}:{} unreachable: {}", target.host(), target.port(), e.getMessage());
            stream.reset(7);
            return;
        }
        byte[] proxyLine = proxyLine(stream, target);
        Thread toLocal = Thread.ofVirtual().name("raw-in").start(() -> {
            try {
                if (proxyLine != null) {
                    local.getOutputStream().write(proxyLine);
                }
                copy(stream.in(), local.getOutputStream());
                local.shutdownOutput();
            } catch (IOException e) {
                closeQuietly(local);
            }
        });
        try {
            copy(local.getInputStream(), stream.out());
            stream.close();
        } catch (IOException e) {
            stream.reset(1);
        } finally {
            closeQuietly(local);
        }
        try {
            toLocal.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void serveUdp(MuxStream stream, NodeState.LinkRec target) {
        DatagramSocket local;
        try {
            local = new DatagramSocket();
            local.connect(InetAddress.getByName(target.host()), target.port());
            local.setSoTimeout((int) UDP_IDLE_MS);
        } catch (IOException e) {
            LOG.warn("udp: local target {}:{} unusable: {}", target.host(), target.port(), e.getMessage());
            stream.reset(7);
            return;
        }
        Thread back = Thread.ofVirtual().name("raw-udp-back").start(() -> {
            byte[] buf = new byte[Frame.MAX_DATA];
            try {
                while (true) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    local.receive(p);
                    stream.send(java.util.Arrays.copyOf(p.getData(), p.getLength()));
                }
            } catch (IOException e) {
                // idle timeout, stream reset or socket closed: the flow is over
                stream.reset(0);
            }
        });
        try {
            byte[] d;
            while ((d = stream.receive()) != null) {
                local.send(new DatagramPacket(d, d.length));
            }
        } catch (IOException e) {
            LOG.debug("udp flow to {}:{} ended: {}", target.host(), target.port(), e.getMessage());
            stream.reset(1);
        } finally {
            local.close();
        }
        try {
            back.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Connects to the local target. A burst of visitors can overflow a small listen backlog
     * (macOS defaults to 128), which shows up as an immediate refusal or reset; a few short
     * retries (up to ~1.5 s) turn that into a served request instead of a 502.
     */
    private static Socket connectLocal(NodeState.LinkRec target) throws IOException {
        IOException last = null;
        for (int attempt = 0; attempt < 5; attempt++) {
            Socket s = new Socket();
            try {
                s.connect(new InetSocketAddress(target.host(), target.port()), LOCAL_CONNECT_TIMEOUT_MS);
                s.setTcpNoDelay(true);
                return s;
            } catch (java.net.SocketTimeoutException e) {
                closeQuietly(s);
                throw e;
            } catch (java.net.SocketException e) { // refused or reset: the listener's backlog is full
                last = e;
                closeQuietly(s);
                try {
                    Thread.sleep(50L << attempt);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            } catch (IOException e) {
                closeQuietly(s);
                throw e;
            }
        }
        throw last;
    }

    private static void relay(TlsEndpoint tls, Socket local, MuxStream stream, byte[] replay) {
        Thread toLocal = Thread.ofVirtual().name("visitor-in").start(() -> {
            try {
                if (replay != null) {
                    local.getOutputStream().write(replay);
                    local.getOutputStream().flush();
                }
                copy(tls.plainIn(), local.getOutputStream());
                local.shutdownOutput();
            } catch (IOException e) {
                closeQuietly(local);
            }
        });
        try {
            copy(local.getInputStream(), tls.plainOut());
            tls.close();
            stream.close();
        } catch (IOException e) {
            stream.reset(1);
        } finally {
            closeQuietly(local);
        }
        try {
            toLocal.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void badGateway(TlsEndpoint tls, NodeState.LinkRec target) {
        try {
            // Consume the request head so the browser sees a clean response, then answer.
            InputStream in = tls.plainIn();
            byte[] buf = new byte[4096];
            int n = in.read(buf);
            if (n < 0) {
                return;
            }
            HttpResponse.html(502, "<!doctype html><meta charset=utf-8><title>jailscale</title>"
                + "<p>The node cannot reach <b>" + target.host() + ":" + target.port() + "</b>.</p>")
                .writeTo(tls.plainOut());
            tls.close();
        } catch (IOException ignored) {
            // visitor gone
        }
    }

    static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[16 * 1024];
        int n;
        while ((n = in.read(buf)) >= 0) {
            if (n > 0) {
                out.write(buf, 0, n);
                out.flush();
            }
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // closing
        }
    }
}
