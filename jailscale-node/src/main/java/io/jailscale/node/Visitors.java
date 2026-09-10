package io.jailscale.node;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;

/**
 * Visitor streams on the node (DESIGN.md §10.2, §10.3): terminate TLS with the hub's
 * certificate and a remote key, connect to the local target, copy bytes both ways.
 */
final class Visitors {

    private static final Log LOG = Log.get("visitor");
    private static final int LOCAL_CONNECT_TIMEOUT_MS = 5_000;

    private final NodeState state;
    private final Map<String, SSLContext> contexts = new ConcurrentHashMap<>();

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
            ctx.init(new KeyManager[] {new RemoteSigning.RemoteKeyManager(chain, cert.keyId())}, null, null);
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

    /** Serves one visitor stream to completion on the calling (virtual) thread. */
    void serve(HubLink link, HubLink.Session session, MuxStream stream) {
        int conn = session.conn;
        String linkId = stream.meta().optString("linkId", null);
        String keyId = stream.meta().optString("keyId", null);
        String sni = stream.meta().optString("sni", "?");
        NodeState.LinkRec target = state.linkById(linkId);
        SSLContext ctx = keyId == null ? null : contexts.get(keyId);
        if (target == null || ctx == null) {
            LOG.warn("visitor for {} refused: {}", sni, target == null ? "unknown link" : "no certificate " + keyId);
            stream.reset(4);
            return;
        }
        TlsEndpoint tls = new TlsEndpoint(ctx, stream.in(), stream.out());
        try {
            RemoteSigning.enter(new RemoteSigning.Context(link, session, HubLink.fullStreamId(conn, stream.id()), keyId));
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
                            + "<p>이 링크는 방문 링크가 있어야 열립니다.</p>").writeTo(tls.plainOut());
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
        Socket local = new Socket();
        try {
            local.connect(new InetSocketAddress(target.host(), target.port()), LOCAL_CONNECT_TIMEOUT_MS);
            local.setTcpNoDelay(true);
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
        relay(tls, local, stream, replay);
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
                + "<p>노드가 <b>" + target.host() + ":" + target.port() + "</b> 에 연결할 수 없습니다.</p>")
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
