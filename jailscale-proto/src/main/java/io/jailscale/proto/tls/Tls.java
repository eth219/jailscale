package io.jailscale.proto.tls;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** SSLContext construction for the hub's listener and the node's client (DESIGN.md §6.1). */
public final class Tls {

    public static final String[] PROTOCOLS = {"TLSv1.3", "TLSv1.2"};
    public static final String[] ALPN_HTTP11 = {"http/1.1"};

    private Tls() {}

    /** Server context from PEM files: certificate chain and PKCS#8 key. */
    public static SSLContext serverContext(Path certPem, Path keyPem) throws IOException, GeneralSecurityException {
        return serverContext(Pem.certificates(Files.readString(certPem)), Pem.privateKey(Files.readString(keyPem)));
    }

    public static SSLContext serverContext(List<X509Certificate> chain, PrivateKey key) throws GeneralSecurityException {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("server", key, new char[0], chain.toArray(new X509Certificate[0]));
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, new char[0]);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            return ctx;
        } catch (IOException e) {
            throw new GeneralSecurityException("keystore", e);
        }
    }

    /** Applies protocol, ALPN and (for servers) no client auth. */
    public static void configureServer(SSLServerSocket ss) {
        SSLParameters p = ss.getSSLParameters();
        p.setProtocols(PROTOCOLS);
        p.setApplicationProtocols(ALPN_HTTP11);
        p.setUseCipherSuitesOrder(true);
        ss.setSSLParameters(p);
    }

    /**
     * Client context. {@code caPem} trusts exactly that certificate chain instead of the system
     * roots; {@code insecure} trusts anything (only allowed together with a pinned hub key).
     */
    public static SSLContext clientContext(Path caPem, boolean insecure) throws IOException, GeneralSecurityException {
        SSLContext ctx = SSLContext.getInstance("TLS");
        TrustManager[] tms;
        if (insecure) {
            tms = new TrustManager[] {new TrustAll()};
        } else if (caPem != null) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try {
                ks.load(null, null);
            } catch (IOException e) {
                throw new GeneralSecurityException("keystore", e);
            }
            int i = 0;
            for (X509Certificate c : Pem.certificates(Files.readString(caPem))) {
                ks.setCertificateEntry("ca" + (i++), c);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            tms = tmf.getTrustManagers();
        } else {
            tms = null; // system default roots
        }
        ctx.init(null, tms, null);
        return ctx;
    }

    /** Opens a TLS client connection with SNI, ALPN http/1.1 and hostname verification (unless insecure). */
    public static SSLSocket connect(SSLContext ctx, String host, int port, boolean verifyHostname, int timeoutMillis)
        throws IOException {
        SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket();
        s.connect(new InetSocketAddress(host, port), timeoutMillis);
        s.setSoTimeout(timeoutMillis);
        s.setTcpNoDelay(true);
        SSLParameters p = s.getSSLParameters();
        p.setProtocols(PROTOCOLS);
        p.setApplicationProtocols(ALPN_HTTP11);
        p.setServerNames(List.of(new SNIHostName(host)));
        if (verifyHostname) {
            p.setEndpointIdentificationAlgorithm("HTTPS");
        }
        s.setSSLParameters(p);
        s.startHandshake();
        return s;
    }

    private static final class TrustAll implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
