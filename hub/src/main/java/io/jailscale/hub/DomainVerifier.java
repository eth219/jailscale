package io.jailscale.hub;

import io.jailscale.proto.tls.Pem;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Proof of ownership for a user domain (DESIGN.md §9.4): a certificate chain for that exact
 * name that validates to a public CA. Whoever holds such a certificate controls the domain,
 * so the hub routes the name to them without keeping any key of its own.
 */
final class DomainVerifier {

    private static final Pattern DOMAIN = Pattern.compile("(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}");

    private final X509TrustManager trust;

    /** {@code caPem} overrides the system roots (tests, private CAs); null uses the platform trust store. */
    DomainVerifier(Path caPem) throws IOException, GeneralSecurityException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        if (caPem == null) {
            tmf.init((KeyStore) null);
        } else {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            int i = 0;
            for (X509Certificate c : Pem.certificates(Files.readString(caPem))) {
                ks.setCertificateEntry("ca" + i++, c);
            }
            tmf.init(ks);
        }
        X509TrustManager found = null;
        for (var tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager x) {
                found = x;
            }
        }
        if (found == null) {
            throw new GeneralSecurityException("no X509TrustManager");
        }
        trust = found;
    }

    static boolean validName(String domain) {
        return domain != null && DOMAIN.matcher(domain).matches();
    }

    /** Returns null when the chain proves {@code domain}, else the reason it does not. */
    String verify(String domain, List<String> chainPem) {
        if (chainPem == null || chainPem.isEmpty()) {
            return "domain-unverified";
        }
        List<X509Certificate> chain;
        try {
            StringBuilder sb = new StringBuilder();
            for (String p : chainPem) {
                sb.append(p);
            }
            chain = Pem.certificates(sb.toString());
        } catch (GeneralSecurityException e) {
            return "domain-cert-unparseable";
        }
        if (chain.isEmpty()) {
            return "domain-cert-unparseable";
        }
        X509Certificate leaf = chain.get(0);
        try {
            leaf.checkValidity();
        } catch (CertificateException e) {
            return "domain-cert-expired";
        }
        if (!coversName(leaf, domain)) {
            return "domain-cert-name-mismatch";
        }
        try {
            trust.checkServerTrusted(chain.toArray(new X509Certificate[0]), leaf.getPublicKey().getAlgorithm().equals("EC") ? "ECDHE_ECDSA" : "RSA");
        } catch (CertificateException e) {
            return "domain-cert-untrusted";
        }
        return null;
    }

    static boolean coversName(X509Certificate leaf, String domain) {
        Collection<List<?>> sans;
        try {
            sans = leaf.getSubjectAlternativeNames();
        } catch (CertificateException e) {
            return false;
        }
        if (sans == null) {
            return false;
        }
        String d = domain.toLowerCase(Locale.ROOT);
        for (List<?> san : sans) {
            if (san.size() == 2 && Integer.valueOf(2).equals(san.get(0)) && san.get(1) instanceof String n) {
                String name = n.toLowerCase(Locale.ROOT);
                if (name.equals(d)) {
                    return true;
                }
                if (name.startsWith("*.") && d.indexOf('.') > 0 && d.substring(d.indexOf('.') + 1).equals(name.substring(2))) {
                    return true;
                }
            }
        }
        return false;
    }
}
