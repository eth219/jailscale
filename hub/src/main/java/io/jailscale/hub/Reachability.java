package io.jailscale.hub;

import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * Does this hub's name actually point at this hub (ARCHITECTURE.md §7.2)? The dns-01 self-check
 * proves the `_acme-challenge` delegation reaches this process and says nothing about the A records
 * that carry every visitor, so a deployment where the apex and the wildcard disagree, or where both
 * point at somebody else, was caught only by the first visitor handshake failing.
 *
 * <p>Three questions, in the order they can be answered without the previous one:
 *
 * <ol>
 *   <li>Do public resolvers have A records for the hub's name and for a name under its wildcard?
 *       Missing ones are a misconfiguration on their own.
 *   <li>Do the two agree? They must, or some names reach this hub and others do not -- the case
 *       where only the wildcard is proxied.
 *   <li>Does the address answer {@code /v1/key} with <b>this process's</b> hub key? That is the
 *       proof, and it needs no PKI: the hub key is what a node pins, so an address that returns a
 *       different one is a different hub whatever certificate it presents.
 * </ol>
 *
 * <p>Question 3 needs the host to be able to reach its own public address, which plenty of networks
 * do not allow -- a cloud instance whose public address is translated in front of it usually cannot.
 * A connection that fails is therefore <b>inconclusive and never an alarm</b>: it means this vantage
 * point cannot answer, not that the records are wrong. What a node reports on arrival (§10) answers
 * the same question from outside, where the failure mode does not exist.
 */
final class Reachability {

    private static final Log LOG = Log.get("reach");
    private static final String[] RESOLVERS = {"1.1.1.1", "8.8.8.8"};
    private static final int DNS_TIMEOUT_MS = 5000;
    private static final int TLS_TIMEOUT_MS = 5000;
    private static final int MAX_BODY = 64 * 1024;

    private Reachability() {}

    /** What one run concluded. {@code problem} is null when nothing is wrong that this can see. */
    record Result(String verdict, String problem, List<String> addresses) {}

    static final String PROVEN = "proven";
    static final String ELSEWHERE = "elsewhere";
    static final String INCONCLUSIVE = "inconclusive";
    static final String MISCONFIGURED = "misconfigured";

    /** Where the names point, so a test can answer without a network. */
    interface Resolver {
        Set<String> resolve(String name) throws IOException;
    }

    /** The hub key served at one address, so a test can answer without a socket. */
    interface KeyAt {
        String at(String address, String host, int port) throws IOException, GeneralSecurityException, HttpException;
    }

    static Result check(HubConfig config, HubKeys keys) {
        return check(config.hostname(), keys.publicText(), config.listenPort(),
            Reachability::resolve, Reachability::hubKeyAt);
    }

    /**
     * The decision itself, with the two things that touch the world passed in. Every verdict below
     * is one a test can reach, which matters more here than usual: a wrong one either cries wolf at
     * a healthy deployment or stays quiet about a broken one.
     */
    static Result check(String host, String ourKey, int port, Resolver resolver, KeyAt keyAt) {
        // A label nobody could have an explicit record for, so what answers is the wildcard.
        String underWildcard = "reach-" + Tokens.inviteToken().toLowerCase(java.util.Locale.ROOT) + "." + host;
        Set<String> apex;
        Set<String> wildcard;
        try {
            apex = resolver.resolve(host);
            wildcard = resolver.resolve(underWildcard);
        } catch (IOException e) {
            return new Result(INCONCLUSIVE, "no resolver answered for " + host + ": " + e.getMessage(), List.of());
        }
        if (apex.isEmpty()) {
            return new Result(MISCONFIGURED, "no A record for " + host
                + ": visitors have nowhere to go. Point it at this host's public address.", List.of());
        }
        if (wildcard.isEmpty()) {
            return new Result(MISCONFIGURED, "no A record for *." + host
                + ": the hub's own name resolves but no published name will. Add the wildcard.", new ArrayList<>(apex));
        }
        if (!apex.equals(wildcard)) {
            return new Result(MISCONFIGURED, host + " resolves to " + apex + " but *." + host + " to " + wildcard
                + ": names would reach different places, which is what a proxy in front of one of them does.",
                new ArrayList<>(apex));
        }
        List<String> addresses = new ArrayList<>(apex);
        String lastFailure = null;
        for (String address : addresses) {
            String seen;
            try {
                seen = keyAt.at(address, host, port);
            } catch (IOException | GeneralSecurityException | HttpException | RuntimeException e) {
                lastFailure = address + ": " + e.getMessage();
                continue;
            }
            if (ourKey.equals(seen)) {
                return new Result(PROVEN, null, addresses);
            }
            return new Result(ELSEWHERE, host + " resolves to " + address + ", and what answers there is a different"
                + " hub: it presented " + seen + " where this process holds " + ourKey
                + ". Nodes will pin whatever that is.", addresses);
        }
        return new Result(INCONCLUSIVE, "could not reach " + addresses + " from this host (" + lastFailure
            + "). That is normal where a public address is translated in front of the machine; it does not mean the"
            + " records are wrong, only that they cannot be checked from here.", addresses);
    }

    /** The union of what the public resolvers answer, so one lagging resolver cannot hide a record. */
    static Set<String> resolve(String name) throws IOException {
        Set<String> out = new LinkedHashSet<>();
        IOException last = null;
        boolean answered = false;
        for (String r : RESOLVERS) {
            try {
                out.addAll(DnsQueryA(r, name));
                answered = true;
            } catch (IOException e) {
                last = e;
            }
        }
        if (!answered) {
            throw last == null ? new IOException("no resolver answered") : last;
        }
        return out;
    }

    private static List<String> DnsQueryA(String resolver, String name) throws IOException {
        return io.jailscale.hub.dns.DnsQuery.a(resolver, 53, name, DNS_TIMEOUT_MS);
    }

    /**
     * The hub key {@code address} serves for {@code host}. The certificate is deliberately not
     * verified: the hub key is the thing a node pins and the thing being compared, so a valid
     * certificate for the name would prove nothing here that the key does not prove better.
     */
    static String hubKeyAt(String address, String host, int port)
        throws IOException, GeneralSecurityException, HttpException {
        SSLContext ctx = Tls.clientContext(null, true);
        try (SSLSocket s = Tls.connect(ctx, host, address, port, false, TLS_TIMEOUT_MS)) {
            Http.writeRequest(s.getOutputStream(), "GET", host, "/v1/key", null, null);
            HttpResponse r = Http.readResponse(s.getInputStream(), MAX_BODY);
            if (r.status() != 200) {
                throw new IOException("/v1/key answered HTTP " + r.status());
            }
            JsonObject o = Json.parseObject(new String(r.body(), java.nio.charset.StandardCharsets.UTF_8));
            return o.string("hubKey");
        }
    }

    /** Runs the check and says what it found, at the volume the verdict deserves. */
    static void report(HubConfig config, HubKeys keys) {
        Result r = check(config, keys);
        switch (r.verdict()) {
            case PROVEN -> LOG.info("{} and *.{} resolve to {} and that is this hub", config.hostname(),
                config.hostname(), r.addresses());
            case ELSEWHERE -> LOG.error("address check FAILED: {}", r.problem());
            case MISCONFIGURED -> LOG.error("address check failed: {}", r.problem());
            default -> LOG.info("address check inconclusive: {}. The next node to arrive answers it from"
                + " outside, where this failure mode does not exist.", r.problem());
        }
    }
}
