package io.jailscale.hub;

import io.jailscale.hub.dns.DnsQuery;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonException;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * Does this hub's name actually point at this hub (ARCHITECTURE.md §7.2)? The dns-01 self-check
 * proves the `_acme-challenge` delegation reaches this process and says nothing about the address
 * records that carry every visitor, so a deployment where the apex and the wildcard disagree, or
 * where both point at somebody else, was caught only by the first visitor handshake failing.
 *
 * <p>Three questions, in the order they can be answered without the previous one:
 *
 * <ol>
 *   <li>Do public resolvers have an address (A or AAAA) for the hub's name and for a name under
 *       its wildcard? Missing ones are a misconfiguration on their own.
 *   <li>Do the two agree? They must share an address, or some names reach this hub and others do
 *       not -- the case where only the wildcard is proxied. Sharing one, rather than being equal,
 *       is the test because the two lookups are not equally fresh: the apex is a name resolvers
 *       have cached, the wildcard probe is a label nobody has ever asked for, so during a record
 *       change the apex can still carry the old address next to the new one.
 *   <li>Does an address both names point at answer {@code /v1/key} with <b>this process's</b> hub
 *       key? That is the proof, and it needs no PKI: the hub key is what a node pins, so an address
 *       that returns a different one is a different hub whatever certificate it presents.
 * </ol>
 *
 * <p>Question 3 needs the host to be able to reach its own public address, which plenty of networks
 * do not allow -- a cloud instance whose public address is translated in front of it usually cannot.
 * A connection that <b>does not complete</b> is therefore inconclusive and never an alarm: it means
 * this vantage point cannot answer, not that the records are wrong. A connection that completes and
 * finds something that is not a hub is the opposite: that is the TLS-terminating proxy §7.2 says
 * cannot sit in front, and it is reported as the fault it is. A node arriving from a public address
 * (§10) answers question 3 from outside, where the translated-address failure mode does not exist.
 *
 * <p>The answer is kept and re-asked rather than logged once at startup ({@link Status}), because a
 * record is not a thing that is set right once: a proxy switched on in front of the name, an A
 * record edited, a hub moved to another address are all changes after boot, and a verdict that
 * exists only as a line in yesterday's log is one the operator who needs it cannot read.
 */
final class Reachability {

    private static final Log LOG = Log.get("reach");
    private static final int TLS_TIMEOUT_MS = 5000;
    private static final int MAX_BODY = 64 * 1024;

    private Reachability() {}

    /** What one run concluded. {@code problem} is null when nothing is wrong that this can see. */
    record Result(String verdict, String problem, List<String> addresses) {}

    static final String PROVEN = "proven";
    static final String ELSEWHERE = "elsewhere";
    static final String INCONCLUSIVE = "inconclusive";
    static final String MISCONFIGURED = "misconfigured";
    /** Nothing this host could see, and a node's arrival saying the records are right from outside. */
    static final String OUTSIDE = "outside";

    /**
     * How long a node's arrival still speaks for the address records. The handshake proves what
     * they said at that moment and nothing about what they say now, so the proof ages out: a day,
     * which any node that reconnects renews, and after which the verdict falls back to what this
     * host can see for itself rather than standing on a statement about a record that may have
     * been edited since.
     */
    static final long OUTSIDE_FRESH_MS = 86_400_000L;

    /**
     * The check as it stands, for an operator who was not at the console when it ran: the run
     * behind it, when it happened, when the verdict was first reached, and the outside view folded
     * in. {@code at} is the run's own time and does not move when a node's arrival is folded in
     * afterwards, so "seconds since the check last ran" means that and nothing else. {@code since}
     * is when the verdict last changed rather than when it was last confirmed, so "misconfigured
     * since 09:14" says how long this has been true -- of this process: nothing here is written to
     * disk, and a restart starts that clock over.
     */
    record Status(Result run, long at, long since, long outsideAt, String outsideIp) {

        /**
         * Whether a node's arrival speaks for the verdict: only over {@link #INCONCLUSIVE} (see
         * {@link #fold}), and only while it is fresh against the run. An arrival after the run is
         * always fresh; one from before it ages out after {@link #OUTSIDE_FRESH_MS}.
         */
        private boolean outside() {
            return INCONCLUSIVE.equals(run.verdict()) && outsideAt > 0 && at - outsideAt <= OUTSIDE_FRESH_MS;
        }

        String verdict() {
            return outside() ? OUTSIDE : run.verdict();
        }

        /** Null when nothing is wrong that this can see. */
        String problem() {
            return outside() ? null : run.problem();
        }

        List<String> addresses() {
            return run.addresses();
        }

        /** The records point here, whether this host proved it or a node did. */
        boolean ok() {
            String verdict = verdict();
            return PROVEN.equals(verdict) || OUTSIDE.equals(verdict);
        }

        /** The two verdicts that name something only the operator can fix; inconclusive is not one. */
        boolean fault() {
            String verdict = verdict();
            return ELSEWHERE.equals(verdict) || MISCONFIGURED.equals(verdict);
        }

        /**
         * The same finding as far as an operator is concerned: the verdict, and for a fault the
         * problem too, because {@link #MISCONFIGURED} covers both a missing wildcard and a wildcard
         * pointing elsewhere, and the pass that sees the second replace the first has seen a
         * change worth a log line and its own {@code since}. An inconclusive answer's text carries
         * the resolver's or the socket's own words, which vary between runs while nothing in the
         * world has moved, so those are not compared.
         */
        boolean sameAs(Status other) {
            return verdict().equals(other.verdict()) && (!fault() || Objects.equals(problem(), other.problem()));
        }

        /** One line, the same sentence on a log, a page and an admin reply. */
        String text(String host) {
            return switch (verdict()) {
                case PROVEN -> host + " and *." + host + " resolve to " + addresses() + " and that is this hub";
                case OUTSIDE -> "this host cannot reach its own public address, and a node at " + outsideIp
                    + " resolved " + host + " and arrived here: from where that node stands, the record"
                    + " points at this hub";
                case INCONCLUSIVE -> problem() + " A node arriving from a public address"
                    + " answers it from outside, where this failure mode does not exist.";
                default -> problem();
            };
        }

        JsonObject json() {
            Long outside = outsideAt > 0 ? outsideAt / 1000 : null;
            return JsonObject.builder()
                .put("verdict", verdict())
                .put("ok", ok())
                .put("fault", fault())
                .put("problem", problem())
                .put("addresses", addresses())
                .put("at", at / 1000)
                .put("since", since / 1000)
                .put("outsideAt", outside)
                .put("outsideIp", outsideIp)
                .build();
        }
    }

    /** Where the names point, so a test can answer without a network. */
    interface Resolver {
        Set<String> resolve(String name) throws IOException;
    }

    /** The hub key served at one address, so a test can answer without a socket. */
    interface KeyAt {
        String at(String address, String host, int port) throws IOException, GeneralSecurityException, HttpException;
    }

    /**
     * The TLS handshake completed and what answered is not a hub: no {@code /v1/key}, or not the
     * JSON a hub serves there. Distinct from a connection that failed, because it means the
     * opposite thing -- something is reachable at the name, and it is not us.
     */
    static final class NotAHub extends IOException {
        private static final long serialVersionUID = 1L;

        NotAHub(String message) {
            super(message);
        }
    }

    static Result check(HubConfig config, HubKeys keys) {
        // The port visitors use is the base URL's, not the one this process listens on: behind a
        // layer-4 proxy (§8.5) those differ, and dialing the listen port from outside proves nothing.
        int port = config.baseUrl().getPort() > 0 ? config.baseUrl().getPort() : 443;
        return check(config.hostname(), keys.publicText(), port, Reachability::resolve, Reachability::hubKeyAt);
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
            return new Result(INCONCLUSIVE, "no resolver answered for " + host + ": " + e.getMessage() + ".", List.of());
        }
        if (apex.isEmpty()) {
            return new Result(MISCONFIGURED, "no address record for " + host
                + ": visitors have nowhere to go. Point it at this host's public address.", List.of());
        }
        if (wildcard.isEmpty()) {
            return new Result(MISCONFIGURED, "no address record for *." + host
                + ": the hub's own name resolves but no published name will. Add the wildcard.", new ArrayList<>(apex));
        }
        List<String> shared = new ArrayList<>(apex);
        shared.retainAll(wildcard);
        if (shared.isEmpty()) {
            return new Result(MISCONFIGURED, host + " resolves to " + apex + " but *." + host + " to " + wildcard
                + ": names would reach different places, which is what a proxy in front of one of them does.",
                new ArrayList<>(apex));
        }
        String foreign = null;
        String notAHub = null;
        String unreachable = null;
        for (String address : shared) {
            String seen;
            try {
                seen = keyAt.at(address, host, port);
            } catch (NotAHub e) {
                notAHub = address + ": " + e.getMessage();
                continue;
            } catch (IOException | GeneralSecurityException | HttpException | RuntimeException e) {
                unreachable = address + ": " + e.getMessage();
                continue;
            }
            if (ourKey.equals(seen)) {
                return new Result(PROVEN, null, shared);
            }
            foreign = address + " presented " + seen;
        }
        // Nothing answered with our key. Say the worst thing that was actually seen: another hub
        // outranks a non-hub, and both outrank not being able to look.
        if (foreign != null) {
            return new Result(ELSEWHERE, host + " resolves to " + shared + ", and what answers there is a different"
                + " hub: " + foreign + " where this process holds " + ourKey + ". Nodes will pin whatever that is.",
                shared);
        }
        if (notAHub != null) {
            return new Result(MISCONFIGURED, host + " resolves to " + shared + " and something that is not a hub"
                + " answers there (" + notAHub + "). A TLS-terminating proxy in front of the hub is the usual cause;"
                + " it cannot sit there, only a layer-4 proxy that copies bytes can (§8.5).", shared);
        }
        return new Result(INCONCLUSIVE, "could not reach " + shared + " from this host (" + unreachable
            + "). That is normal where a public address is translated in front of the machine; it does not mean the"
            + " records are wrong, only that they cannot be checked from here.", shared);
    }

    /**
     * The union of what the public resolvers answer, A and AAAA, so one lagging resolver cannot
     * hide a record and a hub published only over IPv6 is not told it has no address.
     */
    static Set<String> resolve(String name) throws IOException {
        Set<String> out = new LinkedHashSet<>();
        IOException last = null;
        boolean answered = false;
        for (String r : DnsQuery.PUBLIC_RESOLVERS) {
            try {
                out.addAll(DnsQuery.a(r, 53, name, DnsQuery.PUBLIC_TIMEOUT_MS));
                out.addAll(DnsQuery.aaaa(r, 53, name, DnsQuery.PUBLIC_TIMEOUT_MS));
                answered = true;
            } catch (IOException e) {
                last = e;
            } catch (RuntimeException e) {
                // A datagram the parser did not plan for is a bad answer, not a reason to die.
                last = new IOException("bad answer from " + r + ": " + e, e);
            }
        }
        if (!answered) {
            throw last == null ? new IOException("no resolver answered") : last;
        }
        return out;
    }

    /**
     * The hub key {@code address} serves for {@code host}. The certificate is deliberately not
     * verified: the hub key is the thing a node pins and the thing being compared, so a valid
     * certificate for the name would prove nothing here that the key does not prove better. Once
     * the handshake has completed, anything but a hub's answer is {@link NotAHub}.
     */
    static String hubKeyAt(String address, String host, int port)
        throws IOException, GeneralSecurityException, HttpException {
        SSLContext ctx = Tls.clientContext(null, true);
        try (SSLSocket s = Tls.connect(ctx, host, address, port, false, TLS_TIMEOUT_MS)) {
            Http.writeRequest(s.getOutputStream(), "GET", host, "/v1/key", null, null);
            HttpResponse r;
            try {
                r = Http.readResponse(s.getInputStream(), MAX_BODY);
            } catch (HttpException e) {
                throw new NotAHub("not an HTTP answer a hub gives: " + e.getMessage());
            }
            if (r.status() != 200) {
                throw new NotAHub("/v1/key answered HTTP " + r.status());
            }
            try {
                JsonObject o = Json.parseObject(r.bodyText());
                return o.string("hubKey");
            } catch (JsonException e) {
                throw new NotAHub("/v1/key did not answer with a hub key: " + e.getMessage());
            }
        }
    }

    /**
     * One run, the outside view and what was already believed, into the status to report.
     *
     * <p>Only {@link #INCONCLUSIVE} is upgraded by a node's arrival, and deliberately: what the
     * node proves is that this hub's own name led it here from a public resolver, which is exactly
     * the question a host behind a translated address cannot answer about itself. It says nothing
     * about the wildcard, so it cannot clear {@link #MISCONFIGURED}, and a different hub answering
     * at the shared address ({@link #ELSEWHERE}) is a conflict to report rather than one to
     * average away.
     */
    static Status fold(Status previous, Result r, long outsideAt, String outsideIp, long now) {
        return fold(previous, r, now, outsideAt, outsideIp, now);
    }

    /**
     * As above, for a run made at {@code at} and folded at {@code now}: the two differ when a
     * node's arrival is folded into a run that already stands, which moves the verdict and its
     * {@code since} but not when the check last ran.
     */
    static Status fold(Status previous, Result r, long at, long outsideAt, String outsideIp, long now) {
        Status fresh = new Status(r, at, now, outsideAt, outsideIp);
        return previous != null && previous.sameAs(fresh) ? new Status(r, at, previous.since(), outsideAt, outsideIp) : fresh;
    }

    /**
     * Says what the check found, at the volume the verdict deserves, and only when it changed.
     * The check repeats (§7.2), so a hub whose records are wrong would otherwise file the same
     * error every hour and a healthy one the same line, which is how a log stops being read. The
     * verdict that stands is still there to be asked for -- {@code jailhub address check},
     * {@code /admin}, {@code /metrics} -- which is the point of keeping it.
     */
    static void report(String host, Status previous, Status current) {
        if (previous != null && previous.sameAs(current)) {
            return;
        }
        String was = previous == null ? "" : " (was " + previous.verdict() + ")";
        if (current.fault()) {
            LOG.error("address check {}: {}{}", ELSEWHERE.equals(current.verdict()) ? "FAILED" : "failed",
                current.text(host), was);
        } else {
            LOG.info("address check {}: {}{}", current.verdict(), current.text(host), was);
        }
    }
}
