package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/** Names and the links currently serving them (DESIGN.md §9.2). */
final class Links {

    private static final Log LOG = Log.get("links");
    private static final Pattern NAME = Pattern.compile("[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])?");
    private static final Set<String> RESERVED = Set.of("hub", "admin", "www", "api", "mail", "ns", "ns1", "ns2",
        "_acme-challenge", "join", "acme", "hubs", "static");
    private static final String RANDOM_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
    private static final SecureRandom RNG = new SecureRandom();
    static final int MAX_LINKS_PER_NODE = 20;

    /** An active link: a name served by a node (all of its connections). */
    record Link(String linkId, String name, String kind, String user, String mkey, NodeGroup group, String local, int port,
        String domain) {
        boolean raw() {
            return port > 0;
        }

        /** The SNI visitors use: the hub sub-name or the user domain. */
        String host(HubConfig config) {
            return domain != null ? domain : name + "." + config.hostname();
        }
    }

    static final String TCP = Message.LinkOpen.TCP;
    static final String UDP = Message.LinkOpen.UDP;

    private final HubConfig config;
    private final Store store;
    private final RawPorts raw;
    private final DomainVerifier domains;
    private final Map<String, Link> byName = new ConcurrentHashMap<>();
    private final Map<String, Link> byDomain = new ConcurrentHashMap<>();
    private final Map<Integer, Link> byPort = new ConcurrentHashMap<>();
    private final Map<String, Link> byId = new ConcurrentHashMap<>();

    Links(HubConfig config, Store store, RawPorts raw, DomainVerifier domains) {
        this.config = config;
        this.store = store;
        this.raw = raw;
        this.domains = domains;
    }

    Link byDomain(String domain) {
        return byDomain.get(domain);
    }

    Link byPort(int port) {
        return byPort.get(port);
    }

    Link byName(String name) {
        return byName.get(name);
    }

    Link byId(String linkId) {
        return byId.get(linkId);
    }

    List<Link> all() {
        List<Link> all = new ArrayList<>(byName.values());
        all.addAll(byDomain.values());
        all.addAll(byPort.values());
        return all;
    }

    /** True if {@code host} is {@code <name>.<hub>}; returns the name part or null. */
    String nameOf(String host) {
        String suffix = "." + config.hostname();
        if (host == null || !host.endsWith(suffix)) {
            return null;
        }
        String name = host.substring(0, host.length() - suffix.length());
        return name.contains(".") ? null : name;
    }

    /** Handles LinkOpen from a registered node. */
    synchronized Message open(NodeSession s, Message.LinkOpen req) throws IOException {
        Store.NodeRec node = s.node();
        if (node == null) {
            return new Message.LinkOpened(null, null, null, null, "not-registered");
        }
        if (TCP.equals(req.kind()) || UDP.equals(req.kind())) {
            return openRaw(s, node, req);
        }
        if (!Message.LinkOpen.HTTPS.equals(req.kind())) {
            return new Message.LinkOpened(null, null, null, null, "bad-kind");
        }
        int mine = 0;
        for (Link l : all()) {
            if (l.mkey().equals(node.mkey())) {
                mine++;
            }
        }
        if (mine >= MAX_LINKS_PER_NODE) {
            return new Message.LinkOpened(null, null, null, null, "too-many-links");
        }
        if (req.domain() != null) {
            return openDomain(s, node, req);
        }
        String name;
        if (req.name() != null) {
            name = req.name().toLowerCase(Locale.ROOT);
            if (!NAME.matcher(name).matches() || RESERVED.contains(name)) {
                return new Message.LinkOpened(null, null, null, null, "bad-name");
            }
            String owner = store.nameOwner(name);
            if (owner != null && !owner.equals(node.user())) {
                return new Message.LinkOpened(null, null, null, null, "taken");
            }
            if (owner == null) {
                store.claimName(name, node.user(), node.mkey(), req.local());
            }
        } else {
            name = store.nameFor(node.mkey(), req.local());
            if (name == null) {
                do {
                    name = randomName();
                } while (store.nameOwner(name) != null || byName.containsKey(name));
                store.claimName(name, node.user(), node.mkey(), req.local());
            }
        }
        Link existing = byName.get(name);
        if (existing != null && existing.group() != s.group()) {
            if (!existing.mkey().equals(node.mkey()) && !existing.user().equals(node.user())) {
                return new Message.LinkOpened(null, null, null, null, "taken");
            }
            // Same owner from another (or restarted) node: the newest opener wins.
            byId.remove(existing.linkId());
        }
        Link link = new Link(Tokens.id("l_"), name, req.kind(), node.user(), node.mkey(), s.group(), req.local(), 0, null);
        byName.put(name, link);
        byId.put(link.linkId(), link);
        LOG.info("link {} opened by {} ({}) -> {}", name, node.user(), node.mkey(), req.local());
        return new Message.LinkOpened(link.linkId(), name, "https://" + name + "." + config.hostname() + portSuffix(), null, null);
    }

    /**
     * DESIGN.md §9.4: the node brings its own certificate for its own domain; a chain that
     * validates is the proof of ownership. Pure SNI passthrough afterwards, no signing.
     */
    private Message openDomain(NodeSession s, Store.NodeRec node, Message.LinkOpen req) throws IOException {
        String domain = req.domain().toLowerCase(Locale.ROOT);
        if (!DomainVerifier.validName(domain) || domain.equals(config.hostname()) || domain.endsWith("." + config.hostname())) {
            return new Message.LinkOpened(null, null, null, null, "bad-domain");
        }
        String problem = domains.verify(domain, req.chainPem());
        if (problem != null) {
            return new Message.LinkOpened(null, null, null, null, problem);
        }
        Link existing = byDomain.get(domain);
        if (existing != null && existing.group() != s.group()) {
            byId.remove(existing.linkId());
        }
        store.claimDomain(domain, node.user(), node.mkey());
        Link link = new Link(Tokens.id("l_"), domain, req.kind(), node.user(), node.mkey(), s.group(), req.local(), 0, domain);
        byDomain.put(domain, link);
        byId.put(link.linkId(), link);
        LOG.info("domain {} opened by {} ({}) -> {}", domain, node.user(), node.mkey(), req.local());
        return new Message.LinkOpened(link.linkId(), domain, "https://" + domain + portSuffix(), null, null);
    }

    /** DESIGN.md §9.5: a port instead of a name. Stable per node, kind and local target. */
    private Message openRaw(NodeSession s, Store.NodeRec node, Message.LinkOpen req) throws IOException {
        if (!config.hasPortRange()) {
            return new Message.LinkOpened(null, null, null, null, "raw-ports-disabled");
        }
        if (req.local() == null) {
            return new Message.LinkOpened(null, null, null, null, "local-required");
        }
        boolean explicit = req.port() != null && req.port() > 0;
        List<Integer> candidates = new ArrayList<>();
        if (explicit) {
            if (req.port() < config.portRangeLo() || req.port() > config.portRangeHi()) {
                return new Message.LinkOpened(null, null, null, null, "port-out-of-range");
            }
            candidates.add(req.port());
        } else {
            int remembered = store.portFor(node.mkey(), req.kind(), req.local());
            if (remembered > 0) {
                candidates.add(remembered);
            }
            for (int p = config.portRangeLo(); p <= config.portRangeHi(); p++) {
                if (p != remembered && store.port(p) == null && !byPort.containsKey(p)) {
                    candidates.add(p);
                }
            }
            if (candidates.isEmpty()) {
                return new Message.LinkOpened(null, null, null, null, "no-free-port");
            }
        }
        for (int port : candidates) {
            Store.PortRec rec = store.port(port);
            if (rec != null && !rec.mkey().equals(node.mkey()) && !rec.user().equals(node.user())) {
                return new Message.LinkOpened(null, null, null, null, "port-taken");
            }
            Link existing = byPort.get(port);
            if (existing != null) {
                if (existing.group() != s.group() && !existing.mkey().equals(node.mkey()) && !existing.user().equals(node.user())) {
                    return new Message.LinkOpened(null, null, null, null, "port-taken");
                }
                // The newest opener wins, as with names.
                raw.stop(existing);
                byId.remove(existing.linkId());
                byPort.remove(port);
            }
            Link link = new Link(Tokens.id("l_"), req.kind() + "/" + port, req.kind(), node.user(), node.mkey(), s.group(), req.local(), port, null);
            try {
                raw.start(link);
            } catch (IOException e) {
                LOG.warn("cannot bind {} port {}: {}", req.kind(), port, e.getMessage());
                if (explicit) {
                    return new Message.LinkOpened(null, null, null, null, "port-bind-failed");
                }
                continue;
            }
            if (rec == null || !rec.mkey().equals(node.mkey()) || !rec.kind().equals(req.kind()) || !rec.local().equals(req.local())) {
                store.assignPort(port, req.kind(), node.user(), node.mkey(), req.local());
            }
            byPort.put(port, link);
            byId.put(link.linkId(), link);
            return new Message.LinkOpened(link.linkId(), link.name(), req.kind() + "://" + config.hostname() + ":" + port, port, null);
        }
        return new Message.LinkOpened(null, null, null, null, "no-free-port");
    }

    void close(NodeGroup g, String linkId) {
        Link l = byId.remove(linkId);
        if (l != null && l.group() == g) {
            if (l.raw()) {
                raw.stop(l);
                byPort.remove(l.port(), l);
            } else if (l.domain() != null) {
                byDomain.remove(l.domain(), l);
            } else {
                byName.remove(l.name(), l);
            }
            LOG.info("link {} closed", l.name());
        }
    }

    /** Called when a node's last connection ends: its links go offline (names and ports stay assigned). */
    void groupEnded(NodeGroup g) {
        for (Link l : all()) {
            if (l.group() == g) {
                if (l.raw()) {
                    raw.stop(l);
                    byPort.remove(l.port(), l);
                } else if (l.domain() != null) {
                    byDomain.remove(l.domain(), l);
                } else {
                    byName.remove(l.name(), l);
                }
                byId.remove(l.linkId(), l);
            }
        }
    }

    /** Waits up to {@code ms} for a claimed name or domain to come online (hand-off, node restarts). */
    Link awaitOnline(String name, boolean domain, long ms) {
        long deadline = System.currentTimeMillis() + ms;
        Map<String, Link> map = domain ? byDomain : byName;
        Link l;
        while ((l = map.get(name)) == null && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
        return l;
    }

    private String portSuffix() {
        return config.listenPort() == 443 || config.baseUrl().getPort() <= 0 ? "" : ":" + config.baseUrl().getPort();
    }

    static String randomName() {
        StringBuilder sb = new StringBuilder(5);
        for (int i = 0; i < 5; i++) {
            sb.append(RANDOM_ALPHABET.charAt(RNG.nextInt(RANDOM_ALPHABET.length())));
        }
        return sb.toString();
    }
}
