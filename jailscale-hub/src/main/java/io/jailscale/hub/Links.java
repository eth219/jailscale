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

    /** An active link: a name served by a node session. */
    record Link(String linkId, String name, String kind, String user, String mkey, NodeSession session, String local) {}

    private final HubConfig config;
    private final Store store;
    private final Map<String, Link> byName = new ConcurrentHashMap<>();
    private final Map<String, Link> byId = new ConcurrentHashMap<>();

    Links(HubConfig config, Store store) {
        this.config = config;
        this.store = store;
    }

    Link byName(String name) {
        return byName.get(name);
    }

    Link byId(String linkId) {
        return byId.get(linkId);
    }

    List<Link> all() {
        return new ArrayList<>(byName.values());
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
        if (!Message.LinkOpen.HTTPS.equals(req.kind())) {
            return new Message.LinkOpened(null, null, null, null, "kind-not-supported-yet");
        }
        if (req.domain() != null) {
            return new Message.LinkOpened(null, null, null, null, "domain-not-supported-yet");
        }
        int mine = 0;
        for (Link l : byName.values()) {
            if (l.mkey().equals(node.mkey())) {
                mine++;
            }
        }
        if (mine >= MAX_LINKS_PER_NODE) {
            return new Message.LinkOpened(null, null, null, null, "too-many-links");
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
        if (existing != null && existing.session() != s) {
            if (!existing.mkey().equals(node.mkey()) && !existing.user().equals(node.user())) {
                return new Message.LinkOpened(null, null, null, null, "taken");
            }
            // Same owner from another (or restarted) node: the newest opener wins.
            byId.remove(existing.linkId());
        }
        Link link = new Link(Tokens.id("l_"), name, req.kind(), node.user(), node.mkey(), s, req.local());
        byName.put(name, link);
        byId.put(link.linkId(), link);
        LOG.info("link {} opened by {} ({}) -> {}", name, node.user(), node.mkey(), req.local());
        return new Message.LinkOpened(link.linkId(), name, "https://" + name + "." + config.hostname() + portSuffix(), null, null);
    }

    void close(NodeSession s, String linkId) {
        Link l = byId.remove(linkId);
        if (l != null && l.session() == s) {
            byName.remove(l.name(), l);
            LOG.info("link {} closed", l.name());
        }
    }

    /** Called when a session ends: its links go offline (names stay claimed). */
    void sessionEnded(NodeSession s) {
        for (Link l : new ArrayList<>(byName.values())) {
            if (l.session() == s) {
                byName.remove(l.name(), l);
                byId.remove(l.linkId(), l);
            }
        }
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
