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

/** Names and the links currently serving them (ARCHITECTURE.md §8.2). */
final class Links {

    private static final Log LOG = Log.get("links");
    private static final Pattern NAME = Pattern.compile("[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])?");
    private static final Set<String> RESERVED = Set.of("hub", "admin", "www", "api", "mail", "ns", "ns1", "ns2",
        "_acme-challenge", "join", "acme", "hubs", "static", "links");
    private static final String RANDOM_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
    private static final SecureRandom RNG = new SecureRandom();
    static final int MAX_LINKS_PER_NODE = 20;

    /** An active link: a name served by a node (all of its connections). */
    record Link(String linkId, String name, String user, String mkey, NodeGroup group, String local) {

        /** The SNI visitors use. */
        String host(HubConfig config) {
            return name + "." + config.hostname();
        }
    }

    private final HubConfig config;
    private final Store store;
    private final Registry registry;
    private final Map<String, Link> byName = new ConcurrentHashMap<>();
    private final Map<String, Link> byId = new ConcurrentHashMap<>();
    /**
     * The three maps a live link can be in, as one list instead of three names written out at
     * every site that walks them. {@link #all} and {@link #count} have to mean the same thing by
     * "every link" -- one is what a test and the operator's tools walk, the other the number the
     * front page prints -- and a fourth map added to one of two hand-written enumerations is the
     * two disagreeing about how many links this hub is serving. Sharing the list is what makes
     * that impossible; a test can only notice it after the fact, and only for the maps it happens
     * to have filled. {@code byId} is not here: it is an index of the same links, not a fourth place
     * one lives.
     */
    private final List<Map<?, Link>> live = List.<Map<?, Link>>of(byName);

    Links(HubConfig config, Store store, Registry registry) {
        this.config = config;
        this.store = store;
        this.registry = registry;
    }

    Link byName(String name) {
        return byName.get(name);
    }

    Link byId(String linkId) {
        return byId.get(linkId);
    }

    List<Link> all() {
        List<Link> all = new ArrayList<>(count());
        for (Map<?, Link> m : live) {
            all.addAll(m.values());
        }
        return all;
    }

    /**
     * How many links are open, without building the list of them. Exactly {@code all().size()} and
     * not an approximation of it: both walk {@link #live}, so the sum of those maps' sizes is that
     * list's length whatever they hold, and neither can be given a map the other is not. The front
     * page wants this number on every request from anyone visiting the hub's own name, and copying
     * every live link into an {@code ArrayList} to call {@code size()} on it is the allocation
     * that buys.
     */
    int count() {
        int n = 0;
        for (Map<?, Link> m : live) {
            n += m.size();
        }
        return n;
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
            return new Message.LinkOpened(null, null, null, "not-registered");
        }
        int mine = 0;
        for (Link l : all()) {
            if (l.mkey().equals(node.mkey())) {
                mine++;
            }
        }
        if (mine >= MAX_LINKS_PER_NODE) {
            return new Message.LinkOpened(null, null, null, "too-many-links");
        }
        String name;
        if (req.name() != null) {
            name = req.name().toLowerCase(Locale.ROOT);
            if (!NAME.matcher(name).matches() || RESERVED.contains(name)) {
                return new Message.LinkOpened(null, null, null, "bad-name");
            }
            Store.NameRec prior = store.name(name);
            if (prior != null && !prior.user().equals(node.user())) {
                return new Message.LinkOpened(null, null, null, "taken");
            }
            if (prior == null || !prior.mkey().equals(node.mkey())) {
                store.claimName(name, node.user(), node.mkey(), req.local());
                if (prior != null) {
                    // The name moved between this user's nodes (ARCHITECTURE.md §11.4). Driven by the
                    // stored claim, not by a live link: the node that loses a name is usually the
                    // one that is offline, and that is exactly when there is no link to look at.
                    notifyRevoked(prior.mkey(), null, name, Message.LinkRevoked.REASSIGNED);
                }
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
                return new Message.LinkOpened(null, null, null, "taken");
            }
            // Same owner from another (or restarted) node: the newest opener wins.
            byId.remove(existing.linkId());
        }
        Link link = new Link(Tokens.id("l_"), name, node.user(), node.mkey(), s.group(), req.local());
        byName.put(name, link);
        byId.put(link.linkId(), link);
        LOG.info("link {} opened by {} ({}) -> {}", name, node.user(), node.mkey(), req.local());
        return new Message.LinkOpened(link.linkId(), name, "https://" + name + "." + config.hostname() + portSuffix(), null);
    }

    void close(NodeGroup g, String linkId) {
        Link l = byId.remove(linkId);
        if (l != null && l.group() == g) {
            byName.remove(l.name(), l);
            LOG.info("link {} closed", l.name());
        }
    }

    /**
     * An operator released a name (ARCHITECTURE.md §11.4): take the live link down and tell the
     * node. Without this the name keeps serving from the old node until it closes the link.
     */
    void releasedByOperator(String name) {
        Link l = byName.remove(name);
        if (l == null) {
            return;
        }
        byId.remove(l.linkId(), l);
        notifyRevoked(l.mkey(), l.linkId(), l.name(), Message.LinkRevoked.RELEASED);
    }

    /**
     * Tells the node that lost a name: now if it is connected, on its next connection if not
     * (ARCHITECTURE.md §11.4). Being offline is often why the name was taken, so the stored notice is
     * the common path, not the exception.
     */
    private void notifyRevoked(String mkey, String linkId, String name, String reason) {
        LOG.info("{} revoked from {}: {}", name, mkey, reason);
        Message.LinkRevoked m = new Message.LinkRevoked(linkId, name, reason, System.currentTimeMillis());
        NodeGroup g = registry.get(mkey);
        if (g != null) {
            try {
                g.send(m);
                return;
            } catch (IOException | RuntimeException _) {
                // Connected but on its way out: fall through and store it for the next connection.
            }
        }
        try {
            store.addNotice(mkey, linkId, name, reason);
        } catch (IOException e) {
            LOG.warn("cannot record that {} lost {}: {}", mkey, name, e.getMessage());
        }
    }

    /** Called when a node's last connection ends: its links go offline (the names stay claimed). */
    void groupEnded(NodeGroup g) {
        for (Link l : all()) {
            if (l.group() == g) {
                byName.remove(l.name(), l);
                byId.remove(l.linkId(), l);
            }
        }
    }

    /** Waits up to {@code ms} for a claimed name to come online (hand-off, node restarts). */
    Link awaitOnline(String name, long ms) {
        long deadline = System.currentTimeMillis() + ms;
        Map<String, Link> map = byName;
        Link l;
        while ((l = map.get(name)) == null && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException _) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
        return l;
    }

    /** The port in the URL the node is told, when the hub is not on 443 (§8.2). */
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
