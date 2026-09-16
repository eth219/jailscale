package io.jailscale.hub;

import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Args;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Admin commands over the state-directory socket (ARCHITECTURE.md §6.3). Socket permissions are the auth. */
final class AdminIpc implements Ipc.Handler {

    /** What {@code jailhub setting} may write, and to what. */
    static final Map<String, List<String>> SETTING_VALUES = Map.of(
        Store.SETTING_INVITE_POLICY, List.of(HubConfig.POLICY_MEMBERS, HubConfig.POLICY_ADMINS),
        Store.SETTING_REGISTRATION, List.of("invite", "open"),
        Store.SETTING_KNOCK, List.of("on", "off"),
        Store.SETTING_AUTO_PROMOTE, List.of("on", "off"));

    /**
     * The settings whose value is text rather than one of a fixed few (#99), and what each will
     * take. A URL is checked for its scheme rather than parsed into a link and hoped for: this
     * value ends up in an {@code href} on a page anyone can load, and {@code javascript:} in an
     * operator's typo is not something to find out about from a visitor. Empty clears.
     */
    static final Map<String, java.util.function.Predicate<String>> SETTING_TEXT = Map.of(
        Store.SETTING_OPERATOR, v -> v.length() <= 120,
        Store.SETTING_CONTACT, v -> v.length() <= 200 && (v.startsWith("https://") || v.startsWith("mailto:")),
        Store.SETTING_TERMS, v -> v.length() <= 200 && v.startsWith("https://"));

    /** What to say when one of the above refuses a value. */
    private static String textSettingRule(String key) {
        if (key.equals(Store.SETTING_OPERATOR)) {
            return "a name, up to 120 characters, or empty to clear";
        }
        return key.equals(Store.SETTING_CONTACT)
            ? "an https:// or mailto: URL, up to 200 characters, or empty to clear"
            : "an https:// URL, up to 200 characters, or empty to clear";
    }

    private final Hub hub;

    AdminIpc(Hub hub) {
        this.hub = hub;
    }

    @Override
    public void handle(JsonObject req, Ipc.Reply reply) throws Exception {
        String cmd = req.string("cmd");
        Store store = hub.store();
        switch (cmd) {
            case "status" -> reply.done(statusReply(store));
            case "address-check" -> {
                // Asked for, so it runs now rather than at the next hourly pass (§7.2): the reason
                // to type this is having just edited a record. Refused on the terms the loop waits
                // on -- off, a standby, a delegated hub still finding its own address -- and no
                // others: whether the certificate came from ACME is the loop's business and not this
                // command's, because an operator who asks has said which deployment this is.
                String blocker = hub.addressCheckBlocker();
                if (blocker != null) {
                    throw new IllegalArgumentException(blocker);
                }
                reply.done(JsonObject.builder().put("ok", true).put("addressCheck", hub.checkAddress().json()));
            }
            case "availability-reset" -> {
                // The record restarts now: an operator who has finished a day of deliberate restarts
                // does not want them counted against the service from here on (§13.2).
                hub.availability().reset(System.currentTimeMillis());
                reply.done(JsonObject.builder().put("ok", true).put("since", System.currentTimeMillis() / 1000));
            }
            case "promote" -> {
                hub.promote();
                reply.done(JsonObject.builder().put("ok", true).put("role", hub.role())
                    .put("next", "point " + hub.config().hostname() + " at this host; restart the old primary with --peer https://"
                        + hub.config().hostname()));
            }

            case "node-list" -> {
                List<Object> rows = new ArrayList<>();
                for (Store.NodeRec n : store.nodes()) {
                    NodeGroup g = hub.registry().get(n.mkey());
                    rows.add(JsonObject.builder().put("id", n.id()).put("mkey", n.mkey()).put("user", n.user())
                        .put("hostname", n.hostname()).put("os", n.os())
                        .put("ip", g == null ? null : g.remoteIp())
                        .put("online", g != null).build().asMap());
                }
                List<Object> pend = new ArrayList<>();
                for (Store.PendingRec p : store.pending()) {
                    pend.add(JsonObject.builder().put("mkey", p.mkey()).put("hostname", p.hostname()).put("os", p.os())
                        .put("ip", p.ip()).put("user", p.user()).put("at", p.at()).build().asMap());
                }
                reply.done(JsonObject.builder().put("ok", true).put("nodes", rows).put("pending", pend));
            }
            case "handoff" -> {
                hub.handoff();
                reply.ok();
            }
            case "node-approve" -> {
                String mkey = resolveMkey(req.string("mkey"));
                Store.NodeRec n = hub.registrar().approvePending(mkey, req.optString("user", null));
                NodeGroup g = hub.registry().get(mkey);
                if (g != null && g.primary() != null) {
                    g.primary().approved(n);
                }
                reply.done(JsonObject.builder().put("ok", true).put("id", n.id()).put("user", n.user()));
            }
            case "node-deny" -> {
                store.clearPending(resolveMkey(req.string("mkey")));
                reply.ok();
            }
            case "node-remove" -> {
                String mkey = resolveMkey(req.string("mkey"));
                store.removeNode(mkey);
                NodeGroup g = hub.registry().get(mkey);
                if (g != null) {
                    g.goodbyeAll("revoked");
                }
                reply.ok();
            }
            case "node-rename" -> {
                store.renameNode(resolveMkey(req.string("mkey")), req.string("user"));
                reply.ok();
            }
            case "name-list" -> {
                List<Object> rows = new ArrayList<>();
                for (Store.NameRec n : store.names()) {
                    Links.Link l = hub.links().byName(n.name());
                    rows.add(JsonObject.builder().put("name", n.name()).put("user", n.user()).put("mkey", n.mkey())
                        .put("local", n.local()).put("online", l != null).build().asMap());
                }
                reply.done(JsonObject.builder().put("ok", true).put("names", rows));
            }
            case "name-reassign" -> {
                store.reassignName(req.string("name"), req.string("user"));
                reply.ok();
            }
            case "name-release" -> {
                store.releaseName(req.string("name"));
                hub.links().releasedByOperator(req.string("name"), false); // §11.4
                reply.ok();
            }
            case "domain-list" -> {
                List<Object> rows = new ArrayList<>();
                for (Store.DomainRec d : store.domains()) {
                    rows.add(JsonObject.builder().put("domain", d.domain()).put("user", d.user()).put("mkey", d.mkey())
                        .put("open", hub.links().byDomain(d.domain()) != null).build().asMap());
                }
                reply.done(JsonObject.builder().put("ok", true).put("domains", rows));
            }
            case "domain-release" -> {
                store.releaseDomain(req.string("domain"));
                hub.links().releasedByOperator(req.string("domain"), true);
                reply.ok();
            }
            case "ban-list" -> {
                List<Object> rows = new ArrayList<>();
                for (Store.BanRec b : store.bans()) {
                    rows.add(JsonObject.builder().put("cidr", b.cidr()).put("reason", b.reason()).put("at", b.at()).build().asMap());
                }
                reply.done(JsonObject.builder().put("ok", true).put("bans", rows));
            }
            case "ban-add" -> {
                String cidr = req.string("cidr");
                if (Bans.parse(cidr, null, 0) == null) {
                    reply.error("not an address or CIDR block: " + cidr);
                    return;
                }
                store.addBan(cidr, req.optString("reason", null));
                // Disconnect whatever that address currently has, or the ban only applies next time.
                int dropped = 0;
                for (NodeGroup g : hub.registry().all()) {
                    if (hub.bans().isBanned(g.remoteIp())) {
                        g.goodbyeAll(io.jailscale.proto.control.Message.Goodbye.BANNED);
                        dropped++;
                    }
                }
                reply.done(JsonObject.builder().put("ok", true).put("cidr", cidr).put("disconnected", dropped));
            }
            case "ban-remove" -> {
                store.removeBan(req.string("cidr"));
                reply.ok();
            }
            case "user-list" -> reply.done(JsonObject.builder().put("ok", true).put("users", new ArrayList<>(store.users())));
            case "user-remove" -> {
                String user = req.string("user");
                for (Store.NodeRec n : store.nodes()) {
                    if (n.user().equals(user)) {
                        store.removeNode(n.mkey());
                        NodeGroup g = hub.registry().get(n.mkey());
                        if (g != null) {
                            g.goodbyeAll("revoked");
                        }
                    }
                }
                store.removeAdmin(user);
                reply.ok();
            }
            case "invite-create" -> {
                Invites.Created c = hub.invites().create(req.optString("user", null), req.optInt("uses", 0),
                    req.has("ttl") ? req.lng("ttl") : 0, "admin-cli", req.optBool("admin", false));
                reply.done(JsonObject.builder().put("ok", true).put("id", c.rec().id()).put("url", c.url())
                    .put("code", c.code()).put("expiresAt", c.rec().expiresAt()));
            }
            case "invite-list" -> {
                List<Object> rows = new ArrayList<>();
                for (Store.InviteRec r : store.invites()) {
                    rows.add(JsonObject.builder().put("id", r.id()).put("user", r.user()).put("usesLeft", r.usesLeft())
                        .put("expiresAt", r.expiresAt()).put("createdBy", r.createdBy()).put("admin", r.admin()).build().asMap());
                }
                reply.done(JsonObject.builder().put("ok", true).put("invites", rows));
            }
            case "invite-revoke" -> {
                store.revokeInvite(req.string("id"));
                reply.ok();
            }
            case "authkey-create" -> {
                String owner = req.optString("owner", null);
                String tag = req.optString("tag", null);
                if ((owner == null) == (tag == null)) {
                    throw new IllegalArgumentException("exactly one of --owner or --tag");
                }
                String secret = Tokens.authKey();
                Store.AuthKeyRec r = store.createAuthKey(secret, owner, tag, req.optInt("uses", 1),
                    req.has("ttl") ? req.lng("ttl") : 7 * 86400);
                reply.done(JsonObject.builder().put("ok", true).put("id", r.id()).put("key", secret).put("expiresAt", r.expiresAt()));
            }
            case "authkey-list" -> {
                List<Object> rows = new ArrayList<>();
                for (Store.AuthKeyRec r : store.authKeys()) {
                    rows.add(JsonObject.builder().put("id", r.id()).put("owner", r.owner()).put("tag", r.tag())
                        .put("usesLeft", r.usesLeft()).put("expiresAt", r.expiresAt()).build().asMap());
                }
                reply.done(JsonObject.builder().put("ok", true).put("authKeys", rows));
            }
            case "authkey-revoke" -> {
                store.revokeAuthKey(req.string("id"));
                reply.ok();
            }
            case "admin-add" -> {
                store.addAdmin(req.string("user"));
                reply.ok();
            }
            case "admin-remove" -> {
                store.removeAdmin(req.string("user"));
                reply.ok();
            }
            case "admin-login-link" -> reply.done(JsonObject.builder().put("ok", true).put("url", hub.adminWeb().loginLink("shell", true))
                .put("expiresAt", System.currentTimeMillis() + AdminWeb.LOGIN_LINK_TTL_MS));
            case "setting" -> {
                String key = req.string("key");
                // Trimmed before anything looks at it, and for every setting rather than only the
                // text ones. For those it is what keeps a value of spaces from being a third state
                // -- neither refused nor cleared, with the section on the page still drawn around a
                // blank name. For the fixed-value ones it is what keeps `knock "off "`, which a
                // shell or a copied line hands over often enough, from being refused with "knock is
                // on or off, not off": an error whose difference from the value is invisible.
                String value = req.string("value").strip();
                java.util.function.Predicate<String> text = SETTING_TEXT.get(key);
                if (text != null) {
                    // Empty is how a value is taken back off the page, so it is allowed past the
                    // rule rather than being a rule every one of them has to remember to permit.
                    if (!value.isEmpty() && !text.test(value)) {
                        reply.error(key + " takes " + textSettingRule(key));
                        return;
                    }
                    store.setSetting(key, value);
                    reply.ok();
                    return;
                }
                List<String> allowed = SETTING_VALUES.get(key);
                if (allowed == null) {
                    java.util.TreeSet<String> known = new java.util.TreeSet<>(SETTING_VALUES.keySet());
                    known.addAll(SETTING_TEXT.keySet());
                    reply.error("no such setting " + key + " (" + String.join(", ", known) + ")");
                    return;
                }
                // Unchecked, a typo did not fail here: it was stored, and every reader asks
                // `"open".equals(...)` or `"off".equals(...)`, so `setting knock of` answered ok
                // and left knocking on. The /admin form never had the hole because it maps its
                // radio buttons onto the two values instead of passing a string through.
                if (!allowed.contains(value)) {
                    reply.error(key + " is " + String.join(" or ", allowed) + ", not " + value);
                    return;
                }
                store.setSetting(key, value);
                reply.ok();
            }
            case "key-rotate" -> {
                long grace = req.has("grace") ? req.lng("grace") : 30 * 86400;
                long activatesAt = hub.rotateKey(grace);
                reply.done(JsonObject.builder().put("ok", true).put("nextHubKey", hub.keys().nextPublicText())
                    .put("activatesAt", activatesAt));
            }
            default -> reply.error("unknown command " + cmd);
        }
    }

    private JsonObject.Builder statusReply(Store store) {
        JsonObject.Builder b = JsonObject.builder()
            .put("ok", true)
            .put("hostname", hub.config().hostname())
            .put("hubKey", hub.keys().publicText())
            .put("nextHubKey", hub.keys().nextPublicText())
            .put("nodes", store.nodes().size())
            .put("links", hub.links().count())
            .put("certKeyId", hub.tls().isLoaded() ? hub.tls().keyId() : null)
            .put("online", hub.registry().size())
            .put("pending", store.pending().size())
            .put("invites", store.invites().size())
            .put("admins", new ArrayList<>(store.admins()))
            .put("registration", store.setting(Store.SETTING_REGISTRATION, "invite"))
            .put("invitePolicy", store.setting(Store.SETTING_INVITE_POLICY, "members"))
            .put("knock", store.setting(Store.SETTING_KNOCK, "on"))
            .put("role", hub.role())
            .put("epoch", hub.epoch())
            .put("autoPromote", hub.autoPromote() ? "on" : "off")
            .put("standbys", standbys());
        // §7.2: the verdict that stands, so the operator who missed the line at boot has somewhere
        // to look it up. Absent, rather than "unknown", where the check is off or has not run yet:
        // a field that says nothing is worse than a field that is not there.
        Reachability.Status address = hub.addressStatus();
        if (address != null) {
            b.put("addressCheck", address.json());
        }
        PeerClient pc = hub.peerClient();
        if (hub.isStandby() && pc != null) {
            b.put("primary", pc.primaryHost()).put("inSync", pc.isSynced());
        }
        return b;
    }

    private List<Object> standbys() {
        List<Object> rows = new ArrayList<>();
        for (Peers.Session s : hub.peers().all()) {
            rows.add(JsonObject.builder().put("host", s.name()).put("ip", s.remoteIp()).put("connectedAt", s.connectedAt())
                .put("eventsSent", s.eventsSent()).build().asMap());
        }
        return rows;
    }

    /** Accepts a full mkey: text, a unique prefix of one, or a node id. */
    private String resolveMkey(String ref) {
        List<String> candidates = new ArrayList<>();
        for (Store.NodeRec n : hub.store().nodes()) {
            if (n.mkey().equals(ref) || Long.toString(n.id()).equals(ref)) {
                return n.mkey();
            }
            if (n.mkey().startsWith(ref) || n.mkey().substring(5).startsWith(ref)) {
                candidates.add(n.mkey());
            }
        }
        for (Store.PendingRec p : hub.store().pending()) {
            if (p.mkey().equals(ref)) {
                return p.mkey();
            }
            if (p.mkey().startsWith(ref) || p.mkey().substring(5).startsWith(ref)) {
                candidates.add(p.mkey());
            }
        }
        if (candidates.size() == 1) {
            return candidates.get(0);
        }
        throw new IllegalArgumentException(candidates.isEmpty() ? "no node matches " + ref : "ambiguous: " + ref);
    }

    /** Client side: translates {@code jailhub <words>} into an IPC request. */
    static JsonObject requestFor(Args a) {
        String w0 = a.positional(0);
        String w1 = a.positional(1);
        String cmd = w1 == null || w0.equals("setting") ? w0 : w0 + "-" + w1;
        JsonObject.Builder b = JsonObject.builder().put("cmd", cmd);
        switch (cmd) {
            case "node-approve", "node-deny", "node-remove", "node-rename" -> b.put("mkey", need(a.positional(2), "<node>")).put("user", a.get("user"));
            case "user-remove" -> b.put("user", need(a.positional(2), "<user>"));
            case "ban-add" -> b.put("cidr", need(a.positional(2), "<ip|cidr>")).put("reason", a.get("reason"));
            case "ban-remove" -> b.put("cidr", need(a.positional(2), "<ip|cidr>"));
            case "name-reassign" -> b.put("name", need(a.positional(2), "<name>")).put("user", a.require("user"));
            case "name-release" -> b.put("name", need(a.positional(2), "<name>"));
            case "domain-release" -> b.put("domain", need(a.positional(2), "<domain>"));
            case "invite-create" -> b.put("user", a.get("user")).put("uses", a.integer("uses", 0))
                .put("ttl", a.has("ttl") ? a.seconds("ttl", 0) : null).put("admin", a.flag("admin"));
            case "invite-revoke", "authkey-revoke" -> b.put("id", need(a.positional(2), "<id>"));
            case "authkey-create" -> b.put("owner", a.get("owner")).put("tag", a.get("tag")).put("uses", a.integer("uses", 1))
                .put("ttl", a.has("ttl") ? a.seconds("ttl", 0) : null);
            case "admin-add", "admin-remove" -> b.put("user", need(a.positional(2), "<user>"));
            case "key-rotate" -> b.put("grace", a.has("grace") ? a.seconds("grace", 0) : null);
            case "setting" -> b.put("key", need(a.positional(1), "<key>")).put("value", need(a.positional(2), "<value>"));
            default -> { }
        }
        return b.build();
    }

    private static String need(String v, String what) {
        if (v == null) {
            throw new IllegalArgumentException("missing " + what);
        }
        return v;
    }

    static void printReply(JsonObject r) throws IOException {
        if (!r.optBool("ok", false)) {
            throw new IOException(r.optString("error", "failed"));
        }
        System.out.println(r);
    }
}
