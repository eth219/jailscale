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
        Store.SETTING_KNOCK, List.of("on", "off"));

    /**
     * The settings whose value is text rather than one of a fixed few (#99), and what each will
     * take. A URL is checked for its scheme rather than parsed into a link and hoped for: this
     * value ends up in an {@code href} on a page anyone can load, and {@code javascript:} in an
     * operator's typo is not something to find out about from a visitor. Empty clears.
     */
    static final Map<String, java.util.function.Predicate<String>> SETTING_TEXT = Map.of(
        Store.SETTING_OPERATOR, v -> v.length() <= 120,
        Store.SETTING_CONTACT, v -> v.length() <= 200 && HttpFront.linkable(v),
        Store.SETTING_TERMS, v -> v.length() <= 200 && HttpFront.https(v));

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
                // on -- off, or a delegated hub still finding its own address -- and no others:
                // whether the certificate came from ACME is the loop's business and not this
                // command's, because an operator who asks has said which deployment this is.
                String blocker = hub.addressCheckBlocker();
                if (blocker != null) {
                    throw new IllegalArgumentException(blocker);
                }
                reply.done(JsonObject.builder().put("ok", true).put("addressCheck", hub.checkAddress().json()));
            }
            case "node-list" -> {
                List<Object> rows = store.nodes().stream().<Object>map(n -> {
                    NodeGroup g = hub.registry().get(n.mkey());
                    return JsonObject.builder().put("id", n.id()).put("mkey", n.mkey()).put("user", n.user())
                        .put("hostname", n.hostname()).put("os", n.os())
                        .put("ip", g == null ? null : g.remoteIp())
                        .put("online", g != null).build().asMap();
                }).toList();
                List<Object> pend = store.pending().stream().<Object>map(p -> JsonObject.builder()
                    .put("mkey", p.mkey()).put("hostname", p.hostname()).put("os", p.os())
                    .put("ip", p.ip()).put("user", p.user()).put("at", p.at()).build().asMap()).toList();
                reply.done(JsonObject.builder().put("ok", true).put("nodes", rows).put("pending", pend));
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
                List<Object> rows = store.names().stream().<Object>map(n -> JsonObject.builder()
                    .put("name", n.name()).put("user", n.user()).put("mkey", n.mkey())
                    .put("local", n.local()).put("online", hub.links().byName(n.name()) != null).build().asMap()).toList();
                reply.done(JsonObject.builder().put("ok", true).put("names", rows));
            }
            case "name-reassign" -> {
                store.reassignName(req.string("name"), req.string("user"));
                reply.ok();
            }
            case "name-release" -> {
                store.releaseName(req.string("name"));
                hub.links().releasedByOperator(req.string("name")); // §11.4
                reply.ok();
            }
            case "ban-list" -> {
                List<Object> rows = store.bans().stream().<Object>map(b -> JsonObject.builder()
                    .put("cidr", b.cidr()).put("reason", b.reason()).put("at", b.at()).build().asMap()).toList();
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
                List<Object> rows = store.invites().stream().<Object>map(r -> JsonObject.builder()
                    .put("id", r.id()).put("user", r.user()).put("usesLeft", r.usesLeft())
                    .put("expiresAt", r.expiresAt()).put("createdBy", r.createdBy()).put("admin", r.admin()).build().asMap()).toList();
                reply.done(JsonObject.builder().put("ok", true).put("invites", rows));
            }
            case "invite-revoke" -> {
                store.revokeInvite(req.string("id"));
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
            .put("visitors", JsonObject.builder()
                .put("now", hub.router().visitorsInFlight())
                .put("routed", hub.router().visitorsRouted())
                .put("refused", hub.router().visitorsRefused())
                .put("refusedCapacity", hub.router().visitorsRefusedCapacity())
                .build())
            // The receive budget (ARCHITECTURE.md §5.3). Peak against limit is what says whether the
            // bound is the thing holding the queues down, and reclaimed says how many visitor
            // streams it cost -- the pair measure.sh gates the SLOW axis on (§14), and the one
            // number here that an operator watches rather than reads once.
            .put("receiveBudget", JsonObject.builder()
                .put("limit", hub.flowBudget().limitBytes())
                .put("queued", hub.flowBudget().usedBytes())
                .put("peak", hub.flowBudget().peakBytes())
                .put("reclaimed", hub.flowBudget().reclaimedStreams())
                .build())
            .put("pending", store.pending().size())
            .put("invites", store.invites().size())
            .put("admins", new ArrayList<>(store.admins()))
            .put("registration", store.setting(Store.SETTING_REGISTRATION, "invite"))
            .put("invitePolicy", store.setting(Store.SETTING_INVITE_POLICY, "members"))
            .put("knock", store.setting(Store.SETTING_KNOCK, "on"))
            .put("knockQueue", store.pending().size());
        // §7.2: the verdict that stands, so the operator who missed the line at boot has somewhere
        // to look it up. Absent, rather than "unknown", where the check is off or has not run yet:
        // a field that says nothing is worse than a field that is not there.
        Reachability.Status address = hub.addressStatus();
        if (address != null) {
            b.put("addressCheck", address.json());
        }
        return b;
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
            case "invite-create" -> b.put("user", a.get("user")).put("uses", a.integer("uses", 0))
                .put("ttl", a.has("ttl") ? a.seconds("ttl", 0) : null).put("admin", a.flag("admin"));
            case "invite-revoke" -> b.put("id", need(a.positional(2), "<id>"));
            case "admin-add", "admin-remove" -> b.put("user", need(a.positional(2), "<user>"));
            case "key-rotate" -> b.put("grace", a.has("grace") ? a.seconds("grace", 0) : null);
            case "setting" -> {
                // A value with a space in it is several positionals, and taking the first was
                // silent: `jailhub setting operator Example Ltd` stored "Example" and replied ok.
                // The first setting whose value is prose is the first one that could hit this.
                // The line it suggests is the whole value and not the first two words of it: an
                // error that shows something other than what was typed is one more thing to work
                // out, and the words are all right here.
                List<String> words = a.positional();
                if (words.size() > 3) {
                    throw new IllegalArgumentException("a value with spaces has to be quoted: "
                        + "jailhub setting " + words.get(1) + " \""
                        + String.join(" ", words.subList(2, words.size())) + "\"");
                }
                b.put("key", need(a.positional(1), "<key>")).put("value", need(a.positional(2), "<value>"));
            }
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
