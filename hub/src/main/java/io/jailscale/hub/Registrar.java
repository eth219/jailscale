package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.util.Log;
import java.io.IOException;

/** Registration decisions (ARCHITECTURE.md §10). */
final class Registrar {

    private static final Log LOG = Log.get("registrar");
    private static final int MAX_PENDING_PER_IP = 5;
    /**
     * Credential attempts per source address (ARCHITECTURE.md §11.5): invite tokens, invite codes and
     * auth-keys. An invite code is eight characters, so guessing has to be slow to be hopeless.
     * The burst lets a site onboard a batch of machines from one address in one go; the sustained
     * rate of twelve a minute is what a guesser is left with.
     */
    static final int CREDENTIAL_BURST = 20;
    static final double CREDENTIAL_PER_SECOND = 0.2;
    /**
     * New registrations per source address when the operator has opened registration. Nothing is
     * presented in that case, so the credential bucket never sees these: without a limit of its
     * own, one address can register nodes without bound and claim public names under the hub
     * domain. Five at once, then one every twelve minutes.
     */
    static final int OPEN_BURST = 5;
    static final double OPEN_PER_SECOND = 1.0 / 720;

    private final HubConfig config;
    private final Store store;
    private final Bans bans;
    private final RateLimiter credentials = new RateLimiter(CREDENTIAL_BURST, CREDENTIAL_PER_SECOND);
    private final RateLimiter openRegistrations = new RateLimiter(OPEN_BURST, OPEN_PER_SECOND);

    Registrar(HubConfig config, Store store, Bans bans) {
        this.config = config;
        this.store = store;
        this.bans = bans;
    }

    /** Result of a registration attempt: the response plus the node record if approved. */
    record Decision(Message.RegisterResponse response, Store.NodeRec node) {}

    Decision decide(String mkey, Message.RegisterRequest req, String ip) throws IOException {
        // Before anything else, including the check for a node we already know: a ban has to
        // cover the node an operator just removed, or removing it would achieve nothing.
        if (bans != null && bans.isBanned(ip)) {
            bans.logRefusal(ip, "registration");
            return new Decision(Message.RegisterResponse.rejected("banned"), null);
        }
        Store.NodeRec existing = store.node(mkey);
        if (existing != null) {
            return approved(existing);
        }
        String hostname = clean(req.hostname(), 64, "node");
        String os = clean(req.os(), 32, "");
        String self = req.user() == null ? null : clean(req.user(), 64, null);

        // A node the hub already knows returned above, so this only ever throttles new arrivals.
        if ((req.invite() != null || req.code() != null || req.authKey() != null) && !credentials.allow(ip)) {
            LOG.warn("too many credential attempts from {}, refusing", ip);
            return rejected("rate-limited");
        }
        if (req.invite() != null) {
            Store.InviteRec inv = store.consumeInvite(req.invite());
            return inv == null ? rejected("invite-invalid") : register(mkey, inv.user() != null ? inv.user() : self, hostname, os, inv.admin());
        }
        if (req.code() != null) {
            Store.InviteRec inv = store.consumeCode(Tokens.normalizeCode(req.code()));
            return inv == null ? rejected("code-invalid") : register(mkey, inv.user() != null ? inv.user() : self, hostname, os, inv.admin());
        }
        if (req.authKey() != null) {
            Store.AuthKeyRec ak = store.consumeAuthKey(req.authKey());
            if (ak == null) {
                return rejected("authkey-invalid");
            }
            String owner = ak.owner() != null ? ak.owner() : "tag:" + ak.tag();
            return register(mkey, owner, hostname, os, false);
        }
        // knock
        if ("off".equals(store.setting(Store.SETTING_KNOCK, "on"))) {
            return rejected("knock-disabled");
        }
        if ("open".equals(store.setting(Store.SETTING_REGISTRATION, "invite"))) {
            if (!openRegistrations.allow(ip)) {
                LOG.warn("too many open registrations from {}, refusing", ip);
                return rejected("rate-limited");
            }
            return register(mkey, self != null ? self : hostname, hostname, os, false);
        }
        if (store.pending(mkey) == null) {
            if (store.pendingCountFrom(ip) >= MAX_PENDING_PER_IP) {
                return rejected("too-many-pending");
            }
            store.addPending(mkey, hostname, os, ip, self);
            LOG.info("knock from {} ({}) queued for approval", hostname, mkey);
        }
        return new Decision(Message.RegisterResponse.pending(), null);
    }

    /** Admin approval of a pending node. */
    Store.NodeRec approvePending(String mkey, String user) throws IOException {
        Store.PendingRec p = store.pending(mkey);
        if (p == null) {
            throw new IllegalArgumentException("no pending node " + mkey);
        }
        String u = user != null ? user : p.user() != null ? p.user() : p.hostname();
        Store.NodeRec n = store.registerNode(mkey, u, p.hostname(), p.os());
        store.clearPending(mkey);
        return n;
    }

    private Decision register(String mkey, String user, String hostname, String os, boolean admin) throws IOException {
        if (user == null || user.isBlank()) {
            return rejected("user-required");
        }
        Store.NodeRec n = store.registerNode(mkey, user, hostname, os);
        store.clearPending(mkey);
        if (admin || !store.hasAnyAdmin()) {
            store.addAdmin(user);
            LOG.info("{} is now an admin", user);
        }
        LOG.info("registered node {} ({}) for {}", n.id(), hostname, user);
        return approved(n);
    }

    private static Decision approved(Store.NodeRec n) {
        return new Decision(Message.RegisterResponse.approved(n.id(), n.user()), n);
    }

    private static Decision rejected(String reason) {
        return new Decision(Message.RegisterResponse.rejected(reason), null);
    }

    static String clean(String s, int max, String dflt) {
        if (s == null || s.isBlank()) {
            return dflt;
        }
        String t = s.strip().replaceAll("[\\p{Cntrl}]", "");
        return t.length() > max ? t.substring(0, max) : t;
    }
}
