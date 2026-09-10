package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.util.Log;
import java.io.IOException;

/** Registration decisions (DESIGN.md §11.3 to §11.5). */
final class Registrar {

    private static final Log LOG = Log.get("registrar");
    private static final int MAX_PENDING_PER_IP = 5;

    private final HubConfig config;
    private final Store store;

    Registrar(HubConfig config, Store store) {
        this.config = config;
        this.store = store;
    }

    /** Result of a registration attempt: the response plus the node record if approved. */
    record Decision(Message.RegisterResponse response, Store.NodeRec node) {}

    Decision decide(String mkey, Message.RegisterRequest req, String ip) throws IOException {
        Store.NodeRec existing = store.node(mkey);
        if (existing != null) {
            return approved(existing);
        }
        String hostname = clean(req.hostname(), 64, "node");
        String os = clean(req.os(), 32, "");
        String self = req.user() == null ? null : clean(req.user(), 64, null);

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
