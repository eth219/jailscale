package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import java.io.IOException;

/** Invite issuance from nodes and from the admin CLI (ARCHITECTURE.md §10). */
final class Invites {

    static final int DEFAULT_USES = 1;
    static final long DEFAULT_TTL_SECONDS = 24 * 3600;
    static final long CODE_TTL_SECONDS = 10 * 60;

    private final HubConfig config;
    private final Store store;

    Invites(HubConfig config, Store store) {
        this.config = config;
        this.store = store;
    }

    /** Creates an invite and returns the secrets (the store keeps only hashes). */
    record Created(Store.InviteRec rec, String url, String code) {}

    Created create(String user, int uses, long ttlSeconds, String createdBy, boolean admin) throws IOException {
        String token = Tokens.inviteToken();
        String code = Tokens.shortCode();
        Store.InviteRec rec = store.createInvite(token, Tokens.normalizeCode(code), user,
            uses > 0 ? uses : DEFAULT_USES, ttlSeconds > 0 ? ttlSeconds : DEFAULT_TTL_SECONDS,
            CODE_TTL_SECONDS, createdBy, admin);
        return new Created(rec, config.baseUrl() + "/join/" + token, code);
    }

    /** A node asked over the control channel. */
    Message createForNode(NodeSession s, Message.InviteCreate ic) throws IOException {
        Store.NodeRec node = s.node();
        if (node == null) {
            return new Message.Error(ic.type(), "not-registered");
        }
        boolean admin = store.isAdmin(node.user());
        if (HubConfig.POLICY_ADMINS.equals(store.setting(Store.SETTING_INVITE_POLICY, HubConfig.POLICY_MEMBERS)) && !admin && !ic.self()) {
            return new Message.Error(ic.type(), "policy: only admins may invite new users");
        }
        String user = ic.self() ? node.user() : ic.user();
        Created c = create(user, ic.uses(), ic.ttlSeconds(), node.user(), false);
        return new Message.InviteCreated(c.url(), c.code(), c.rec().expiresAt());
    }
}
