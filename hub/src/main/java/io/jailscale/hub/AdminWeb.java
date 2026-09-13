package io.jailscale.hub;

import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The minimal admin page (ARCHITECTURE.md §6.3): no password, no IdP. An admin node asks for a
 * one-time login link over the control channel; visiting it sets a session cookie. Server
 * rendered HTML, no JavaScript, forms with a session-bound CSRF token.
 */
final class AdminWeb {

    private static final Log LOG = Log.get("admin");
    static final long LOGIN_LINK_TTL_MS = 60_000;
    static final long SESSION_TTL_MS = 12 * 3600 * 1000L;
    static final String COOKIE = "__Host-jailhub_admin";

    private record Login(String user, boolean shell, long expiresAt) {}

    /** Package-private so the status page can render admin controls for a signed-in admin. */
    record Session(String user, boolean shell, long expiresAt, String csrf) {}

    private final Hub hub;
    private final Map<String, Login> logins = new ConcurrentHashMap<>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    AdminWeb(Hub hub) {
        this.hub = hub;
    }

    /** A one-time URL that logs {@code user} in for the next minute. */
    String loginLink(String user) {
        return loginLink(user, false);
    }

    /**
     * As above, but {@code shell} marks a link issued over the admin IPC socket. That caller is
     * authorised by the socket's file permissions (§6.3) and has no entry in the admin list, so
     * it is exempt from the per-request admin re-check rather than being looked up there.
     */
    String loginLink(String user, boolean shell) {
        prune();
        String token = Tokens.inviteToken();
        logins.put(token, new Login(user, shell, System.currentTimeMillis() + LOGIN_LINK_TTL_MS));
        return hub.config().baseUrl() + "/admin/login/" + token;
    }

    /**
     * Drops what has expired. Nothing else removed these: an unused login token and every
     * logged-out-by-time session stayed in the map for the life of the process.
     */
    private void prune() {
        long now = System.currentTimeMillis();
        logins.entrySet().removeIf(e -> now > e.getValue().expiresAt());
        sessions.entrySet().removeIf(e -> now > e.getValue().expiresAt());
    }

    HttpResponse handle(HttpRequest req) throws IOException {
        String path = req.path();
        prune();
        if (path.startsWith("/admin/login/")) {
            Login l = logins.remove(path.substring("/admin/login/".length()));
            if (l == null || System.currentTimeMillis() > l.expiresAt()) {
                return HttpResponse.html(403, page("login link expired", "<p>Run <code>jailscale admin</code> on the node again.</p>"));
            }
            String sid = Tokens.inviteToken();
            sessions.put(sid, new Session(l.user(), l.shell(), System.currentTimeMillis() + SESSION_TTL_MS, Tokens.inviteToken()));
            LOG.info("admin {} logged in", l.user());
            return HttpResponse.redirect("/admin").header("Set-Cookie", cookie(sid, SESSION_TTL_MS / 1000));
        }
        Session s = session(req);
        if (s == null) {
            return HttpResponse.html(403, page("jailhub admin", "<p>Run <code>jailscale admin</code> on an admin node to open a login link.</p>"));
        }
        // Admin rights are checked again on every request, not only when the link was issued.
        // Without this, `admin remove` left the removed admin's browser working until the twelve
        // hour session lapsed.
        if (!authorized(s)) {
            sessions.values().removeIf(v -> v == s);
            LOG.warn("session for {} is no longer an admin; signed out", s.user());
            return HttpResponse.html(403, page("not authorised", "<p>This account is no longer an admin.</p>"))
                .header("Set-Cookie", cookie("", 0));
        }
        if (req.method().equals("POST")) {
            Map<String, String> f = req.form();
            if (!secretEquals(s.csrf(), f.get("csrf"))) {
                return HttpResponse.text(403, "bad csrf token");
            }
            if (path.equals("/admin/logout")) {
                sessions.values().removeIf(v -> v == s);
                LOG.info("admin {} signed out", s.user());
                return HttpResponse.redirect("/admin").header("Set-Cookie", cookie("", 0));
            }
            try {
                act(path, f, s);
            } catch (IllegalArgumentException e) {
                return HttpResponse.html(400, page("error", "<p>" + HttpFront.escape(e.getMessage()) + "</p><p><a href=\"/admin\">Back</a></p>"));
            }
            // A form on the status page should not dump the admin on /admin afterwards.
            String back = f.get("back");
            return HttpResponse.redirect("/".equals(back) ? "/" : "/admin");
        }
        if (!path.equals("/admin") && !path.equals("/admin/")) {
            return HttpResponse.text(404, "not found");
        }
        return HttpResponse.html(200, render(s));
    }

    /**
     * The session behind this request when it belongs to a current admin, otherwise null. The
     * status page uses it to decide whether to render node controls; rights are re-checked here
     * rather than trusted from the cookie, the same as on {@code /admin} itself.
     */
    Session adminSession(HttpRequest req) {
        Session s = session(req);
        return s != null && authorized(s) ? s : null;
    }

    /** The local shell is authorised by the IPC socket's permissions; everyone else by the list. */
    private boolean authorized(Session s) {
        return s.shell() || hub.store().isAdmin(s.user());
    }

    /**
     * What to put in the Name box of a knock. The node's own suggestion, unless it names someone
     * who already exists here: an operator approving on autopilot would then be handing a stranger
     * another member's identity, and admin rights with it. An empty box asks them to choose.
     */
    private String suggestedName(Store.PendingRec p) {
        String suggested = p.user() == null ? p.hostname() : p.user();
        return hub.registrar().taken(suggested) ? "" : suggested;
    }

    /**
     * Registered nodes with the controls an admin has over them, and the current bans. Rendered
     * on {@code /admin} and, for a signed-in admin, on the status page; {@code back} is where the
     * POST returns to so a button pressed on one page does not land on the other.
     */
    String nodesAndBans(String csrf, String back) {
        StringBuilder b = new StringBuilder();
        Store store = hub.store();
        String backField = "<input type=hidden name=back value=\"" + HttpFront.escape(back) + "\">";

        b.append("<h2>Nodes</h2><table><tr><th>#</th><th>User</th><th>Host</th><th>Key</th><th>Address</th>")
            .append("<th>Status</th><th></th></tr>");
        for (Store.NodeRec n : store.nodes()) {
            NodeGroup g = hub.registry().get(n.mkey());
            String ip = g == null ? null : g.remoteIp();
            b.append("<tr><td>").append(n.id()).append("</td><td>").append(HttpFront.escape(n.user())).append("</td><td>")
                .append(HttpFront.escape(n.hostname())).append("</td><td><code>")
                .append(HttpFront.escape(n.mkey().substring(0, 17))).append("…</code></td><td>")
                .append(ip == null ? "—" : "<code>" + HttpFront.escape(ip) + "</code>").append("</td><td>")
                .append(g == null ? "offline" : "online (" + g.connections() + ")").append("</td><td>")
                .append("<form method=post action=/admin/node/remove style=\"display:inline\">").append(csrf).append(backField)
                .append("<input type=hidden name=mkey value=\"").append(HttpFront.escape(n.mkey()))
                .append("\"><button>Remove</button></form>");
            if (ip != null) {
                // Banning the address is separate from removing the node: removing it alone lets
                // the same machine walk back in, since a new machine key is free to make.
                b.append(" <form method=post action=/admin/ban/add style=\"display:inline\">").append(csrf).append(backField)
                    .append("<input type=hidden name=cidr value=\"").append(HttpFront.escape(ip))
                    .append("\"><input type=hidden name=reason value=\"banned from the node list\">")
                    .append("<button>Ban address</button></form>");
            }
            b.append("</td></tr>");
        }
        b.append("</table>");

        b.append("<h2>Bans</h2><p>Barred from registering and from reconnecting. Visitors are not affected.</p>");
        b.append("<table><tr><th>Address or block</th><th>Reason</th><th></th></tr>");
        for (Store.BanRec ban : store.bans()) {
            b.append("<tr><td><code>").append(HttpFront.escape(ban.cidr())).append("</code></td><td>")
                .append(ban.reason() == null ? "" : HttpFront.escape(ban.reason())).append("</td><td>")
                .append("<form method=post action=/admin/ban/remove>").append(csrf).append(backField)
                .append("<input type=hidden name=cidr value=\"").append(HttpFront.escape(ban.cidr()))
                .append("\"><button>Lift</button></form></td></tr>");
        }
        b.append("</table>");
        b.append("<form method=post action=/admin/ban/add>").append(csrf).append(backField)
            .append("<label>Address or CIDR <input name=cidr placeholder=\"203.0.113.0/24\" required></label> ")
            .append("<label>Reason <input name=reason></label> <button>Ban</button></form>");
        return b.toString();
    }

    /** {@code __Host-} forbids a Domain attribute and requires Path=/ and Secure. */
    private static String cookie(String sid, long maxAgeSeconds) {
        return COOKIE + "=" + sid + "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=" + maxAgeSeconds;
    }

    /**
     * Compares a presented secret against a stored one without returning at the first differing
     * byte (§11.6). Length still separates them, which is fine: these are fixed-width tokens.
     * Nothing here is reachable by walking a prefix of 128 random bits, so this is habit rather
     * than a fix -- but the habit is what keeps the next comparison honest.
     */
    private static boolean secretEquals(String stored, String presented) {
        if (presented == null) {
            return false;
        }
        return MessageDigest.isEqual(
            stored.getBytes(StandardCharsets.UTF_8), presented.getBytes(StandardCharsets.UTF_8));
    }

    private Session session(HttpRequest req) {
        String cookie = req.headers().get("Cookie");
        if (cookie == null) {
            return null;
        }
        for (String kv : cookie.split(";")) {
            String[] p = kv.trim().split("=", 2);
            if (p.length == 2 && p[0].equals(COOKIE)) {
                Session s = sessions.get(p[1]);
                if (s != null && System.currentTimeMillis() < s.expiresAt()) {
                    return s;
                }
            }
        }
        return null;
    }

    private void act(String path, Map<String, String> f, Session s) throws IOException {
        Store store = hub.store();
        switch (path) {
            case "/admin/approve" -> {
                String mkey = need(f, "mkey");
                Store.NodeRec n = hub.registrar().approvePending(mkey, blankToNull(f.get("user")));
                NodeGroup g = hub.registry().get(mkey);
                if (g != null && g.primary() != null) {
                    g.primary().approved(n);
                }
            }
            case "/admin/deny" -> store.clearPending(need(f, "mkey"));
            case "/admin/node/remove" -> {
                String mkey = need(f, "mkey");
                store.removeNode(mkey);
                NodeGroup g = hub.registry().get(mkey);
                if (g != null) {
                    g.goodbyeAll("revoked");
                }
            }
            case "/admin/ban/add" -> {
                String cidr = need(f, "cidr").trim();
                if (Bans.parse(cidr, null, 0) == null) {
                    throw new IllegalArgumentException("not an address or CIDR block: " + cidr);
                }
                store.addBan(cidr, blankToNull(f.get("reason")));
                // Disconnect what that address has open now, or the ban only bites next time.
                for (NodeGroup g : hub.registry().all()) {
                    if (hub.bans().isBanned(g.remoteIp())) {
                        g.goodbyeAll(io.jailscale.proto.control.Message.Goodbye.BANNED);
                    }
                }
            }
            case "/admin/ban/remove" -> store.removeBan(need(f, "cidr"));
            case "/admin/invite/create" -> {
                int uses = f.getOrDefault("uses", "1").isBlank() ? 1 : Integer.parseInt(f.get("uses").trim());
                long ttl = f.getOrDefault("ttl", "24h").isBlank() ? 86400 : io.jailscale.proto.util.Args.parseSeconds(f.get("ttl"));
                Invites.Created c = hub.invites().create(blankToNull(f.get("user")), uses, ttl, "admin:" + s.user(), false);
                lastInvite = c;
            }
            case "/admin/invite/revoke" -> store.revokeInvite(need(f, "id"));
            case "/admin/authkey/create" -> {
                String owner = blankToNull(f.get("owner"));
                String tag = blankToNull(f.get("tag"));
                if ((owner == null) == (tag == null)) {
                    throw new IllegalArgumentException("enter either owner or tag, not both");
                }
                // Blank means the default, as it does one form above and as omitting the flag
                // does on the CLI. Cleared fields used to reach parseInt and parseSeconds as "",
                // and the admin got a 400 quoting a Java parse error.
                int uses = f.getOrDefault("uses", "1").isBlank() ? 1 : Integer.parseInt(f.get("uses").trim());
                long ttl = f.getOrDefault("ttl", "7d").isBlank() ? 7 * 86400
                    : io.jailscale.proto.util.Args.parseSeconds(f.get("ttl"));
                String secret = Tokens.authKey();
                store.createAuthKey(secret, owner, tag, uses, ttl);
                lastAuthKey = secret;
            }
            case "/admin/authkey/revoke" -> store.revokeAuthKey(need(f, "id"));
            case "/admin/name/release" -> {
                String name = need(f, "name");
                store.releaseName(name);
                hub.links().releasedByOperator(name, false); // take it down now, and tell the node (§11.4)
            }
            case "/admin/domain/release" -> {
                String domain = need(f, "domain");
                store.releaseDomain(domain);
                hub.links().releasedByOperator(domain, true);
            }
            case "/admin/settings" -> {
                store.setSetting(Store.SETTING_INVITE_POLICY, "admins".equals(f.get("invitePolicy")) ? "admins" : "members");
                store.setSetting(Store.SETTING_REGISTRATION, "open".equals(f.get("registration")) ? "open" : "invite");
                store.setSetting(Store.SETTING_KNOCK, "off".equals(f.get("knock")) ? "off" : "on");
            }
            default -> throw new IllegalArgumentException("unknown action " + path);
        }
    }

    private volatile Invites.Created lastInvite;
    private volatile String lastAuthKey;

    private String render(Session s) {
        Store store = hub.store();
        StringBuilder b = new StringBuilder(8192);
        b.append("<p>").append(HttpFront.escape(hub.config().hostname())).append(" · signed in: <b>").append(HttpFront.escape(s.user())).append("</b>")
            .append(" · nodes ").append(store.nodes().size()).append(" · online ").append(hub.registry().size())
            .append(" · links ").append(hub.links().all().size()).append("</p>");
        String csrf = "<input type=hidden name=csrf value=\"" + s.csrf() + "\">";
        b.append("<form method=post action=/admin/logout>").append(csrf).append("<button>Sign out</button></form>");

        b.append("<h2>Pending approval</h2>");
        if (store.pending().isEmpty()) {
            b.append("<p>None</p>");
        }
        for (Store.PendingRec p : store.pending()) {
            b.append("<form method=post action=/admin/approve class=row>").append(csrf)
                .append("<input type=hidden name=mkey value=\"").append(HttpFront.escape(p.mkey())).append("\">")
                .append("<code>").append(HttpFront.escape(p.mkey().substring(0, 17))).append("…</code> ")
                .append(HttpFront.escape(p.hostname())).append(" (").append(HttpFront.escape(p.os())).append(", ").append(HttpFront.escape(String.valueOf(p.ip()))).append(") ")
                .append("Name <input name=user value=\"").append(HttpFront.escape(suggestedName(p))).append("\" size=12> ")
                .append("<button>Approve</button></form>")
                .append("<form method=post action=/admin/deny class=row>").append(csrf)
                .append("<input type=hidden name=mkey value=\"").append(HttpFront.escape(p.mkey())).append("\"><button>Deny</button></form>");
        }

        b.append(nodesAndBans(csrf, "/admin"));

        b.append("<h2>Names</h2><table><tr><th>Name</th><th>Owner</th><th>Target</th><th>Status</th><th></th></tr>");
        for (Store.NameRec n : store.names()) {
            b.append("<tr><td>").append(HttpFront.escape(n.name())).append("</td><td>").append(HttpFront.escape(n.user())).append("</td><td>")
                .append(HttpFront.escape(String.valueOf(n.local()))).append("</td><td>").append(hub.links().byName(n.name()) != null ? "open" : "closed").append("</td><td>")
                .append("<form method=post action=/admin/name/release>").append(csrf)
                .append("<input type=hidden name=name value=\"").append(HttpFront.escape(n.name())).append("\"><button>Release</button></form></td></tr>");
        }
        b.append("</table>");

        if (!store.domains().isEmpty()) {
            b.append("<h2>User domains</h2><table><tr><th>Domain</th><th>Owner</th><th>Status</th><th></th></tr>");
            for (Store.DomainRec d : store.domains()) {
                b.append("<tr><td>").append(HttpFront.escape(d.domain())).append("</td><td>").append(HttpFront.escape(d.user()))
                    .append("</td><td>").append(hub.links().byDomain(d.domain()) != null ? "open" : "closed").append("</td><td>")
                    .append("<form method=post action=/admin/domain/release>").append(csrf)
                    .append("<input type=hidden name=domain value=\"").append(HttpFront.escape(d.domain())).append("\"><button>Release</button></form></td></tr>");
            }
            b.append("</table>");
        }

        b.append("<h2>Invites</h2>");
        if (lastInvite != null) {
            b.append("<p class=new>New invite: <code>").append(HttpFront.escape(lastInvite.url())).append("</code> · code <code>")
                .append(HttpFront.escape(lastInvite.code())).append("</code></p>");
            lastInvite = null;
        }
        b.append("<form method=post action=/admin/invite/create class=row>").append(csrf)
            .append("Name <input name=user size=10> Uses <input name=uses value=1 size=3> TTL <input name=ttl value=24h size=5> <button>Create invite</button></form>");
        b.append("<table><tr><th>id</th><th>Name</th><th>Uses left</th><th>Expires</th><th>Created by</th><th></th></tr>");
        for (Store.InviteRec r : store.invites()) {
            b.append("<tr><td><code>").append(HttpFront.escape(r.id())).append("</code></td><td>").append(HttpFront.escape(String.valueOf(r.user())))
                .append("</td><td>").append(r.usesLeft()).append("</td><td>").append(new java.util.Date(r.expiresAt())).append("</td><td>")
                .append(HttpFront.escape(String.valueOf(r.createdBy()))).append("</td><td><form method=post action=/admin/invite/revoke>").append(csrf)
                .append("<input type=hidden name=id value=\"").append(HttpFront.escape(r.id())).append("\"><button>Revoke</button></form></td></tr>");
        }
        b.append("</table>");

        b.append("<h2>auth-key</h2>");
        if (lastAuthKey != null) {
            b.append("<p class=new>New auth-key (shown only now): <code>").append(HttpFront.escape(lastAuthKey)).append("</code></p>");
            lastAuthKey = null;
        }
        b.append("<form method=post action=/admin/authkey/create class=row>").append(csrf)
            .append("Owner <input name=owner size=10> or tag <input name=tag size=8> Uses <input name=uses value=1 size=3> TTL <input name=ttl value=7d size=5> <button>Create</button></form>");
        b.append("<table><tr><th>id</th><th>Owner/tag</th><th>Uses left</th><th>Expires</th><th></th></tr>");
        for (Store.AuthKeyRec r : store.authKeys()) {
            b.append("<tr><td><code>").append(HttpFront.escape(r.id())).append("</code></td><td>")
                .append(HttpFront.escape(r.owner() != null ? r.owner() : "tag:" + r.tag())).append("</td><td>").append(r.usesLeft())
                .append("</td><td>").append(new java.util.Date(r.expiresAt())).append("</td><td><form method=post action=/admin/authkey/revoke>").append(csrf)
                .append("<input type=hidden name=id value=\"").append(HttpFront.escape(r.id())).append("\"><button>Revoke</button></form></td></tr>");
        }
        b.append("</table>");

        b.append("<h2>Settings</h2><form method=post action=/admin/settings>").append(csrf)
            .append("<p>Invite creation: ").append(radio("invitePolicy", "members", "Any member", store.setting(Store.SETTING_INVITE_POLICY, "members")))
            .append(radio("invitePolicy", "admins", "Admins only", store.setting(Store.SETTING_INVITE_POLICY, "members"))).append("</p>")
            .append("<p>Registration: ").append(radio("registration", "invite", "Invite required", store.setting(Store.SETTING_REGISTRATION, "invite")))
            .append(radio("registration", "open", "Approve knocks immediately (careful)", store.setting(Store.SETTING_REGISTRATION, "invite"))).append("</p>")
            .append("<p>Knocking: ").append(radio("knock", "on", "Allow", store.setting(Store.SETTING_KNOCK, "on")))
            .append(radio("knock", "off", "Block", store.setting(Store.SETTING_KNOCK, "on"))).append("</p>")
            .append("<button>Save</button></form>");
        b.append("<p><small>hub key <code>").append(HttpFront.escape(hub.keys().publicText())).append("</code>");
        if (hub.tls().isLoaded()) {
            b.append(" · cert expires ").append(hub.tls().leaf().getNotAfter());
        }
        b.append("</small></p>");
        return page("jailhub admin", b.toString());
    }

    private static String radio(String name, String value, String label, String current) {
        return "<label><input type=radio name=" + name + " value=" + value + (value.equals(current) ? " checked" : "") + "> " + label + "</label> ";
    }

    private static String page(String title, String body) {
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>" + HttpFront.escape(title) + "</title>"
            + "<style>body{font-family:system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
            + "table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.25rem .5rem;border-bottom:1px solid #ddd}"
            + "form{display:inline}form.row{display:block;margin:.25rem 0}.new{background:#eef;padding:.5rem}code{font-size:.9em}</style>"
            + "</head><body><h1>" + HttpFront.escape(title) + "</h1>" + body + "</body></html>";
    }

    private static String need(Map<String, String> f, String k) {
        String v = f.get(k);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("missing " + k);
        }
        return v;
    }

    private static String blankToNull(String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }
}
