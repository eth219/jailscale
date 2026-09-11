package io.jailscale.hub;

import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The minimal admin page (DESIGN.md §7.6): no password, no IdP. An admin node asks for a
 * one-time login link over the control channel; visiting it sets a session cookie. Server
 * rendered HTML, no JavaScript, forms with a session-bound CSRF token.
 */
final class AdminWeb {

    private static final Log LOG = Log.get("admin");
    static final long LOGIN_LINK_TTL_MS = 60_000;
    static final long SESSION_TTL_MS = 12 * 3600 * 1000L;
    static final String COOKIE = "__Host-jailhub_admin";

    private record Login(String user, boolean shell, long expiresAt) {}

    private record Session(String user, boolean shell, long expiresAt, String csrf) {}

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
     * authorised by the socket's file permissions (§7.6) and has no entry in the admin list, so
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
                return HttpResponse.html(403, page("로그인 링크가 만료되었습니다", "<p>노드에서 <code>jailscale admin</code>을 다시 실행하세요.</p>"));
            }
            String sid = Tokens.inviteToken();
            sessions.put(sid, new Session(l.user(), l.shell(), System.currentTimeMillis() + SESSION_TTL_MS, Tokens.inviteToken()));
            LOG.info("admin {} logged in", l.user());
            return HttpResponse.redirect("/admin").header("Set-Cookie", cookie(sid, SESSION_TTL_MS / 1000));
        }
        Session s = session(req);
        if (s == null) {
            return HttpResponse.html(403, page("jailhub 관리", "<p>관리자 노드에서 <code>jailscale admin</code>을 실행하면 로그인 링크가 열립니다.</p>"));
        }
        // Admin rights are checked again on every request, not only when the link was issued.
        // Without this, `admin remove` left the removed admin's browser working until the twelve
        // hour session lapsed.
        if (!authorized(s)) {
            sessions.values().removeIf(v -> v == s);
            LOG.warn("session for {} is no longer an admin; signed out", s.user());
            return HttpResponse.html(403, page("권한이 없습니다", "<p>이 계정은 더 이상 관리자가 아닙니다.</p>"))
                .header("Set-Cookie", cookie("", 0));
        }
        if (req.method().equals("POST")) {
            Map<String, String> f = req.form();
            if (!s.csrf().equals(f.get("csrf"))) {
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
                return HttpResponse.html(400, page("오류", "<p>" + HttpFront.escape(e.getMessage()) + "</p><p><a href=\"/admin\">돌아가기</a></p>"));
            }
            return HttpResponse.redirect("/admin");
        }
        if (!path.equals("/admin") && !path.equals("/admin/")) {
            return HttpResponse.text(404, "not found");
        }
        return HttpResponse.html(200, render(s));
    }

    /** The local shell is authorised by the IPC socket's permissions; everyone else by the list. */
    private boolean authorized(Session s) {
        return s.shell() || hub.store().isAdmin(s.user());
    }

    /** {@code __Host-} forbids a Domain attribute and requires Path=/ and Secure. */
    private static String cookie(String sid, long maxAgeSeconds) {
        return COOKIE + "=" + sid + "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=" + maxAgeSeconds;
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
                    throw new IllegalArgumentException("owner 또는 tag 중 하나만 입력하세요");
                }
                String secret = Tokens.authKey();
                store.createAuthKey(secret, owner, tag, Integer.parseInt(f.getOrDefault("uses", "1")),
                    io.jailscale.proto.util.Args.parseSeconds(f.getOrDefault("ttl", "7d")));
                lastAuthKey = secret;
            }
            case "/admin/authkey/revoke" -> store.revokeAuthKey(need(f, "id"));
            case "/admin/name/release" -> store.releaseName(need(f, "name"));
            case "/admin/domain/release" -> store.releaseDomain(need(f, "domain"));
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
        b.append("<p>").append(HttpFront.escape(hub.config().hostname())).append(" · 로그인: <b>").append(HttpFront.escape(s.user())).append("</b>")
            .append(" · 노드 ").append(store.nodes().size()).append(" · 온라인 ").append(hub.registry().size())
            .append(" · 링크 ").append(hub.links().all().size()).append("</p>");
        String csrf = "<input type=hidden name=csrf value=\"" + s.csrf() + "\">";
        b.append("<form method=post action=/admin/logout>").append(csrf).append("<button>로그아웃</button></form>");

        b.append("<h2>승인 대기</h2>");
        if (store.pending().isEmpty()) {
            b.append("<p>없음</p>");
        }
        for (Store.PendingRec p : store.pending()) {
            b.append("<form method=post action=/admin/approve class=row>").append(csrf)
                .append("<input type=hidden name=mkey value=\"").append(HttpFront.escape(p.mkey())).append("\">")
                .append("<code>").append(HttpFront.escape(p.mkey().substring(0, 17))).append("…</code> ")
                .append(HttpFront.escape(p.hostname())).append(" (").append(HttpFront.escape(p.os())).append(", ").append(HttpFront.escape(String.valueOf(p.ip()))).append(") ")
                .append("이름 <input name=user value=\"").append(HttpFront.escape(p.user() == null ? p.hostname() : p.user())).append("\" size=12> ")
                .append("<button>승인</button></form>")
                .append("<form method=post action=/admin/deny class=row>").append(csrf)
                .append("<input type=hidden name=mkey value=\"").append(HttpFront.escape(p.mkey())).append("\"><button>거부</button></form>");
        }

        b.append("<h2>노드</h2><table><tr><th>#</th><th>사용자</th><th>호스트</th><th>키</th><th>상태</th><th></th></tr>");
        for (Store.NodeRec n : store.nodes()) {
            NodeGroup g = hub.registry().get(n.mkey());
            b.append("<tr><td>").append(n.id()).append("</td><td>").append(HttpFront.escape(n.user())).append("</td><td>")
                .append(HttpFront.escape(n.hostname())).append("</td><td><code>").append(HttpFront.escape(n.mkey().substring(0, 17))).append("…</code></td><td>")
                .append(g == null ? "오프라인" : "온라인 (" + g.connections() + ")").append("</td><td>")
                .append("<form method=post action=/admin/node/remove>").append(csrf)
                .append("<input type=hidden name=mkey value=\"").append(HttpFront.escape(n.mkey())).append("\"><button>제거</button></form></td></tr>");
        }
        b.append("</table>");

        b.append("<h2>이름</h2><table><tr><th>이름</th><th>소유자</th><th>대상</th><th>상태</th><th></th></tr>");
        for (Store.NameRec n : store.names()) {
            b.append("<tr><td>").append(HttpFront.escape(n.name())).append("</td><td>").append(HttpFront.escape(n.user())).append("</td><td>")
                .append(HttpFront.escape(String.valueOf(n.local()))).append("</td><td>").append(hub.links().byName(n.name()) != null ? "열림" : "닫힘").append("</td><td>")
                .append("<form method=post action=/admin/name/release>").append(csrf)
                .append("<input type=hidden name=name value=\"").append(HttpFront.escape(n.name())).append("\"><button>해제</button></form></td></tr>");
        }
        b.append("</table>");

        if (!store.domains().isEmpty()) {
            b.append("<h2>사용자 도메인</h2><table><tr><th>도메인</th><th>소유자</th><th>상태</th><th></th></tr>");
            for (Store.DomainRec d : store.domains()) {
                b.append("<tr><td>").append(HttpFront.escape(d.domain())).append("</td><td>").append(HttpFront.escape(d.user()))
                    .append("</td><td>").append(hub.links().byDomain(d.domain()) != null ? "열림" : "닫힘").append("</td><td>")
                    .append("<form method=post action=/admin/domain/release>").append(csrf)
                    .append("<input type=hidden name=domain value=\"").append(HttpFront.escape(d.domain())).append("\"><button>해제</button></form></td></tr>");
            }
            b.append("</table>");
        }

        b.append("<h2>초대</h2>");
        if (lastInvite != null) {
            b.append("<p class=new>새 초대: <code>").append(HttpFront.escape(lastInvite.url())).append("</code> · 코드 <code>")
                .append(HttpFront.escape(lastInvite.code())).append("</code></p>");
            lastInvite = null;
        }
        b.append("<form method=post action=/admin/invite/create class=row>").append(csrf)
            .append("이름 <input name=user size=10> 횟수 <input name=uses value=1 size=3> 기간 <input name=ttl value=24h size=5> <button>초대 만들기</button></form>");
        b.append("<table><tr><th>id</th><th>이름</th><th>남은 횟수</th><th>만료</th><th>발급자</th><th></th></tr>");
        for (Store.InviteRec r : store.invites()) {
            b.append("<tr><td><code>").append(HttpFront.escape(r.id())).append("</code></td><td>").append(HttpFront.escape(String.valueOf(r.user())))
                .append("</td><td>").append(r.usesLeft()).append("</td><td>").append(new java.util.Date(r.expiresAt())).append("</td><td>")
                .append(HttpFront.escape(String.valueOf(r.createdBy()))).append("</td><td><form method=post action=/admin/invite/revoke>").append(csrf)
                .append("<input type=hidden name=id value=\"").append(HttpFront.escape(r.id())).append("\"><button>취소</button></form></td></tr>");
        }
        b.append("</table>");

        b.append("<h2>auth-key</h2>");
        if (lastAuthKey != null) {
            b.append("<p class=new>새 auth-key (지금만 표시): <code>").append(HttpFront.escape(lastAuthKey)).append("</code></p>");
            lastAuthKey = null;
        }
        b.append("<form method=post action=/admin/authkey/create class=row>").append(csrf)
            .append("소유자 <input name=owner size=10> 또는 태그 <input name=tag size=8> 횟수 <input name=uses value=1 size=3> 기간 <input name=ttl value=7d size=5> <button>만들기</button></form>");
        b.append("<table><tr><th>id</th><th>소유자/태그</th><th>남은 횟수</th><th>만료</th><th></th></tr>");
        for (Store.AuthKeyRec r : store.authKeys()) {
            b.append("<tr><td><code>").append(HttpFront.escape(r.id())).append("</code></td><td>")
                .append(HttpFront.escape(r.owner() != null ? r.owner() : "tag:" + r.tag())).append("</td><td>").append(r.usesLeft())
                .append("</td><td>").append(new java.util.Date(r.expiresAt())).append("</td><td><form method=post action=/admin/authkey/revoke>").append(csrf)
                .append("<input type=hidden name=id value=\"").append(HttpFront.escape(r.id())).append("\"><button>취소</button></form></td></tr>");
        }
        b.append("</table>");

        b.append("<h2>설정</h2><form method=post action=/admin/settings>").append(csrf)
            .append("<p>초대 발급: ").append(radio("invitePolicy", "members", "멤버 누구나", store.setting(Store.SETTING_INVITE_POLICY, "members")))
            .append(radio("invitePolicy", "admins", "관리자만", store.setting(Store.SETTING_INVITE_POLICY, "members"))).append("</p>")
            .append("<p>가입: ").append(radio("registration", "invite", "초대 필요", store.setting(Store.SETTING_REGISTRATION, "invite")))
            .append(radio("registration", "open", "두드리면 즉시 승인 (주의)", store.setting(Store.SETTING_REGISTRATION, "invite"))).append("</p>")
            .append("<p>두드리기: ").append(radio("knock", "on", "허용", store.setting(Store.SETTING_KNOCK, "on")))
            .append(radio("knock", "off", "차단", store.setting(Store.SETTING_KNOCK, "on"))).append("</p>")
            .append("<button>저장</button></form>");
        b.append("<p><small>hub 키 <code>").append(HttpFront.escape(hub.keys().publicText())).append("</code>");
        if (hub.tls().isLoaded()) {
            b.append(" · 인증서 만료 ").append(hub.tls().leaf().getNotAfter());
        }
        b.append("</small></p>");
        return page("jailhub 관리", b.toString());
    }

    private static String radio(String name, String value, String label, String current) {
        return "<label><input type=radio name=" + name + " value=" + value + (value.equals(current) ? " checked" : "") + "> " + label + "</label> ";
    }

    private static String page(String title, String body) {
        return "<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\"><title>" + HttpFront.escape(title) + "</title>"
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
