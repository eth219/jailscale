package io.jailscale.node;

import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.HttpCall;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;

/**
 * Whether a newer jailscale has been published (ARCHITECTURE.md §9.4). There is no self-replacement
 * here: this reports a version and the command that installs it, and the operator decides. Replacing
 * a running binary means privilege over a root-owned path, a signature to check it with, and a
 * different answer on every OS, none of which a version check needs.
 *
 * <p><b>The URL is compiled in and never comes from the hub.</b> The hub already tells a node its own
 * version in {@code HelloResponse}, and letting it name where the update lives would hand a
 * compromised hub (§11.2) a way to point every node at a binary of its choosing. The hub is trusted
 * to route bytes, not to say what this node should run.
 */
final class Updates {

    /** The published releases of this project. */
    static final URI LATEST = URI.create("https://api.github.com/repos/eth219/jailscale/releases/latest");
    static final String PAGE = "https://github.com/eth219/jailscale/releases/latest";

    private static final int TIMEOUT_MS = 10_000;
    private static final int MAX_BODY = 1 << 20;

    private Updates() {}

    /**
     * The outcome of one check. {@code newer} is true only when a release was read and is above the
     * running version; {@code error} explains every other case rather than leaving it as "no".
     */
    record Result(String running, String latest, boolean newer, long checkedAt, String error) {

        JsonObject.Builder json() {
            return JsonObject.builder().put("running", running).put("latest", latest)
                .put("newer", newer).put("checkedAt", checkedAt / 1000).put("error", error);
        }

        /** One line for a human, in the imperative when there is something to do. */
        String line() {
            if (error != null) {
                return "could not check for updates: " + error;
            }
            if (!newer) {
                return "jailscale " + running + " is the latest release.";
            }
            return "jailscale " + latest + " is out; this is " + running + ". " + PAGE;
        }
    }

    /** Asks for the latest release. Never throws: a failed check is a Result carrying why. */
    static Result check(String running) {
        long now = System.currentTimeMillis();
        try {
            HttpResponse r = HttpCall.send("GET", LATEST,
                new Headers().add("Accept", "application/vnd.github+json").add("User-Agent", "jailscale/" + running),
                null, TIMEOUT_MS, MAX_BODY);
            if (r.status() != 200) {
                return new Result(running, null, false, now, "the release index answered HTTP " + r.status());
            }
            JsonObject o = Json.parseObject(r.bodyText());
            String tag = o.optString("tag_name", null);
            if (tag == null) {
                return new Result(running, null, false, now, "the release index carried no tag_name");
            }
            String latest = tag.startsWith("v") ? tag.substring(1) : tag;
            Integer cmp = compare(running, latest);
            if (cmp == null) {
                return new Result(running, latest, false, now,
                    "cannot compare this build (" + running + ") with " + latest);
            }
            return new Result(running, latest, cmp < 0, now, null);
        } catch (IOException | HttpException | RuntimeException e) {
            return new Result(running, null, false, now, e.getMessage() == null ? e.toString() : e.getMessage());
        }
    }

    /**
     * Dotted numeric comparison, negative when {@code a} is older, null when either side is not a
     * version this understands -- a source build reports {@code dev} and has nothing to compare with.
     */
    static Integer compare(String a, String b) {
        int[] x = numbers(a);
        int[] y = numbers(b);
        return x == null || y == null ? null : Arrays.compare(x, y);
    }

    /**
     * {@code {major, minor, patch, release}}, where the last is 0 for a pre-release such as
     * {@code 0.2.0-SNAPSHOT} and 1 for the release itself: a snapshot is the build on the way to a
     * version, so it sorts below it and never reports itself as newer. Null for anything else,
     * which is how {@code dev} and a tag nobody expected stay "cannot tell" instead of "no".
     */
    private static int[] numbers(String v) {
        if (v == null) {
            return null;
        }
        String s = v.startsWith("v") ? v.substring(1) : v;
        int dash = s.indexOf('-');
        boolean pre = dash >= 0;
        String[] parts = (pre ? s.substring(0, dash) : s).split("\\.", -1);
        if (parts.length > 3) {
            return null;
        }
        int[] out = {0, 0, 0, pre ? 0 : 1};
        for (int i = 0; i < parts.length; i++) {
            try {
                out[i] = Integer.parseInt(parts[i]);
            } catch (NumberFormatException e) {
                return null;
            }
            if (out[i] < 0) {
                return null;
            }
        }
        return out;
    }
}
