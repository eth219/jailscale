package io.jailscale.node;

import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.HttpCall;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Set;

/**
 * Whether a newer jailscale has been published, and fetching it when there is (ARCHITECTURE.md
 * §9.4). There is still no self-replacement here: this reports a version, and on {@code --download}
 * puts a verified binary on disk and prints the command that installs it. The last step stays with
 * the operator, because replacing a running binary means privilege over a root-owned path, a
 * different answer on every OS, and a package manager that must not find a second owner of its
 * file -- none of which a download needs to have answered.
 *
 * <p><b>What makes a download acceptable</b> is a chain of three links, checked in this order and
 * every one of them fatal: an Ed25519 signature ({@link ReleaseKey}) over {@link #MANIFEST}, which
 * names the release and the digest of {@code SHA256SUMS.txt}; that digest against the checksum list
 * actually fetched; and that list's hash for exactly the asset fetched. The signature comes first
 * because a checksum list is only worth the key over it. The release's own tag is inside the signed
 * bytes because otherwise the signature says nothing about *which* release it belongs to, and any
 * past release's genuine signature would be valid for every future one. And a name absent from the
 * list is an error rather than a download that verified nothing -- the {@code --ignore-missing} trap
 * the install instructions warn a human about, which in code would be worse.
 *
 * <p><b>The URLs are compiled in and never come from the hub.</b> The hub already tells a node its
 * own version in {@code HelloResponse}, and letting it name where the update lives would hand a
 * compromised hub (§11.2) a way to point every node at a binary of its choosing. The hub is trusted
 * to route bytes, not to say what this node should run.
 */
final class Updates {

    /** The published releases of this project. */
    static final URI LATEST = URI.create("https://api.github.com/repos/eth219/jailscale/releases/latest");
    static final String PAGE = "https://github.com/eth219/jailscale/releases/latest";
    static final String DOWNLOADS = "https://github.com/eth219/jailscale/releases/download/";

    /** The files a release carries beside the binaries (§14). */
    static final String SUMS = "SHA256SUMS.txt";
    /** What is actually signed: the release's identity and the digest of {@link #SUMS}. */
    static final String MANIFEST = "RELEASE.txt";
    static final String SIGNATURE = MANIFEST + ".sig";
    /** The first line of {@link #MANIFEST}; a build refuses a format it was not taught. */
    static final String MANIFEST_FORMAT = "jailscale-release 1";

    private static final int TIMEOUT_MS = 10_000;
    private static final int ASSET_TIMEOUT_MS = 120_000;
    private static final int MAX_BODY = 1 << 20;
    private static final int MAX_SUMS = 64 * 1024;
    private static final int MAX_MANIFEST = 4096;
    private static final int MAX_SIGNATURE = 4096;
    /** Five times the size of a binary today: a ceiling, not a size anyone expects to approach. */
    private static final long MAX_ASSET = 128L << 20;

    private Updates() {}

    /**
     * The outcome of one check. {@code newer} is true only when a release was read and is above the
     * running version; {@code error} explains every other case rather than leaving it as "no".
     * {@code tag} is the release's own tag, which is what names a download; {@code latest} is the
     * version inside it, which is what compares.
     */
    record Result(String running, String latest, String tag, boolean newer, long checkedAt, String error) {

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
                return new Result(running, null, null, false, now, "the release index answered HTTP " + r.status());
            }
            JsonObject o = Json.parseObject(r.bodyText());
            String tag = o.optString("tag_name", null);
            if (tag == null) {
                return new Result(running, null, null, false, now, "the release index carried no tag_name");
            }
            String latest = tag.startsWith("v") ? tag.substring(1) : tag;
            Integer cmp = compare(running, latest);
            if (cmp == null) {
                return new Result(running, latest, tag, false, now,
                    "cannot compare this build (" + running + ") with " + latest);
            }
            return new Result(running, latest, tag, cmp < 0, now, null);
        } catch (IOException | HttpException | RuntimeException e) {
            return new Result(running, null, null, false, now, e.getMessage() == null ? e.toString() : e.getMessage());
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

    // --- downloading ----------------------------------------------------------------------------

    /** A release asset on disk, checked. */
    record Downloaded(Path file, String asset, long bytes, String sha256, String key) {}

    /**
     * Where a download comes from and the key it has to be signed with. Production has exactly one
     * of these, {@link #compiledIn()}, built from two constants: the point of §11.2 is that neither
     * the hub nor a flag nor the state file gets to name either. It is a parameter at all so that
     * the whole of {@link #fetch} -- signature, then checksum, then what happens to a file that
     * fails one -- can be driven against a server a test stands up, rather than only in pieces.
     */
    record Source(String base, List<String> keys) {
        static Source compiledIn() {
            return new Source(DOWNLOADS, ReleaseKey.PUBLIC_KEYS);
        }
    }

    /**
     * Fetches the release {@code r} names into {@code dir}, verifies it, and returns where it is.
     * Nothing is left behind on a failure: a file whose hash did not match is deleted before the
     * reason is thrown, so there is never a half-checked binary lying next to instructions for
     * installing it.
     */
    static Downloaded fetch(Result r, Path dir) throws IOException, GeneralSecurityException, HttpException {
        return fetch(r, dir, Source.compiledIn());
    }

    static Downloaded fetch(Result r, Path dir, Source source)
        throws IOException, GeneralSecurityException, HttpException {
        if (source.keys().isEmpty()) {
            throw new IOException("this build carries no release signing key, so a download cannot be"
                + " checked; install by hand from " + PAGE);
        }
        String asset = asset(target(), nativeImage());
        if (asset == null) {
            throw new IOException("no binary is published for " + System.getProperty("os.name") + "/"
                + System.getProperty("os.arch") + "; see " + PAGE);
        }
        String tag = r.tag();
        byte[] manifest;
        byte[] signature;
        try {
            manifest = get(assetUrl(source.base(), tag, MANIFEST), MAX_MANIFEST);
            signature = get(assetUrl(source.base(), tag, SIGNATURE), MAX_SIGNATURE);
        } catch (HttpException e) {
            // Only a 404 means what it looks like. Every release published before the signing key
            // existed has assets, a checksum file and nothing signed, and telling that operator to
            // install by hand is right -- but telling it to someone whose network dropped for a
            // second is steering them off verification for something a retry would fix, so every
            // other status keeps its own message.
            if (e.status() != 404) {
                throw new IOException("could not read the signed " + MANIFEST + " for " + tag + ": "
                    + e.getMessage(), e);
            }
            throw new IOException(tag + " carries no signed " + MANIFEST + ", so there is nothing to"
                + " check it with. Install it by hand from " + PAGE, e);
        }
        String key = ReleaseKey.verify(source.keys(), manifest, signature);
        Manifest m = Manifest.parse(new String(manifest, StandardCharsets.UTF_8));

        // What the signature is for. Without this the signed bytes say nothing about which release
        // they belong to, and any past release's genuine signature is a valid signature for every
        // future tag -- so whoever can publish a release could republish an old, signed, vulnerable
        // one under a higher version and this would call it verified. It also makes the comparison
        // in check() mean something: that answer was made from an unauthenticated tag until here.
        if (!m.tag().equals(tag)) {
            throw new IOException("the signed " + MANIFEST + " under " + tag + " says it belongs to "
                + m.tag() + "; an old release has been republished under a new version");
        }
        byte[] sums = get(assetUrl(source.base(), tag, SUMS), MAX_SUMS);
        String sumsHash = sha256(sums);
        if (!sumsHash.equalsIgnoreCase(m.sums())) {
            throw new IOException(SUMS + " hashes to " + sumsHash + ", and the signed " + MANIFEST
                + " says " + m.sums() + "; the checksum list is not the one that was signed");
        }
        String want = hashFor(new String(sums, StandardCharsets.UTF_8), asset);

        Files.createDirectories(dir);
        Path file = dir.resolve(asset);
        String got;
        try {
            got = download(assetUrl(source.base(), tag, asset), file);
        } catch (IOException | RuntimeException e) {
            Files.deleteIfExists(file);
            throw e;
        }
        if (!got.equalsIgnoreCase(want)) {
            Files.deleteIfExists(file);
            throw new IOException(asset + " hashes to " + got + ", and the signed " + SUMS + " says "
                + want + "; the download was not what the release says it is");
        }
        executable(file);
        return new Downloaded(file, asset, Files.size(file), got, key);
    }

    /**
     * The one signed document in a release: which release it is, and the digest of the checksum
     * list that names every file in it. {@code SHA256SUMS.txt} itself stays exactly what
     * {@code sha256sum -c} expects, which is why the identity lives here instead of in a line
     * inside it that would break every reader.
     */
    record Manifest(String tag, String sums) {

        /**
         * Strict about the format line and relaxed about the rest: an unknown field is a later
         * release saying something this build does not need, which is the additive case §5.4 already
         * permits on the wire, while a format line this build was not taught is a change it cannot
         * assume is additive and refuses.
         */
        static Manifest parse(String text) throws IOException {
            String[] lines = text.split("\n");
            if (lines.length == 0 || !lines[0].trim().equals(MANIFEST_FORMAT)) {
                throw new IOException("the signed " + MANIFEST + " is not in a format this build reads"
                    + " (it begins " + (lines.length == 0 ? "empty" : "\"" + lines[0].trim() + "\"")
                    + ", this build reads \"" + MANIFEST_FORMAT + "\")");
            }
            String tag = null;
            String sums = null;
            for (int i = 1; i < lines.length; i++) {
                int colon = lines[i].indexOf(':');
                if (colon <= 0) {
                    continue;
                }
                String name = lines[i].substring(0, colon).trim();
                String value = lines[i].substring(colon + 1).trim();
                if (name.equals("tag")) {
                    tag = value;
                } else if (name.equals("sha256sums")) {
                    sums = value;
                }
            }
            if (tag == null || tag.isEmpty() || sums == null || !sums.matches("[0-9a-fA-F]{64}")) {
                throw new IOException("the signed " + MANIFEST + " does not name both a tag and a"
                    + " sha256 of " + SUMS);
            }
            return new Manifest(tag, sums);
        }
    }

    /**
     * {@code SHA256SUMS.txt}'s hash for exactly this name.
     *
     * <p>Absent is an error, not an empty answer. {@code sha256sum --ignore-missing -c} reports
     * success for having checked nothing when the name it was given is not in the list, which the
     * install instructions warn a human about; the same mistake made in code would be a download
     * that verified nothing and said it verified something.
     */
    static String hashFor(String sums, String name) throws IOException {
        String found = null;
        for (String line : sums.split("\n")) {
            String[] parts = line.trim().split("\\s+", 2);
            if (parts.length != 2) {
                continue;
            }
            String file = parts[1].startsWith("*") ? parts[1].substring(1) : parts[1]; // binary-mode marker
            if (!file.equals(name)) {
                continue;
            }
            String hash = parts[0].toLowerCase(Locale.ROOT);
            if (hash.length() != 64 || !hash.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                throw new IOException(SUMS + " gives " + name + " a hash that is not sha256: " + parts[0]);
            }
            if (found != null && !found.equals(hash)) {
                throw new IOException(SUMS + " gives " + name + " two different hashes");
            }
            found = hash;
        }
        if (found == null) {
            throw new IOException(SUMS + " has no line for " + name + ", so there is nothing to check it against");
        }
        return found;
    }

    /**
     * Where a release file lives. The tag arrives from the release index, so it is held to what a
     * tag can be before it is pasted into a URL: a {@code ../} or a {@code //} in there would point
     * this somewhere else entirely on a host that is otherwise the right one.
     */
    static URI assetUrl(String tag, String name) throws IOException {
        return assetUrl(DOWNLOADS, tag, name);
    }

    static URI assetUrl(String base, String tag, String name) throws IOException {
        if (tag == null || tag.isEmpty() || tag.length() > 64 || !tag.matches("[A-Za-z0-9][A-Za-z0-9._+-]*")
            || tag.contains("..")) {
            throw new IOException("the release index named a tag this will not put in a URL: " + tag);
        }
        return URI.create(base + tag + "/" + name);
    }

    /** {@code linux-amd64}, {@code darwin-arm64}, ... or null where no binary is published. */
    static String target() {
        return target(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
    }

    static String target(String osName, String osArch) {
        String os = osName.toLowerCase(Locale.ROOT);
        String arch = osArch.toLowerCase(Locale.ROOT);
        String o = os.contains("windows") ? "windows" : os.contains("mac") || os.contains("darwin") ? "darwin"
            : os.contains("linux") ? "linux" : null;
        String a = arch.equals("amd64") || arch.equals("x86_64") ? "amd64"
            : arch.equals("aarch64") || arch.equals("arm64") ? "arm64" : null;
        if (o == null || a == null) {
            return null;
        }
        String t = o + "-" + a;
        // The four the release builds (§14). darwin-amd64 is deliberately not among them: GraalVM
        // CE 25.3 does not produce one, and an Intel Mac runs the JAR.
        return Set.of("linux-amd64", "linux-arm64", "darwin-arm64", "windows-amd64").contains(t) ? t : null;
    }

    /**
     * The file to fetch for this build. A JVM build wants the JAR whatever it is running on, which
     * is also the answer on the platforms with no native binary; a native build wants its target.
     */
    static String asset(String target, boolean nativeImage) {
        if (!nativeImage) {
            return "jailscale.jar";
        }
        return target == null ? null : "jailscale-" + target + (target.startsWith("windows") ? ".exe" : "");
    }

    static boolean windows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows");
    }

    static boolean nativeImage() {
        return System.getProperty("org.graalvm.nativeimage.imagecode") != null;
    }

    /**
     * The command that puts {@code file} where {@code running} is, for a human to run.
     *
     * <p>A JAR is copied and a binary is installed, which is not a cosmetic difference: `install -m
     * 755` on a jar produces an executable file that is not one.
     */
    static String installCommand(Path file, Path running, boolean windows) {
        boolean jar = fileName(file).endsWith(".jar");
        String from = file.toString();
        String to = running != null ? running.toString()
            : jar ? "/path/to/jailscale.jar" : windows ? "jailscale.exe" : "/usr/local/bin/jailscale";
        if (windows) {
            // Windows will not let a file in use be overwritten, but it will let it be renamed, so
            // the old one is moved aside rather than deleted and can go once the new one has run.
            return "Move-Item -Force \"" + to + "\" \"" + to + ".old\"\n"
                + "  Move-Item \"" + from + "\" \"" + to + "\"";
        }
        boolean mine = running != null && Files.isWritable(running);
        return (mine ? "" : "sudo ") + (jar ? "cp " : "install -m 755 ") + from + " " + to;
    }

    /**
     * What this build is running from, or null when it cannot be established.
     *
     * <p>For a native image that is the executable. <b>For a JVM build it is emphatically not the
     * command</b>, which is the java launcher: printing that would tell the operator to install a
     * 25 MiB jar over their own {@code java}, and on a user-owned prefix it would not even ask for
     * a password first. What a JVM build replaces is the jar it was started from, so that is what
     * this looks for, and anything else -- a directory of classes under a test runner, a code
     * source the JVM will not name -- is null, which prints a path with a blank in it rather than
     * a confident wrong one.
     */
    static Path self() {
        if (nativeImage()) {
            try {
                return ProcessHandle.current().info().command().map(Path::of).orElse(null);
            } catch (RuntimeException e) {
                return null;
            }
        }
        try {
            java.security.CodeSource src = Updates.class.getProtectionDomain().getCodeSource();
            if (src == null || src.getLocation() == null) {
                return null;
            }
            Path p = Path.of(src.getLocation().toURI());
            return fileName(p).endsWith(".jar") ? p : null;
        } catch (java.net.URISyntaxException | RuntimeException e) {
            return null;
        }
    }

    /** The last element of a path, or "" for one that has none -- a root has no file name. */
    private static String fileName(Path p) {
        Path name = p == null ? null : p.getFileName();
        return name == null ? "" : name.toString();
    }

    private static String sha256(byte[] bytes) throws IOException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("no SHA-256 in this runtime", e);
        }
    }

    /** Throws {@link HttpException} rather than flattening it, so the caller can read the status. */
    private static byte[] get(URI url, int max) throws IOException, HttpException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        HttpCall.get(url, headers(), buf, TIMEOUT_MS, max);
        return buf.toByteArray();
    }

    /** Streams {@code url} into {@code file}, hashing as it goes; returns the hash. */
    private static String download(URI url, Path file) throws IOException {
        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("no SHA-256 in this runtime", e);
        }
        try (OutputStream out = new DigestOutputStream(Files.newOutputStream(file), sha)) {
            HttpCall.get(url, headers(), out, ASSET_TIMEOUT_MS, MAX_ASSET);
        } catch (HttpException e) {
            throw new IOException(url + ": " + e.getMessage(), e);
        }
        return HexFormat.of().formatHex(sha.digest());
    }

    private static Headers headers() {
        return new Headers().add("Accept", "application/octet-stream")
            .add("User-Agent", "jailscale/" + Version.string());
    }

    private static void executable(Path file) {
        try {
            Files.setPosixFilePermissions(file, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        } catch (IOException | UnsupportedOperationException e) {
            // Windows has no POSIX bits and does not need them; anywhere else this is a convenience,
            // and the install command below would have set the mode anyway.
        }
    }
}
