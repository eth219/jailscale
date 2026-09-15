package io.jailscale.node;

import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.HttpCall;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Sha256;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

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
    /** What a download is written under until it has been checked. */
    static final String PARTIAL = ".part";

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
     * {@code tag} is the release's own tag, which is what names a download; {@link #latest()} is
     * the version inside it, which is what compares and what a human is told.
     */
    record Result(String running, String tag, boolean newer, long checkedAt, String error) {

        /** The version the tag names. */
        String latest() {
            return tag == null ? null : version(tag);
        }

        JsonObject.Builder json() {
            return JsonObject.builder().put("running", running).put("latest", latest())
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
            return "jailscale " + latest() + " is out; this is " + running + ". " + PAGE;
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
            Integer cmp = compare(running, tag);
            if (cmp == null) {
                return new Result(running, tag, false, now,
                    "cannot compare this build (" + running + ") with " + tag);
            }
            return new Result(running, tag, cmp < 0, now, null);
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

    /** The version a tag names: the tag without its leading {@code v}. The one place that rule is written. */
    static String version(String tag) {
        return tag.startsWith("v") ? tag.substring(1) : tag;
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
        String s = version(v);
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
     * The bytes go to a {@code .part} file beside the final name and are moved into place only once
     * the hash has matched, so nothing that was in {@code dir} before is touched by a download that
     * fails, and there is never a half-checked binary lying next to instructions for installing it.
     */
    static Downloaded fetch(String running, String tag, Path dir)
        throws IOException, GeneralSecurityException, HttpException {
        return fetch(running, tag, dir, Source.compiledIn(), self());
    }

    /**
     * @param running the version this process is, which the signed release has to be above
     * @param tag the release to fetch, as the index named it; what the signature is checked to name
     * @param self the file this process runs from, or null; a download is refused rather than
     *     written over it, because that would be the install this command deliberately leaves to
     *     the operator, done without the privilege check or the restart it needs
     */
    static Downloaded fetch(String running, String tag, Path dir, Source source, Path self)
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
        byte[] manifest;
        byte[] signature;
        try {
            manifest = get(assetUrl(source.base(), tag, MANIFEST), MAX_MANIFEST);
            signature = get(assetUrl(source.base(), tag, SIGNATURE), MAX_SIGNATURE);
        } catch (HttpException e) {
            if (e.status() != 404) {
                throw new IOException("could not read the signed " + MANIFEST + " for " + tag + ": "
                    + e.getMessage(), e);
            }
            // This build carries a key, so every release newer than it -- the only kind that gets
            // here -- was published under signing and must carry a signature. One that does not is
            // either a publishing mistake or a signature somebody removed, and neither is a reason
            // to send the operator off to install the same bytes unchecked by hand: that would turn
            // "strip the signature" into a working downgrade of the whole check.
            throw new IOException(tag + " carries no signed " + MANIFEST + ", and every release since"
                + " this build was signed. Do not install it by hand; if it is a fresh release, the"
                + " signature may still be on its way, so try again later", e);
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
        // Never below what is running, decided here, against the tag the signature was just checked
        // to name: the one place on the download path where "is this an upgrade" is answered.
        // check() answers the same question for the announcement; a caller of this does not get to
        // pass that answer in.
        Integer cmp = compare(running, m.tag());
        if (cmp == null || cmp >= 0) {
            throw new IOException("the signed " + MANIFEST + " names " + m.tag() + ", which is not newer than"
                + " the running " + running + "; refusing to fetch a release that is not an upgrade");
        }
        byte[] sums;
        try {
            sums = get(assetUrl(source.base(), tag, SUMS), MAX_SUMS);
        } catch (HttpException e) {
            throw new IOException("could not read " + SUMS + " for " + tag + ": " + e.getMessage(), e);
        }
        String sumsHash = Sha256.hex(sums);
        if (!sumsHash.equals(m.sums())) {
            throw new IOException(SUMS + " hashes to " + sumsHash + ", and the signed " + MANIFEST
                + " says " + m.sums() + "; the checksum list is not the one that was signed");
        }
        String want = hashFor(new String(sums, StandardCharsets.UTF_8), asset);

        boolean made = !Files.isDirectory(dir); // so a failure removes what this created and nothing else
        Files.createDirectories(dir);
        Path file = dir.resolve(asset);
        Path part = dir.resolve(asset + PARTIAL);
        MessageDigest sha = Sha256.digest();
        long bytes;
        try {
            if (self != null && Files.exists(file) && Files.exists(self) && Files.isSameFile(file, self)) {
                throw new IOException(file + " is the binary this is running from; download somewhere else"
                    + " (--dir) and install from there");
            }
            bytes = download(assetUrl(source.base(), tag, asset), part, sha);
            String got = HexFormat.of().formatHex(sha.digest());
            if (!got.equals(want)) {
                throw new IOException(asset + " hashes to " + got + ", and the signed " + SUMS
                    + " says " + want + "; the download was not what the release says it is");
            }
            executable(part);
            Files.move(part, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            return new Downloaded(file, asset, bytes, got, key);
        } catch (IOException | RuntimeException e) {
            Files.deleteIfExists(part);
            if (made) {
                try {
                    Files.deleteIfExists(dir); // the leaf only; empty, since the .part is gone
                } catch (IOException ignored) {
                    // the download's own reason is the one to report
                }
            }
            throw e;
        }
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
            if (tag == null || tag.isEmpty() || sums == null) {
                throw new IOException("the signed " + MANIFEST + " does not name both a tag and a"
                    + " sha256 of " + SUMS);
            }
            return new Manifest(tag, sha256Field(sums, MANIFEST + " gives " + SUMS));
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
            String hash = sha256Field(parts[0], SUMS + " gives " + name);
            if (found != null && !found.equals(hash)) {
                throw new IOException(SUMS + " gives " + name + " two different hashes");
            }
            found = hash;
        }
        if (found == null) {
            throw new IOException(SUMS + " has no line for " + name + ", so there is nothing to check it"
                + " against; this release carries no binary for this platform, or not under that name");
        }
        return found;
    }

    /** A sha256 as written in a file, lowercased, or an error naming {@code what} it was meant to be. */
    private static String sha256Field(String s, String what) throws IOException {
        String hex = s.trim().toLowerCase(Locale.ROOT);
        if (hex.length() != 64 || !hex.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            throw new IOException(what + " a hash that is not sha256: " + s);
        }
        return hex;
    }

    /**
     * Where a release file lives. The tag arrives from the release index, so it is held to what a
     * tag can be before it is pasted into a URL: a {@code ../} or a {@code //} in there would point
     * this somewhere else entirely on a host that is otherwise the right one.
     */
    static URI assetUrl(String base, String tag, String name) throws IOException {
        if (tag == null || tag.isEmpty() || tag.length() > 64 || !tag.matches("[A-Za-z0-9][A-Za-z0-9._+-]*")
            || tag.contains("..")) {
            throw new IOException("the release index named a tag this will not put in a URL: " + tag);
        }
        return URI.create(base + tag + "/" + name);
    }

    /** {@code linux-amd64}, {@code darwin-arm64}, ... or null where the OS or the CPU is neither. */
    static String target() {
        return target(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
    }

    /**
     * No list of what the release builds here: the signed {@code SHA256SUMS.txt} is that list, and
     * a name it does not carry is refused by {@link #hashFor} with a message that says so. A copy of
     * release.yml's matrix in this file would be the one that was forgotten when the matrix grew.
     */
    static String target(String osName, String osArch) {
        String o = switch (HubLink.osName(osName)) { // one classification of os.name, shared with windows()
            case "windows" -> "windows";
            case "macos" -> "darwin"; // the release names it as the toolchain does
            case "linux" -> "linux";
            default -> null;
        };
        String arch = osArch.toLowerCase(Locale.ROOT);
        String a = arch.equals("amd64") || arch.equals("x86_64") ? "amd64"
            : arch.equals("aarch64") || arch.equals("arm64") ? "arm64" : null;
        return o == null || a == null ? null : o + "-" + a;
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
        return "windows".equals(HubLink.osName());
    }

    static boolean nativeImage() {
        return System.getProperty("org.graalvm.nativeimage.imagecode") != null;
    }

    /**
     * The command that puts {@code file} where {@code running} is, for a human to run.
     *
     * <p>A JAR is copied and a binary is installed, which is not a cosmetic difference: `install -m
     * 755` on a jar produces an executable file that is not one. Both paths are quoted for the
     * shell they are printed for, because {@code --dir} and a jar under {@code Application Support}
     * both put a space in one.
     */
    static String installCommand(Path file, Path running, boolean windows) {
        boolean jar = file.toString().endsWith(".jar");
        String from = file.toString();
        String to = running != null ? running.toString()
            : jar ? "/path/to/jailscale.jar" : windows ? "jailscale.exe" : "/usr/local/bin/jailscale";
        if (windows) {
            // Windows will not let a file in use be overwritten, but it will let it be renamed, so
            // the old one is moved aside rather than deleted and can go once the new one has run.
            return "Move-Item -Force " + powershellQuote(to) + " " + powershellQuote(to + ".old") + "\n"
                + "  Move-Item " + powershellQuote(from) + " " + powershellQuote(to);
        }
        boolean mine = running != null && Files.isWritable(running);
        return (mine ? "" : "sudo ") + (jar ? "cp " : "install -m 755 ") + shellQuote(from) + " " + shellQuote(to);
    }

    /** {@code s} as one word to a POSIX shell: as it is when nothing in it needs it, else single-quoted. */
    static String shellQuote(String s) {
        // A leading = is a zsh command-path expansion (=ls), so it is quoted even though the
        // character is otherwise safe inside a word.
        if (!s.isEmpty() && s.charAt(0) != '='
            && s.chars().allMatch(c -> Character.isLetterOrDigit(c) || "_-./:@%+=,".indexOf(c) >= 0)) {
            return s;
        }
        return "'" + s.replace("'", "'\\''") + "'";
    }

    /** {@code s} as one PowerShell string: single-quoted, where only a quote needs doubling. */
    static String powershellQuote(String s) {
        return "'" + s.replace("'", "''") + "'";
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
            return p.toString().endsWith(".jar") ? p : null;
        } catch (java.net.URISyntaxException | RuntimeException e) {
            return null;
        }
    }

    /** Throws {@link HttpException} rather than flattening it, so the caller can read the status. */
    private static byte[] get(URI url, int max) throws IOException, HttpException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        HttpCall.get(url, headers(), buf, TIMEOUT_MS, max);
        return buf.toByteArray();
    }

    /**
     * Streams {@code url} into {@code file} through {@code sha}, and returns how many bytes.
     * Buffered underneath the digest so that a 25 MiB body is a few hundred writes rather than
     * one per socket read.
     */
    private static long download(URI url, Path file, MessageDigest sha) throws IOException {
        try (OutputStream out = new DigestOutputStream(new BufferedOutputStream(Files.newOutputStream(file), 64 * 1024), sha)) {
            return HttpCall.get(url, headers(), out, ASSET_TIMEOUT_MS, MAX_ASSET);
        } catch (HttpException e) {
            throw new IOException(url + ": " + e.getMessage(), e);
        }
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
