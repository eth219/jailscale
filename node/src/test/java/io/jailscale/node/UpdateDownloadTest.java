package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpRequest;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@code update --download} end to end against a release this test publishes itself
 * (ARCHITECTURE.md §9.4): the signature over {@code RELEASE.txt}, that file's digest of
 * {@code SHA256SUMS.txt}, that list's hash of the binary, and what is left on disk when any of the
 * three does not hold.
 *
 * <p>The asset is always {@code jailscale.jar} here, because these run on a JVM and that is what a
 * JVM build is told to fetch; {@link UpdatesTest} covers the native targets separately.
 */
class UpdateDownloadTest {

    private static final String TAG = "v0.2.0";
    private static final Updates.Result NEWER = new Updates.Result("0.1.0", "0.2.0", TAG, true, 0, null);

    private record Release(Map<String, byte[]> files, List<String> keys) {}

    /** A release served on loopback: paths under /v0.2.0/ to bytes. */
    private static ServerSocket serve(Map<String, byte[]> files) throws IOException {
        ServerSocket ss = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread t = new Thread(() -> {
            while (!ss.isClosed()) {
                try (Socket s = ss.accept()) {
                    HttpRequest r = Http.readRequest(s.getInputStream(), 0);
                    byte[] body = files.get(r.path());
                    var out = s.getOutputStream();
                    out.write(("HTTP/1.1 " + (body == null ? "404 Not Found" : "200 OK") + "\r\nContent-Length: "
                        + (body == null ? 0 : body.length) + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                    if (body != null) {
                        out.write(body);
                    }
                    out.flush();
                } catch (Exception e) {
                    return;
                }
            }
        }, "canned-release");
        t.setDaemon(true);
        t.start();
        return ss;
    }

    private static Updates.Source at(ServerSocket ss, Release rel) {
        return new Updates.Source("http://" + ss.getInetAddress().getHostAddress() + ":" + ss.getLocalPort() + "/",
            rel.keys());
    }

    private static String sha256(byte[] b) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
    }

    /** A binary big enough that it arrives in more than one read. */
    private static byte[] binary(String seed) {
        byte[] b = new byte[64 * 1024];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) (i * 31 + seed.charAt(i % seed.length()));
        }
        return b;
    }

    /** What an honest release looks like: everything describes everything below it. */
    private static Release honest(byte[] asset) throws Exception {
        return publish(asset, asset, TAG, Updates.MANIFEST_FORMAT, true);
    }

    /**
     * A release with each link of the chain separately bendable, signed the way
     * {@code tools/sign-release.sh} signs one -- over {@code RELEASE.txt}, never over the binary.
     *
     * @param asset what is served as jailscale.jar
     * @param sumsDescribes what SHA256SUMS.txt claims jailscale.jar hashes to
     * @param manifestTag the release RELEASE.txt says it is
     * @param format the format line RELEASE.txt opens with
     * @param signManifest whether the signature is over RELEASE.txt or over something else
     */
    private static Release publish(byte[] asset, byte[] sumsDescribes, String manifestTag, String format,
        boolean signManifest) throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] sums = (sha256(sumsDescribes) + "  jailscale.jar\n"
            + sha256("a hub".getBytes(StandardCharsets.UTF_8)) + "  jailhub-linux-amd64\n")
            .getBytes(StandardCharsets.UTF_8);
        byte[] manifest = (format + "\ntag: " + manifestTag + "\nsha256sums: " + sha256(sums) + "\n")
            .getBytes(StandardCharsets.UTF_8);
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(kp.getPrivate());
        s.update(signManifest ? manifest : "something else entirely".getBytes(StandardCharsets.UTF_8));
        Map<String, byte[]> files = new HashMap<>();
        files.put("/v0.2.0/RELEASE.txt", manifest);
        files.put("/v0.2.0/RELEASE.txt.sig", s.sign());
        files.put("/v0.2.0/SHA256SUMS.txt", sums);
        files.put("/v0.2.0/jailscale.jar", asset);
        return new Release(files, List.of(Base64.getEncoder().encodeToString(kp.getPublic().getEncoded())));
    }

    private static List<String> left(Path dir) throws IOException {
        try (var s = Files.list(dir)) {
            return s.map(Path::getFileName).map(Path::toString).sorted().toList();
        }
    }

    @Test
    void fetchesWhatTheSignedChainDescribes(@TempDir Path dir) throws Exception {
        byte[] asset = binary("jailscale");
        Release rel = honest(asset);
        try (ServerSocket ss = serve(rel.files())) {
            Updates.Downloaded d = Updates.fetch(NEWER, dir, at(ss, rel));
            assertEquals("jailscale.jar", d.asset());
            assertEquals(asset.length, d.bytes());
            assertEquals(sha256(asset), d.sha256());
            assertEquals(-1, java.util.Arrays.mismatch(asset, Files.readAllBytes(d.file())));
            assertEquals(ReleaseKey.fingerprint(rel.keys().get(0)), d.key()); // the key that actually accepted it
            assertEquals(dir, d.file().getParent());
        }
    }

    @Test
    void anOldReleaseRepublishedUnderANewTagIsRefused(@TempDir Path dir) throws Exception {
        // The whole reason the tag is inside the signed bytes. Someone with release-write access
        // cannot forge a signature, but without this they would not need to: they could publish
        // v0.2.0 carrying an old, genuinely signed, vulnerable release and this would call it
        // verified. Every file below is authentic and internally consistent; only the tag differs.
        Release rel = publish(binary("old vulnerable"), binary("old vulnerable"), "v0.1.0",
            Updates.MANIFEST_FORMAT, true);
        try (ServerSocket ss = serve(rel.files())) {
            IOException e = assertThrows(IOException.class, () -> Updates.fetch(NEWER, dir, at(ss, rel)));
            assertTrue(e.getMessage().contains("says it belongs to v0.1.0"), e.getMessage());
            assertEquals(List.of(), left(dir));
        }
    }

    @Test
    void aChecksumListTheManifestDoesNotDescribeIsRefused(@TempDir Path dir) throws Exception {
        // The signature covers RELEASE.txt, so SHA256SUMS.txt is only trustworthy through the digest
        // in it. Swap the list for one that is internally consistent with a different binary and the
        // chain has to break at that digest -- otherwise the signature covers nothing that matters.
        Release rel = honest(binary("jailscale"));
        Map<String, byte[]> swapped = new HashMap<>(rel.files());
        byte[] other = binary("swapped");
        swapped.put("/v0.2.0/SHA256SUMS.txt", (sha256(other) + "  jailscale.jar\n").getBytes(StandardCharsets.UTF_8));
        swapped.put("/v0.2.0/jailscale.jar", other);
        try (ServerSocket ss = serve(swapped)) {
            IOException e = assertThrows(IOException.class, () -> Updates.fetch(NEWER, dir, at(ss, rel)));
            assertTrue(e.getMessage().contains("not the one that was signed"), e.getMessage());
            assertEquals(List.of(), left(dir));
        }
    }

    @Test
    void aBinaryThatIsNotTheOneInTheListIsDeletedRatherThanOffered(@TempDir Path dir) throws Exception {
        // Signature and manifest honest, list signed and honest; the file served under that name is
        // not the file it names.
        Release rel = publish(binary("swapped"), binary("jailscale"), TAG, Updates.MANIFEST_FORMAT, true);
        try (ServerSocket ss = serve(rel.files())) {
            IOException e = assertThrows(IOException.class, () -> Updates.fetch(NEWER, dir, at(ss, rel)));
            assertTrue(e.getMessage().contains("not what the release says it is"), e.getMessage());
            // Nothing is left for a hurried operator to install: the message names a file that is gone.
            assertEquals(List.of(), left(dir));
        }
    }

    @Test
    void anUnsignedManifestIsNotReadAtAll(@TempDir Path dir) throws Exception {
        // Signature first, on purpose: a manifest nobody signed is a manifest anyone could have
        // written, and this must not get as far as fetching 25 MiB on its say-so.
        Release rel = publish(binary("jailscale"), binary("jailscale"), TAG, Updates.MANIFEST_FORMAT, false);
        try (ServerSocket ss = serve(rel.files())) {
            assertThrows(SignatureException.class, () -> Updates.fetch(NEWER, dir, at(ss, rel)));
            assertEquals(List.of(), left(dir));
        }
    }

    @Test
    void aFormatThisBuildWasNotTaughtIsRefused(@TempDir Path dir) throws Exception {
        // A later release could add fields, which this ignores; a different format line is a change
        // it cannot assume is additive, so it stops rather than guessing (§5.4's rule, on a file).
        Release rel = publish(binary("jailscale"), binary("jailscale"), TAG, "jailscale-release 2", true);
        try (ServerSocket ss = serve(rel.files())) {
            IOException e = assertThrows(IOException.class, () -> Updates.fetch(NEWER, dir, at(ss, rel)));
            assertTrue(e.getMessage().contains("not in a format this build reads"), e.getMessage());
            assertEquals(List.of(), left(dir));
        }
    }

    @Test
    void aReleaseWithNothingSignedBesideItIsARefusal(@TempDir Path dir) throws Exception {
        // What every release published before the signing key existed looks like: assets, a checksum
        // file, and nothing signed. It has to be an error rather than a download.
        Release rel = honest(binary("jailscale"));
        Map<String, byte[]> unsigned = new HashMap<>(rel.files());
        unsigned.remove("/v0.2.0/RELEASE.txt");
        unsigned.remove("/v0.2.0/RELEASE.txt.sig");
        try (ServerSocket ss = serve(unsigned)) {
            IOException e = assertThrows(IOException.class, () -> Updates.fetch(NEWER, dir, at(ss, rel)));
            assertTrue(e.getMessage().contains("carries no signed RELEASE.txt"), e.getMessage());
            // And it says so plainly rather than as an HTTP status, which is the 404's whole point:
            // the status is read (see the 503 below) rather than passed on for the operator to
            // interpret.
            assertFalse(e.getMessage().contains("404"), e.getMessage());
            assertEquals(List.of(), left(dir));
        }
    }

    @Test
    void aNetworkFailureIsNotReportedAsAnUnsignedRelease(@TempDir Path dir) throws Exception {
        // The message for an unsigned release tells the operator to install by hand, which is right
        // for a release that has nothing signed and wrong for a server that was briefly unhappy --
        // that one is steering someone off verification for something a retry would fix.
        Release rel = honest(binary("jailscale"));
        try (ServerSocket ss = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            Thread t = new Thread(() -> {
                while (!ss.isClosed()) {
                    try (Socket s = ss.accept()) {
                        Http.readRequest(s.getInputStream(), 0);
                        s.getOutputStream().write("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
                            .getBytes(StandardCharsets.ISO_8859_1));
                        s.getOutputStream().flush();
                    } catch (Exception e) {
                        return;
                    }
                }
            }, "unhappy-release");
            t.setDaemon(true);
            t.start();
            Updates.Source source = new Updates.Source(
                "http://" + ss.getInetAddress().getHostAddress() + ":" + ss.getLocalPort() + "/", rel.keys());
            IOException e = assertThrows(IOException.class, () -> Updates.fetch(NEWER, dir, source));
            assertTrue(e.getMessage().contains("503"), e.getMessage());
            assertFalse(e.getMessage().contains("by hand"), e.getMessage());
            assertEquals(List.of(), left(dir));
        }
    }

    @Test
    void withoutAKeyNothingIsEvenAsked(@TempDir Path dir) throws Exception {
        Release rel = honest(binary("jailscale"));
        try (ServerSocket ss = serve(rel.files())) {
            IOException e = assertThrows(IOException.class, () -> Updates.fetch(NEWER, dir,
                new Updates.Source(at(ss, rel).base(), List.of())));
            assertTrue(e.getMessage().contains("no release signing key"), e.getMessage());
            assertEquals(List.of(), left(dir));
        }
    }

    @Test
    void theListHasToNameTheFileThisBuildWants(@TempDir Path dir) throws Exception {
        // A release carrying every other target's binary and not this one. The download must stop at
        // "there is nothing to check it against" rather than fetch something unchecked.
        Release rel = honest(binary("jailscale"));
        Map<String, byte[]> files = new HashMap<>(rel.files());
        byte[] sums = (sha256(binary("hub")) + "  jailhub-linux-amd64\n").getBytes(StandardCharsets.UTF_8);
        files.put("/v0.2.0/SHA256SUMS.txt", sums);
        // and a manifest that honestly describes that list, so the chain only breaks at the name
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] manifest = (Updates.MANIFEST_FORMAT + "\ntag: " + TAG + "\nsha256sums: " + sha256(sums) + "\n")
            .getBytes(StandardCharsets.UTF_8);
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(kp.getPrivate());
        s.update(manifest);
        files.put("/v0.2.0/RELEASE.txt", manifest);
        files.put("/v0.2.0/RELEASE.txt.sig", s.sign());
        Release named = new Release(files, List.of(Base64.getEncoder().encodeToString(kp.getPublic().getEncoded())));
        try (ServerSocket ss = serve(files)) {
            IOException e = assertThrows(IOException.class, () -> Updates.fetch(NEWER, dir, at(ss, named)));
            assertTrue(e.getMessage().contains("no line for jailscale.jar"), e.getMessage());
            assertFalse(Files.exists(dir.resolve("jailscale.jar")));
        }
    }

    @Test
    void aManifestMissingWhatItMustSayIsRefused() {
        // Parsed only after the signature, but a signed document that does not say what it must is
        // still not something to guess at.
        assertThrows(IOException.class, () -> Updates.Manifest.parse(""));
        assertThrows(IOException.class, () -> Updates.Manifest.parse("tag: v0.2.0\nsha256sums: " + "a".repeat(64)));
        assertThrows(IOException.class, () -> Updates.Manifest.parse(Updates.MANIFEST_FORMAT + "\ntag: v0.2.0\n"));
        assertThrows(IOException.class, () -> Updates.Manifest.parse(Updates.MANIFEST_FORMAT + "\nsha256sums: "
            + "a".repeat(64) + "\n"));
        assertThrows(IOException.class, () -> Updates.Manifest.parse(Updates.MANIFEST_FORMAT
            + "\ntag: v0.2.0\nsha256sums: nothex\n"));
        assertThrows(IOException.class, () -> Updates.Manifest.parse(Updates.MANIFEST_FORMAT
            + "\ntag: \nsha256sums: " + "a".repeat(64) + "\n"));
    }

    @Test
    void aManifestMaySayMoreThanThisBuildReads() throws Exception {
        // The additive case: a field a later release adds must not stop an older build, which is the
        // same rule §5.4 applies to the wire.
        Updates.Manifest m = Updates.Manifest.parse(Updates.MANIFEST_FORMAT + "\ntag: v0.3.0\nnotes: whatever\n"
            + "sha256sums: " + "b".repeat(64) + "\nsigned-by: someone\n");
        assertEquals("v0.3.0", m.tag());
        assertEquals("b".repeat(64), m.sums());
    }
}
