package io.jailscale.hub;

import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Which build this process is, for the status page: the SHA-256 of the executable the kernel is
 * running, which is the file the release's {@code SHA256SUMS.txt} names.
 *
 * <p>It is self-reported, and the page says so. A hub that has been tampered with prints whatever
 * it likes here, so this is no evidence at all against a dishonest hub (ARCHITECTURE.md §11.2); what
 * it catches is an operator running something other than the release they believe they are, which is
 * the failure that actually happens.
 *
 * <p>Only a native image is hashed. Under a JAR the running executable is the JVM, and its digest
 * says nothing about jailhub, so nothing is reported rather than something misleading.
 */
final class Build {

    private static final Log LOG = Log.get("http");
    private static final int CHUNK = 64 * 1024;
    /** {@code ImageInfo.PROPERTY_IMAGE_CODE_KEY}, read directly so no build-time API is needed. */
    private static final String IMAGE_CODE = "org.graalvm.nativeimage.imagecode";

    private static boolean computed;
    private static String hash;

    private Build() {
    }

    /**
     * SHA-256 of the running executable in hex, or null where there is no single file to name.
     * Computed once on first use, since a hub nobody looks at should not read 26 MiB at boot.
     */
    static synchronized String executableSha256() {
        if (!computed) {
            computed = true;
            hash = hashSelf();
        }
        return hash;
    }

    private static String hashSelf() {
        if (System.getProperty(IMAGE_CODE) == null) {
            return null;
        }
        // /proc/self/exe names the image actually mapped, even if the file was renamed or replaced
        // since it started, which is the question being asked. Elsewhere, the command it was run as.
        Path exe = Path.of("/proc/self/exe");
        if (!Files.isReadable(exe)) {
            String cmd = ProcessHandle.current().info().command().orElse(null);
            if (cmd == null) {
                return null;
            }
            exe = Path.of(cmd);
        }
        try {
            return sha256(exe);
        } catch (IOException | RuntimeException e) {
            LOG.debug("cannot hash {}: {}", exe, e.toString());
            return null;
        }
    }

    /** Streams the file rather than reading it, so a 26 MiB binary costs one buffer. */
    static String sha256(Path file) throws IOException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required of every JRE", e);
        }
        byte[] buf = new byte[CHUNK];
        try (InputStream in = Files.newInputStream(file)) {
            for (int n; (n = in.read(buf)) > 0; ) {
                md.update(buf, 0, n);
            }
        }
        StringBuilder sb = new StringBuilder(64);
        for (byte b : md.digest()) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }
}
