package io.jailscale.node;

/**
 * Build version, taken from the jar manifest when present (maven-jar-plugin adds it).
 *
 * <p>This deliberately does not say whether the binary was built against a PGO profile, though it
 * was tried: a {@code -D} on the native-image command line is set for the builder and does not
 * reach the image's run time, and every other way of baking a constant in either needs build-time
 * class initialisation (§3.1 forbids it) or reuses a manifest field for something it does not mean.
 * The release proves it instead, which is stronger: each native build is checked for
 * "PGO: user-provided" in native-image's own output, and the published BUILDINFO.txt and
 * SHA256SUMS.txt say what was built and let anyone check that a binary is that one (§14).
 */
final class Version {

    private Version() {}

    static String string() {
        String v = Version.class.getPackage() == null ? null : Version.class.getPackage().getImplementationVersion();
        return v == null ? "dev" : v;
    }
}
