package io.jailscale.node;

/**
 * Build version, taken from the jar manifest when present (maven-jar-plugin adds it).
 *
 * <p>This deliberately does not say which build options the binary was built with, though it was
 * tried: a {@code -D} on the native-image command line is set for the builder and does not
 * reach the image's run time, and every other way of baking a constant in either needs build-time
 * class initialisation (§3.1 forbids it) or reuses a manifest field for something it does not mean.
 * The release answers it beside the binary instead: the published BUILDINFO.txt names the target,
 * the commit, the toolchain and the build options, and SHA256SUMS.txt lets anyone check that the
 * binary in hand is that one (§14).
 */
final class Version {

    private Version() {}

    static String string() {
        String v = Version.class.getPackage() == null ? null : Version.class.getPackage().getImplementationVersion();
        return v == null ? "dev" : v;
    }
}
