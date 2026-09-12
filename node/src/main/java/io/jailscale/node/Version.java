package io.jailscale.node;

/**
 * Build version, taken from the jar manifest when present (maven-jar-plugin adds it), with a
 * {@code +pgo} suffix when the binary was built against a profile.
 *
 * <p>The suffix exists so that "is this a profile-guided build?" is a question the binary answers.
 * A PGO build is about 7 MiB smaller and a fifth lighter at idle (ARCHITECTURE.md §14), the release
 * always makes one, and a redeploy of the public hub is supposed to check. Guessing from a file
 * size is not a check.
 */
final class Version {

    private Version() {}

    static String string() {
        String v = Version.class.getPackage() == null ? null : Version.class.getPackage().getImplementationVersion();
        return (v == null ? "dev" : v) + ("true".equals(System.getProperty("jailscale.pgo")) ? "+pgo" : "");
    }
}
