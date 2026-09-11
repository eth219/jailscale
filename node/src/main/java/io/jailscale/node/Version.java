package io.jailscale.node;

/** Build version, taken from the jar manifest when present (maven-jar-plugin adds it). */
final class Version {

    private Version() {}

    static String string() {
        String v = Version.class.getPackage() == null ? null : Version.class.getPackage().getImplementationVersion();
        return v == null ? "dev" : v;
    }
}
