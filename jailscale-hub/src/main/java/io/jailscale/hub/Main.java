package io.jailscale.hub;

/** Entry point of the {@code jailhub} binary. M0 placeholder: prints the version and exits. */
public final class Main {

    private Main() {}

    public static void main(String[] args) {
        String v = Main.class.getPackage() == null ? null : Main.class.getPackage().getImplementationVersion();
        System.out.println("jailhub " + (v == null ? "dev" : v));
    }
}
