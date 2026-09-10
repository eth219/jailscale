package io.jailscale.node;

/** Entry point of the {@code jailscale} binary. M0 placeholder: prints the version and exits. */
public final class Main {

    private Main() {}

    public static void main(String[] args) {
        System.out.println("jailscale " + Version.string());
    }
}
