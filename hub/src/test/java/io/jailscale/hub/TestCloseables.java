package io.jailscale.hub;

/**
 * Closing a fixture without letting the first failure strand the rest of it.
 *
 * <p>A teardown written as a sequence of {@code close()} calls stops at the first one that throws,
 * and what the survivors hold is a listening port and its threads for the remainder of the suite.
 * From the outside that is an unrelated later test failing to bind, on a different class, with
 * nothing pointing back at the teardown -- a diagnosis that starts in the wrong file, which is the
 * cost #125 charged twice in one day.
 *
 * <p>So every item is closed whatever the others do, and the failure is still reported: the first
 * one thrown is what comes out, with any later ones attached to it as suppressed. Silence would
 * trade one bad failure mode for another.
 */
final class TestCloseables {

    private TestCloseables() {}

    /**
     * Closes each item in order, skipping nulls -- a fixture whose {@code @BeforeEach} threw part
     * way through still has its {@code @AfterEach} run, and half of its fields unset.
     *
     * <p>It catches {@link Throwable} and not {@link Exception}, because an {@code Error} on the
     * way out -- an assertion inside a close path, most likely -- strands the items behind it
     * exactly as an exception does, and stranding them is the whole of what this is for.
     *
     * @throws Exception the first failure, carrying any later ones as suppressed
     * @throws Error the first failure, when that is what it was
     */
    static void closeAll(AutoCloseable... items) throws Exception {
        Throwable first = null;
        for (AutoCloseable c : items) {
            if (c == null) {
                continue;
            }
            try {
                c.close();
            } catch (Throwable t) {
                if (first == null) {
                    first = t;
                } else if (first != t) {
                    // Throwable refuses to suppress itself, and the same instance arriving twice --
                    // one closeable listed twice, or a cached throwable rethrown -- would turn this
                    // into an IllegalArgumentException that says nothing about either close.
                    first.addSuppressed(t);
                }
            }
        }
        switch (first) {
            case null -> { }
            case Error e -> throw e;
            case Exception e -> throw e;
            // Throwable is not sealed, so the compiler wants this arm. Nothing in this repository
            // extends it directly; wrapping is the honest answer if anything ever does.
            default -> throw new IllegalStateException("close threw " + first, first);
        }
    }
}
