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
     * @throws Exception the first failure, carrying any later ones as suppressed
     */
    static void closeAll(AutoCloseable... items) throws Exception {
        Exception first = null;
        for (AutoCloseable c : items) {
            if (c == null) {
                continue;
            }
            try {
                c.close();
            } catch (Exception e) {
                if (first == null) {
                    first = e;
                } else {
                    first.addSuppressed(e);
                }
            }
        }
        if (first != null) {
            throw first;
        }
    }
}
