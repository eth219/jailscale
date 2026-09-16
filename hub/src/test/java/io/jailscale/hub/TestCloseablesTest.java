package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * What {@link TestCloseables#closeAll} has to do that a sequence of {@code close()} calls does not.
 *
 * <p>Each case is the failure direction rather than the happy one: a helper that only ever closed
 * things that do not throw is indistinguishable from the plain sequence it replaces, and the plain
 * sequence is the defect (#159). So something always refuses to close here, and what is asserted is
 * that the ones behind it were closed anyway.
 *
 * <p>The three shapes of refusal are driven separately because the helper treats them differently
 * and a narrower catch would pass a suite that only drove one: a checked exception, which is what
 * {@code Daemon.close()} and {@code Hub.close()} actually declare; an unchecked one; and an
 * {@code Error}, which is not part of {@code AutoCloseable}'s contract and strands the fixture
 * just the same.
 */
class TestCloseablesTest {

    /** Records that it was closed, and optionally refuses to be. */
    private static final class Spy implements AutoCloseable {
        private final String name;
        private final List<String> log;
        private final Throwable fail;
        private Spy(String name, List<String> log, Throwable fail) {
            this.name = name;
            this.log = log;
            this.fail = fail;
        }

        /**
         * {@code throws IOException} and not {@code throws Exception}: javac warns that an
         * auto-closeable whose close can throw {@code Exception} can throw
         * {@code InterruptedException}, and this build is {@code -Werror}. It is also the narrower
         * truth -- {@code IOException} is what the closeables in the real fixture declare.
         */
        @Override
        public void close() throws IOException {
            log.add(name);
            if (fail instanceof IOException e) {
                throw e;
            }
            if (fail instanceof RuntimeException e) {
                throw e;
            }
            if (fail instanceof Error e) {
                throw e;
            }
            if (fail != null) {
                throw new IllegalStateException("this spy cannot throw a " + fail.getClass().getName(), fail);
            }
        }
    }

    @Test
    void oneThatRefusesToCloseDoesNotStrandTheOnesBehindIt() {
        List<String> closed = new ArrayList<>();
        RuntimeException boom = new IllegalStateException("daemon");
        Spy daemon = new Spy("daemon", closed, boom);
        Spy localApp = new Spy("localApp", closed, null);
        Spy hub = new Spy("hub", closed, null);

        Exception thrown = assertThrows(Exception.class, () -> TestCloseables.closeAll(daemon, localApp, hub));

        assertSame(boom, thrown, "the failure has to be reported, not swallowed");
        assertEquals(List.of("daemon", "localApp", "hub"), closed,
            "the hub keeps its port and its threads for the rest of the suite if this is not all three");
    }

    @Test
    void aCheckedFailureIsCaughtToo() {
        // Daemon.close() and Hub.close() declare checked exceptions, so this is the shape the real
        // teardown produces; a catch narrowed to RuntimeException would leave the case above green.
        List<String> closed = new ArrayList<>();
        IOException boom = new IOException("daemon");
        Spy daemon = new Spy("daemon", closed, boom);
        Spy hub = new Spy("hub", closed, null);

        Exception thrown = assertThrows(Exception.class, () -> TestCloseables.closeAll(daemon, hub));

        assertSame(boom, thrown);
        assertEquals(List.of("daemon", "hub"), closed);
    }

    @Test
    void anErrorDoesNotStrandThemEither() {
        // Not part of AutoCloseable's contract, and it leaves the fixture open exactly as an
        // exception does -- an assertion inside a close path is the likely way to get one.
        List<String> closed = new ArrayList<>();
        AssertionError boom = new AssertionError("daemon");
        Spy daemon = new Spy("daemon", closed, boom);
        Spy hub = new Spy("hub", closed, null);

        AssertionError thrown = assertThrows(AssertionError.class, () -> TestCloseables.closeAll(daemon, hub));

        assertSame(boom, thrown, "an Error is rethrown as itself rather than wrapped");
        assertEquals(List.of("daemon", "hub"), closed);
    }

    @Test
    void everyFailureIsReported() {
        List<String> closed = new ArrayList<>();
        RuntimeException firstBoom = new IllegalStateException("daemon");
        RuntimeException secondBoom = new IllegalStateException("hub");
        Spy daemon = new Spy("daemon", closed, firstBoom);
        Spy hub = new Spy("hub", closed, secondBoom);

        Exception thrown = assertThrows(Exception.class, () -> TestCloseables.closeAll(daemon, hub));

        assertSame(firstBoom, thrown);
        assertEquals(1, thrown.getSuppressed().length, "the second failure is attached, not dropped");
        assertSame(secondBoom, thrown.getSuppressed()[0]);
        assertEquals(List.of("daemon", "hub"), closed);
    }

    @Test
    void theSameFailureArrivingTwiceIsNotSuppressedIntoItself() {
        // One closeable listed twice, or a cached throwable rethrown. Throwable refuses to suppress
        // itself, so without the guard this is an IllegalArgumentException thrown from inside the
        // loop -- which both hides the real failure and strands whatever was behind it.
        List<String> closed = new ArrayList<>();
        RuntimeException shared = new IllegalStateException("the same one twice");
        Spy first = new Spy("first", closed, shared);
        Spy second = new Spy("second", closed, shared);
        Spy hub = new Spy("hub", closed, null);

        Exception thrown = assertThrows(Exception.class, () -> TestCloseables.closeAll(first, second, hub));

        assertSame(shared, thrown);
        assertEquals(0, thrown.getSuppressed().length, "it cannot be attached to itself");
        assertEquals(List.of("first", "second", "hub"), closed);
    }

    @Test
    void aFailureOnTheLastItemIsStillReported() {
        // The hub is last in the real teardown, so a hub that fails to close is the case every
        // other test here leaves uncovered: they all refuse on the first item.
        List<String> closed = new ArrayList<>();
        RuntimeException boom = new IllegalStateException("hub");
        Spy daemon = new Spy("daemon", closed, null);
        Spy hub = new Spy("hub", closed, boom);

        Exception thrown = assertThrows(Exception.class, () -> TestCloseables.closeAll(daemon, hub));

        assertSame(boom, thrown);
        assertEquals(List.of("daemon", "hub"), closed);
    }

    @Test
    void aFixtureThatWasHalfBuiltStillTearsDown() throws Exception {
        List<String> closed = new ArrayList<>();
        Spy hub = new Spy("hub", closed, null);

        // What an @AfterEach sees when its @BeforeEach threw between the hub and the local app.
        TestCloseables.closeAll(null, hub, null);

        assertEquals(List.of("hub"), closed);
    }

    @Test
    void nothingIsThrownWhenNothingFails() throws Exception {
        List<String> closed = new ArrayList<>();
        TestCloseables.closeAll(new Spy("a", closed, null), new Spy("b", closed, null));
        assertEquals(List.of("a", "b"), closed, "in the order given, which is the order a fixture was built in");
    }
}
