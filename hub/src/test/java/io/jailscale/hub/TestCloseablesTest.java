package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * What {@link TestCloseables#closeAll} has to do that a sequence of {@code close()} calls does not.
 *
 * <p>Each case is the failure direction rather than the happy one: a helper that only ever closed
 * things that do not throw is indistinguishable from the plain sequence it replaces, and the plain
 * sequence is the defect (#159). So the item that throws is always first here, and what is asserted
 * is that the ones behind it were still closed.
 */
class TestCloseablesTest {

    /** Records that it was closed, and optionally refuses to be. */
    private static final class Spy implements AutoCloseable {
        private final String name;
        private final List<String> log;
        private final RuntimeException fail;
        private Spy(String name, List<String> log, RuntimeException fail) {
            this.name = name;
            this.log = log;
            this.fail = fail;
        }

        @Override
        public void close() {
            log.add(name);
            if (fail != null) {
                throw fail;
            }
        }
    }

    @Test
    void oneThatRefusesToCloseDoesNotStrandTheOnesBehindIt() throws Exception {
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
