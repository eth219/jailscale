package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * No teardown in this package closes two things in sequence.
 *
 * <p>A sequence stops at the first {@code close()} that throws, and what the survivors hold is a
 * listening port and its threads for the rest of the suite. From the outside that is an unrelated
 * later class failing to bind, with nothing pointing back at the teardown — #125 charged that
 * diagnosis twice in one day, #159 fixed the one class it had been found in, and #169 was the other
 * nineteen.
 *
 * <p>A test rather than a note, because nineteen classes were fixed by hand and the twentieth is
 * written by somebody who has not read any of this. {@link TestCloseables#closeAll} is the answer
 * and it is one line.
 *
 * <p>This reads source rather than behaviour, which is the only way to ask the question at all: the
 * failure it prevents is a later, unrelated test failing to bind, and no assertion can be written
 * where that lands.
 */
@Timeout(60)
class FixtureTeardownTest {

    /** A close-alike counts too: an {@code HttpServer} stops rather than closes. */
    private static final Pattern CLOSING = Pattern.compile("\\w+\\.(close|stop)\\(");
    private static final Pattern TEARDOWN =
        Pattern.compile("@AfterEach\\s*\\n\\s*(?:\\w+\\s+)*void\\s+\\w+\\([^)]*\\)[^{]*\\{(.*?)\\n    \\}", Pattern.DOTALL);

    @Test
    void noTeardownClosesTwoThingsInSequence() throws IOException {
        Path dir = Path.of("src/test/java/io/jailscale/hub");
        assertTrue(Files.isDirectory(dir), "the test sources moved; this test reads them: " + dir.toAbsolutePath());
        List<String> offenders = new ArrayList<>();
        int checked = 0;
        try (Stream<Path> files = Files.walk(dir)) {
            for (Path f : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                Matcher m = TEARDOWN.matcher(Files.readString(f));
                if (!m.find()) {
                    continue;
                }
                checked++;
                String body = m.group(1);
                if (body.contains("TestCloseables.closeAll")) {
                    continue;
                }
                long n = CLOSING.matcher(body).results().count();
                if (n >= 2) {
                    offenders.add(f.getFileName() + " (" + n + ")");
                }
            }
        }
        // The count is asserted as well: a regex that stopped matching any teardown at all would
        // otherwise report success for a package it had not read, which is the shape this whole
        // class exists to refuse.
        assertTrue(checked >= 20, "expected to have read at least 20 teardowns, read " + checked);
        assertTrue(offenders.isEmpty(),
            "these close two or more things in sequence, so the first failure strands the rest; "
                + "use TestCloseables.closeAll: " + offenders);
    }
}
