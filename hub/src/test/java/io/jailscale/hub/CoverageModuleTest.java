package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * The coverage report covers every module, and goes on doing so.
 *
 * <p>{@code coverage/pom.xml} lists each module as a direct compile dependency because that is the
 * only thing jacoco's {@code report-aggregate} reads. A module missing from that list is not an
 * error, a warning, or a smaller number: it is a report that silently omits it, which is worse than
 * no report. That already happened once — the first version ran the aggregation from {@code hub} and
 * covered hub and proto only, dropping {@code node} because hub depends on it at test scope and
 * {@code crypto} because it arrives through proto rather than directly. The figure looked
 * reasonable, and {@code node} is the module the whole aggregation exists for.
 *
 * <p>Here rather than in {@code coverage/} because that module is pom-packaged and builds no tests,
 * and rather than nowhere because this project already keeps this kind of check — the CLI's flag
 * table against its usage text, every {@code Message} record against a pinned wire line.
 */
class CoverageModuleTest {

    /** {@code <module>x</module>}, which in the root pom is both the build list and this list. */
    private static final Pattern MODULE = Pattern.compile("<module>([^<]+)</module>");

    /** {@code <artifactId>x</artifactId>} inside coverage/pom.xml's dependency block. */
    private static final Pattern ARTIFACT = Pattern.compile("<artifactId>([^<]+)</artifactId>");

    /**
     * The repository root. Surefire runs with the module directory as the working directory, so the
     * root is one level up; asserted rather than assumed, because a wrong answer here would make
     * this test pass by reading nothing.
     */
    private static Path root() {
        Path root = Path.of("..").toAbsolutePath().normalize();
        assertTrue(Files.isRegularFile(root.resolve("pom.xml")),
            "expected the repository root at " + root + "; this test reads the poms and cannot do it from elsewhere");
        return root;
    }

    private static String read(Path p) throws IOException {
        assertTrue(Files.isRegularFile(p), p + " is missing");
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    @Test
    void everyModuleInTheBuildIsInTheCoverageReport() throws IOException {
        Path root = root();
        Set<String> built = new LinkedHashSet<>();
        Matcher m = MODULE.matcher(read(root.resolve("pom.xml")));
        while (m.find()) {
            // `coverage` is itself one of these, listed under the profile it belongs to. It has no
            // code and does not cover itself.
            if (!m.group(1).equals("coverage")) {
                built.add(m.group(1));
            }
        }
        assertEquals(Set.of("crypto", "proto", "node", "hub"), built,
            "the build's module list moved; if that is deliberate, coverage/pom.xml moves with it");

        String coverage = read(root.resolve("coverage/pom.xml"));
        String deps = coverage.substring(coverage.indexOf("<dependencies>"), coverage.indexOf("</dependencies>"));
        Set<String> covered = new LinkedHashSet<>();
        Matcher d = ARTIFACT.matcher(deps);
        while (d.find()) {
            covered.add(d.group(1));
        }

        assertEquals(built, covered,
            "coverage/pom.xml does not depend on every module, so -Pcoverage reports a number that "
                + "leaves one out without saying so");
    }

    @Test
    void theCoverageModuleIsOnlyBuiltUnderItsProfile() throws IOException {
        // If it ever moved into the top-level <modules>, an ordinary `./mvnw package` would build a
        // module that exists to run a third-party agent -- which is the thing §3.2 keeps behind a
        // profile so that building from source needs nothing but a JDK.
        String pom = read(root().resolve("pom.xml"));
        int profile = pom.indexOf("<id>coverage</id>");
        assertTrue(profile > 0, "the coverage profile is gone; so is the report this test is about");
        assertTrue(pom.indexOf("<module>coverage</module>") > profile,
            "coverage is listed as a module outside its own profile");
    }
}
