package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.util.Args;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * {@link Main#FLAGS} against the two things it has to agree with: the parser, and the usage text.
 *
 * <p>A flag missing from the list is read as taking a value, so the next word is swallowed and an
 * option at the end of the line is refused outright -- that is how {@code --proxy-protocol} was
 * found missing from jailhub's list. A flag on the list that the usage text never names is the
 * opposite mistake and just as quiet: {@code --new-link} was declared here and documented on
 * {@code gate}, and nothing read it, because {@code gate NAME} issues a fresh link either way.
 * {@code --foreground} was declared and neither read nor documented.
 */
class CliFlagsTest {

    /**
     * The two every CLI is expected to take without saying so. Listing them as exceptions rather
     * than adding them to the usage text keeps the rule below exact.
     */
    private static final Set<String> UNIVERSAL = Set.of("debug", "help");

    /**
     * Spelled out rather than read from {@link Main#FLAGS}, which would make this tautological:
     * iterating the list can only ever confirm what is on it, and the mistake worth catching is a
     * flag that has fallen off. Written the lazy way first, this passed with a flag deleted from
     * the list -- exactly the bug it exists to find.
     */
    private static final String[] READ_BY_THE_CLI = {"debug", "self", "tls-insecure", "help", "gate", "off",
        "proxy-protocol", "download"};

    @Test
    void everyFlagTheCliReadsIsDeclaredAndTakesNoValue() {
        for (String flag : READ_BY_THE_CLI) {
            Args a = Args.parse(new String[] {"open", "8080", "--" + flag}, Main.FLAGS);
            assertTrue(a.flag(flag), "--" + flag + " is not in Main.FLAGS");
            assertEquals(List.of("open", "8080"), a.positional(), "--" + flag + " swallowed a word");
        }
        assertEquals(READ_BY_THE_CLI.length, Main.FLAGS.length,
            "Main.FLAGS has an entry this test does not know about: " + String.join(", ", Main.FLAGS));
    }

    @Test
    void everyDeclaredFlagIsOneTheUsageTextOffers() {
        for (String flag : Main.FLAGS) {
            if (UNIVERSAL.contains(flag)) {
                continue;
            }
            assertTrue(Main.USAGE.contains("--" + flag),
                "--" + flag + " is declared but the usage text never offers it; either document it or drop it");
        }
    }

    /** And the gate's own line says what it does, now that no option distinguishes the two cases. */
    @Test
    void theGateLineNoLongerOffersAnOptionThatChangesNothing() {
        String line = Main.USAGE.lines().filter(l -> l.strip().startsWith("jailscale gate")).findFirst().orElseThrow();
        assertTrue(line.contains("--ttl"), line);
        assertTrue(line.contains("--off"), line);
        assertTrue(!line.contains("--new-link"), line);
    }
}
