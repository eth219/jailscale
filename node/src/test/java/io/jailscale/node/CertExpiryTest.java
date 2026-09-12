package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * The one line an operator may act on (ARCHITECTURE.md §15). A user domain's certificate is renewed
 * by the node, and renewal needs the hub, so the node that cannot renew is the node nobody hears
 * from. Getting this wrong is silent either way: too quiet and the site goes down unannounced, too
 * loud and the warning is what people learn to scroll past.
 */
class CertExpiryTest {

    private static final long NOW = 1_700_000_000_000L;
    private static final long DAY = 86400_000L;

    @Test
    void aCertificateWithPlentyOfLifeSaysNothing() {
        assertNull(Daemon.expiryWarning("app.example.com", NOW + 30 * DAY, NOW));
        assertNull(Daemon.expiryWarning("app.example.com", NOW + Daemon.CERT_WARN_MS + 1, NOW));
    }

    @Test
    void aLinkWithNoCertificateSaysNothing() {
        // Raw ports and names under the hub's own domain never load one, and 0 is "not known".
        assertNull(Daemon.expiryWarning("app.example.com", 0, NOW));
    }

    @Test
    void insideTheWindowItNamesTheDomainAndTheTimeLeft() {
        String w = Daemon.expiryWarning("app.example.com", NOW + 6 * DAY, NOW);
        assertTrue(w.contains("app.example.com"), w);
        assertTrue(w.contains("6 days"), w);
        assertTrue(w.contains("connected to its hub"), w);
    }

    @Test
    void theBoundaryIsInclusiveSoTheFirstDayIsNotMissed() {
        assertNotNull(Daemon.expiryWarning("app.example.com", NOW + Daemon.CERT_WARN_MS, NOW));
    }

    @Test
    void underADayIsCountedInHoursRatherThanZeroDays() {
        // "expires in 0 days" reads as a rounding error rather than as tonight.
        String w = Daemon.expiryWarning("app.example.com", NOW + 5 * 3600_000L, NOW);
        assertTrue(w.contains("5 hours"), w);
        String h = Daemon.expiryWarning("app.example.com", NOW + 90 * 60_000L, NOW);
        assertTrue(h.contains("an hour"), h);
    }

    @Test
    void anAlreadyExpiredCertificateSaysWhatTheVisitorSees() {
        String w = Daemon.expiryWarning("app.example.com", NOW - 3 * DAY, NOW);
        assertTrue(w.contains("EXPIRED"), w);
        assertTrue(w.contains("3 days ago"), w);
        assertTrue(w.contains("visitors"), w);
    }

    @Test
    void theCliAndTheLogUseOneThreshold() {
        // `ls` used to warn at seven days while nothing logged at all; one rule now.
        assertEquals(14 * DAY, Daemon.CERT_WARN_MS);
        assertEquals("", Main.certNote(NOW + Daemon.CERT_WARN_MS + 1, NOW));
        assertTrue(Main.certNote(NOW + Daemon.CERT_WARN_MS - 1, NOW).contains("cert expires"));
    }

    @Test
    void theCliSaysExpiredRatherThanExpiringInThePast() {
        // "expires <a date last week>" reads as a formatting bug, not as a site that is down.
        String n = Main.certNote(NOW - DAY, NOW);
        assertTrue(n.contains("EXPIRED"), n);
        assertFalse(n.contains("expires"), n);
    }

    @Test
    void theCliSaysNothingAboutALinkWithNoCertificate() {
        // Raw ports and hub-domain names: the daemon sends null and 0 means "not known" either way.
        assertEquals("", Main.certNote(0, NOW));
    }
}
