package io.jailscale.proto.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;

/**
 * {@link NetKey}: what a per-address limit counts against (ARCHITECTURE.md §8.1, §11.5).
 *
 * <p>The hub serves both stacks wherever its listener is bound to {@code ::}, which is one flag and
 * an AAAA record away for any operator. Counted per address, every limit it has would then be free
 * to anyone with a routed /64 — which is every ordinary VPS.
 */
class NetKeyTest {

    @Test
    void aV4AddressIsItsOwnKey() {
        // In v4 an attacker has to acquire each address, so the address is the unit.
        assertEquals("203.0.113.7", NetKey.of("203.0.113.7"));
        assertNotEquals(NetKey.of("203.0.113.7"), NetKey.of("203.0.113.8"), "neighbours are not one key");
    }

    @Test
    void everyAddressInAV6SixtyFourIsOneKey() throws Exception {
        String a = NetKey.of("2001:db8:1:2::1");
        assertEquals(a, NetKey.of("2001:db8:1:2::2"));
        assertEquals(a, NetKey.of("2001:db8:1:2:ffff:ffff:ffff:ffff"));
        assertEquals(a, NetKey.of(InetAddress.getByName("2001:db8:1:2:dead:beef::1")), "from an address too");
        assertNotEquals(a, NetKey.of("2001:db8:1:3::1"), "the next /64 is another key");
        assertNotEquals(a, NetKey.of("2001:db8:2:2::1"), "and so is another /48");
    }

    @Test
    void aKeyIsNotMistakableForAnAddress() {
        // It is logged and compared, never parsed back, and it should not read as an address that
        // somebody could then look for in a ban list or a packet capture.
        String key = NetKey.of("2001:db8:1:2::1");
        assertEquals("20010db800010002/64", key);
    }

    @Test
    void nonsenseIsItsOwnKeyRatherThanEverybodysKey() {
        // Whatever arrives here has come off a socket or a PROXY header, but a key that collapsed
        // on bad input would put every such caller in one bucket, and that bucket would be the one
        // honest callers were in.
        assertEquals("not-an-address", NetKey.of("not-an-address"));
        assertEquals("", NetKey.of((String) null));
        assertNotEquals(NetKey.of("::gg::"), NetKey.of("::hh::"));
    }

    @Test
    void v4MappedV6IsTreatedAsTheV4AddressItIs() throws Exception {
        // A dual-stack listener reports a v4 peer this way on some stacks. It has to land on the
        // same key as the plain v4 address, or the two paths to one host would get two budgets.
        assertEquals(NetKey.of("203.0.113.7"), NetKey.of(InetAddress.getByName("::ffff:203.0.113.7")));
    }
}
