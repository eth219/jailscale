package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** The DNS responder is exposed to the whole internet on :53 (ARCHITECTURE.md §14): mutation fuzzing of its packet path. */
@Timeout(120)
class DnsFuzzTest {

    @Test
    void respondNeverThrows() throws Exception {
        DnsResponder d = new DnsResponder("hub.test");
        d.setTxt(java.util.List.of("abc"));
        d.setZone(new DnsResponder.Zone() {
            @Override public java.util.List<String> serving() { return java.util.List.of("203.0.113.1", "203.0.113.2"); }
            @Override public java.util.Map<String, String> nameServers() { return java.util.Map.of("ns1", "203.0.113.1", "ns2", "203.0.113.2"); }
        });
        byte[][] seeds = {
            query("_acme-challenge.hub.test", 16),
            query("_acme-challenge.hub.test", 6),
            query("hub.test", 2),
            query("_acme-challenge.hub.test", 255),
            query("other.example", 1),
            query("hub.test", 1),
            query("hub.test", 6),
            query("myapp.hub.test", 1),
            query("a.b.hub.test", 28),
            query("ns1.hub.test", 1),
            query("_jailhub-self.hub.test", 16),
            query("hub.test", 255),
        };
        Random rng = new Random(53);
        for (int i = 0; i < 20_000; i++) {
            byte[] in = i < seeds.length ? seeds[i] : mutate(rng, seeds[i % seeds.length]);
            try {
                byte[] out = d.respond(in);
                if (out != null && out.length > 4096) {
                    fail("oversized answer for " + Arrays.toString(in));
                }
            } catch (Throwable t) {
                fail("case " + i + " threw " + t, t);
            }
        }
    }

    private static byte[] mutate(Random rng, byte[] seed) {
        byte[] b = seed.clone();
        for (int k = 0, ops = 1 + rng.nextInt(4); k < ops; k++) {
            switch (rng.nextInt(4)) {
                case 0 -> {
                    if (b.length > 0) {
                        b[rng.nextInt(b.length)] = (byte) rng.nextInt(256);
                    }
                }
                case 1 -> b = Arrays.copyOf(b, rng.nextInt(b.length + 1));
                case 2 -> { // pointer loops and wild offsets
                    int at = 12 + rng.nextInt(Math.max(1, b.length - 12));
                    if (at < b.length) {
                        b[at] = (byte) (0xC0 | rng.nextInt(4));
                    }
                }
                default -> b = Arrays.copyOf(b, b.length + rng.nextInt(64));
            }
        }
        return b;
    }

    /** A plain query packet: header, one question. */
    static byte[] query(String name, int type) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x12);
        o.write(0x34);
        o.write(0x01);
        o.write(0x00);
        o.write(0);
        o.write(1);
        o.write(0);
        o.write(0);
        o.write(0);
        o.write(0);
        o.write(0);
        o.write(0);
        for (String label : name.split("\\.")) {
            byte[] l = label.getBytes(StandardCharsets.US_ASCII);
            o.write(l.length);
            o.write(l, 0, l.length);
        }
        o.write(0);
        o.write(type >> 8);
        o.write(type);
        o.write(0);
        o.write(1);
        return o.toByteArray();
    }
}
