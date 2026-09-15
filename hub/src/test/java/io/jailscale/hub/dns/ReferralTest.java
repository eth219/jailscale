package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The glue is read from the parent's referral (ARCHITECTURE.md §13.3), which is what a parent's
 * server answers to a question without recursion about a name it has delegated: NS records in
 * the authority section and their addresses in the additional one.
 */
@Timeout(30)
public class ReferralTest {

    /** A parent that answers every question with the same referral for hub.example.com. */
    public static DatagramSocket fakeParent() throws Exception {
        DatagramSocket s = new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        Thread.ofVirtual().start(() -> {
            byte[] buf = new byte[512];
            while (!s.isClosed()) {
                try {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    s.receive(p);
                    byte[] q = java.util.Arrays.copyOf(p.getData(), p.getLength());
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    out.write(q[0]);
                    out.write(q[1]);
                    out.write(0x80); // QR, no AA: a referral is not authoritative
                    out.write(0x00);
                    out.write(0); out.write(1); // qd
                    out.write(0); out.write(0); // an
                    out.write(0); out.write(2); // ns
                    out.write(0); out.write(2); // ar
                    int qEnd = 12;
                    while (q[qEnd] != 0) {
                        qEnd += 1 + (q[qEnd] & 0xff);
                    }
                    qEnd += 5;
                    out.write(q, 12, qEnd - 12);
                    for (String ns : List.of("ns1.hub.example.com", "ns2.hub.example.com")) {
                        rr(out, "hub.example.com", 2, DnsResponder.encodeName(ns));
                    }
                    rr(out, "ns1.hub.example.com", 1, new byte[] {(byte) 203, 0, 113, 1});
                    rr(out, "ns2.hub.example.com", 1, new byte[] {(byte) 203, 0, 113, 2});
                    byte[] r = out.toByteArray();
                    s.send(new DatagramPacket(r, r.length, p.getSocketAddress()));
                } catch (Exception e) {
                    return;
                }
            }
        });
        return s;
    }

    private static void rr(ByteArrayOutputStream out, String owner, int type, byte[] rdata) {
        out.writeBytes(DnsResponder.encodeName(owner));
        out.write(type >>> 8); out.write(type);
        out.write(0); out.write(1);
        out.write(0); out.write(0); out.write(0x0e); out.write(0x10); // ttl 3600
        out.write(rdata.length >>> 8); out.write(rdata.length);
        out.writeBytes(rdata);
    }

    @Test
    void theAdditionalSectionOfAReferralIsTheGlue() throws Exception {
        try (DatagramSocket parent = fakeParent()) {
            Map<String, String> glue = DnsQuery.referralGlue("127.0.0.1", parent.getLocalPort(), "ns1.hub.example.com", 2000);
            assertEquals(Map.of("ns1.hub.example.com", "203.0.113.1", "ns2.hub.example.com", "203.0.113.2"), glue);
        }
    }
}
