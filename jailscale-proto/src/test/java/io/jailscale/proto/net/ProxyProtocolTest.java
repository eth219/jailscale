package io.jailscale.proto.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class ProxyProtocolTest {

    private static InputStream in(byte[] b) {
        return new ByteArrayInputStream(b);
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    @Test
    void v1() throws Exception {
        InputStream s = in(ascii("PROXY TCP4 203.0.113.5 10.0.0.1 51234 443\r\n"));
        ProxyProtocol.Header h = ProxyProtocol.read(s);
        assertEquals("203.0.113.5", h.srcIp());
        assertEquals(51234, h.srcPort());
        assertEquals(443, h.dstPort());
        assertEquals(0x16, s.read()); // the TLS record follows untouched

        ProxyProtocol.Header v6 = ProxyProtocol.read(in(ascii("PROXY TCP6 2001:db8::1 ::1 1 2\r\n")));
        assertEquals("2001:db8:0:0:0:0:0:1", v6.srcIp());
        assertFalse(ProxyProtocol.read(in(ascii("PROXY UNKNOWN\r\n"))).known());

        assertThrows(IOException.class, () -> ProxyProtocol.read(in(ascii("PROXY TCP4 1.2.3.4 5.6.7.8 1\r\n"))));
        assertThrows(IOException.class, () -> ProxyProtocol.read(in(ascii("PROXY TCP4 1.2.3.4 5.6.7.8 1 99999\r\n"))));
        assertThrows(IOException.class, () -> ProxyProtocol.read(in(ascii("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n"))));
        assertThrows(IOException.class, () -> ProxyProtocol.read(in(ascii("GET / HTTP/1.1\r\n"))));
        assertThrows(IOException.class, () -> ProxyProtocol.read(in(ascii("PROXY TCP4 " + "1".repeat(120) + "\r\n"))));
    }

    @Test
    void v2() throws Exception {
        byte[] sig = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};
        byte[] v4 = new byte[16 + 12 + 1];
        System.arraycopy(sig, 0, v4, 0, 12);
        v4[12] = 0x21; // v2, PROXY
        v4[13] = 0x11; // AF_INET, STREAM
        v4[14] = 0;
        v4[15] = 12;
        System.arraycopy(new byte[] {(byte) 203, 0, 113, 5, 10, 0, 0, 1, (byte) 0xC8, 0x12, 0x01, (byte) 0xBB}, 0, v4, 16, 12);
        v4[28] = 0x16;
        InputStream s = in(v4);
        ProxyProtocol.Header h = ProxyProtocol.read(s);
        assertEquals("203.0.113.5", h.srcIp());
        assertEquals(0xC812, h.srcPort());
        assertEquals("10.0.0.1", h.dstIp());
        assertEquals(443, h.dstPort());
        assertEquals(0x16, s.read());

        byte[] local = new byte[16];
        System.arraycopy(sig, 0, local, 0, 12);
        local[12] = 0x20; // LOCAL (health check)
        assertFalse(ProxyProtocol.read(in(local)).known());

        byte[] v6 = new byte[16 + 36];
        System.arraycopy(sig, 0, v6, 0, 12);
        v6[12] = 0x21;
        v6[13] = 0x21; // AF_INET6
        v6[15] = 36;
        v6[16] = 0x20;
        v6[17] = 0x01;
        v6[18] = 0x0d;
        v6[19] = (byte) 0xb8;
        v6[31] = 1; // 2001:db8::1
        v6[47] = 1; // ::1
        v6[48] = 0;
        v6[49] = 80;
        v6[50] = 1;
        v6[51] = (byte) 0xbb;
        ProxyProtocol.Header h6 = ProxyProtocol.read(in(v6));
        assertEquals("2001:db8:0:0:0:0:0:1", h6.srcIp());
        assertEquals(80, h6.srcPort());

        byte[] badSig = v4.clone();
        badSig[5] = 1;
        assertThrows(IOException.class, () -> ProxyProtocol.read(in(badSig)));
    }

    @Test
    void cidr() throws Exception {
        List<Cidr> trusted = List.of(Cidr.parse("10.0.0.0/8"), Cidr.parse("192.168.1.7"), Cidr.parse("fd00::/8"));
        assertTrue(Cidr.anyContains(trusted, InetAddress.getByName("10.20.30.40")));
        assertTrue(Cidr.anyContains(trusted, InetAddress.getByName("192.168.1.7")));
        assertFalse(Cidr.anyContains(trusted, InetAddress.getByName("192.168.1.8")));
        assertTrue(Cidr.anyContains(trusted, InetAddress.getByName("fd12::1")));
        assertFalse(Cidr.anyContains(trusted, InetAddress.getByName("fe80::1")));
        assertTrue(Cidr.parse("172.16.0.0/12").contains(InetAddress.getByName("172.31.255.255")));
        assertFalse(Cidr.parse("172.16.0.0/12").contains(InetAddress.getByName("172.32.0.0")));
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("10.0.0.0/33"));
        assertEquals("PROXY TCP4 203.0.113.5 127.0.0.1 51234 3000\r\n", ProxyProtocol.v1Line("203.0.113.5", 51234, "127.0.0.1", 3000));
    }
}
