package io.jailscale.proto.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/** IPv4/IPv6 prefix matching for {@code --trusted-proxy} (ARCHITECTURE.md §8.5). */
public final class Cidr {

    private final byte[] network;
    private final int bits;

    private Cidr(byte[] network, int bits) {
        this.network = network;
        this.bits = bits;
    }

    /** {@code 10.0.0.0/8}, {@code fd00::/8}, or a bare address (a /32 or /128). */
    public static Cidr parse(String s) {
        String addr = s;
        int bits = -1;
        int slash = s.indexOf('/');
        if (slash >= 0) {
            addr = s.substring(0, slash);
            bits = Integer.parseInt(s.substring(slash + 1));
        }
        byte[] net;
        try {
            net = InetAddress.getByName(addr).getAddress();
        } catch (UnknownHostException _) {
            throw new IllegalArgumentException("bad CIDR " + s);
        }
        if (bits < 0) {
            bits = net.length * 8;
        }
        if (bits > net.length * 8) {
            throw new IllegalArgumentException("bad prefix length in " + s);
        }
        return new Cidr(net, bits);
    }

    public boolean contains(InetAddress a) {
        byte[] b = a.getAddress();
        if (b.length != network.length) {
            return false;
        }
        int full = bits / 8;
        for (int i = 0; i < full; i++) {
            if (b[i] != network[i]) {
                return false;
            }
        }
        int rem = bits % 8;
        if (rem == 0) {
            return true;
        }
        int mask = 0xff << (8 - rem);
        return (b[full] & mask) == (network[full] & mask);
    }

    public static boolean anyContains(List<Cidr> list, InetAddress a) {
        return list.stream().anyMatch(c -> c.contains(a));
    }
}
