package io.jailscale.hub.dns;

import io.jailscale.proto.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The tiny authoritative DNS server behind {@code _acme-challenge.<hub>} (ARCHITECTURE.md §7.1). It
 * answers TXT (the current challenge values), SOA and NS for that one name, and REFUSED for
 * everything else. UDP and TCP, no EDNS, no compression beyond a pointer to the question name.
 */
public final class DnsResponder implements AutoCloseable {

    private static final Log LOG = Log.get("dns");
    private static final int TYPE_NS = 2;
    private static final int TYPE_SOA = 6;
    private static final int TYPE_TXT = 16;
    private static final int TYPE_ANY = 255;
    private static final int TTL = 5;

    private final String zone;      // _acme-challenge.hub.example.com (lower case, no trailing dot)
    private final String hubName;   // hub.example.com, the NS and SOA mname
    private final List<String> txt = new CopyOnWriteArrayList<>();
    private DatagramSocket udp;
    private ServerSocket tcp;
    private volatile boolean running;

    public DnsResponder(String hubName) {
        this.hubName = hubName.toLowerCase(Locale.ROOT);
        this.zone = "_acme-challenge." + this.hubName;
    }

    public String zone() {
        return zone;
    }

    public void start(String bindHost, int port) throws IOException {
        InetSocketAddress addr = new InetSocketAddress(bindHost, port);
        udp = new DatagramSocket(null);
        udp.setReuseAddress(true);
        udp.bind(addr);
        tcp = new ServerSocket();
        tcp.setReuseAddress(true);
        tcp.bind(new InetSocketAddress(bindHost, udp.getLocalPort()), 16);
        running = true;
        Thread.ofPlatform().name("dns-udp").daemon(true).start(this::udpLoop);
        Thread.ofVirtual().name("dns-tcp").start(this::tcpLoop);
        LOG.info("answering TXT for {} on {}:{}", zone, bindHost, udp.getLocalPort());
    }

    public int port() {
        return udp.getLocalPort();
    }

    public void setTxt(List<String> values) {
        txt.clear();
        txt.addAll(values);
    }

    public void addTxt(String value) {
        txt.add(value);
    }

    public void clearTxt() {
        txt.clear();
    }

    public List<String> txt() {
        return new ArrayList<>(txt);
    }

    private void udpLoop() {
        byte[] buf = new byte[1024];
        while (running) {
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            try {
                udp.receive(p);
                byte[] q = java.util.Arrays.copyOf(p.getData(), p.getLength());
                byte[] r = respond(q);
                if (r != null) {
                    udp.send(new DatagramPacket(r, r.length, p.getSocketAddress()));
                }
            } catch (IOException e) {
                if (running) {
                    LOG.debug("udp: {}", e.getMessage());
                }
            }
        }
    }

    private void tcpLoop() {
        while (running) {
            try {
                Socket s = tcp.accept();
                Thread.ofVirtual().start(() -> serveTcp(s));
            } catch (IOException e) {
                if (running) {
                    LOG.debug("tcp: {}", e.getMessage());
                }
            }
        }
    }

    private void serveTcp(Socket s) {
        try (s) {
            s.setSoTimeout(5000);
            DataInputStream in = new DataInputStream(s.getInputStream());
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            int len = in.readUnsignedShort();
            if (len > 4096) {
                return;
            }
            byte[] q = new byte[len];
            in.readFully(q);
            byte[] r = respond(q);
            if (r != null) {
                out.writeShort(r.length);
                out.write(r);
                out.flush();
            }
        } catch (IOException ignored) {
            // client gone
        }
    }

    /** Builds a response for one query message, or null if it is not a query we can parse. */
    byte[] respond(byte[] q) {
        if (q.length < 12) {
            return null;
        }
        int flags = ((q[2] & 0xff) << 8) | (q[3] & 0xff);
        if ((flags & 0x8000) != 0) {
            return null; // a response, not a query
        }
        int qdcount = ((q[4] & 0xff) << 8) | (q[5] & 0xff);
        if (qdcount != 1) {
            return error(q, 1);
        }
        int p = 12;
        StringBuilder name = new StringBuilder();
        while (p < q.length) {
            int l = q[p++] & 0xff;
            if (l == 0) {
                break;
            }
            if ((l & 0xc0) != 0 || p + l > q.length) {
                return error(q, 1);
            }
            if (name.length() > 0) {
                name.append('.');
            }
            name.append(new String(q, p, l, StandardCharsets.US_ASCII));
            p += l;
        }
        if (p + 4 > q.length) {
            return error(q, 1);
        }
        int qtype = ((q[p] & 0xff) << 8) | (q[p + 1] & 0xff);
        int questionEnd = p + 4;
        String qname = name.toString().toLowerCase(Locale.ROOT);
        if (!qname.equals(zone)) {
            return error(q, 5); // REFUSED: not our zone
        }
        List<byte[]> answers = new ArrayList<>();
        if (qtype == TYPE_TXT || qtype == TYPE_ANY) {
            for (String v : txt) {
                answers.add(rr(TYPE_TXT, txtRdata(v)));
            }
        }
        if (qtype == TYPE_NS || qtype == TYPE_ANY) {
            answers.add(rr(TYPE_NS, encodeName(hubName)));
        }
        if (qtype == TYPE_SOA || qtype == TYPE_ANY || answers.isEmpty()) {
            byte[] soa = soaRdata();
            if (qtype == TYPE_SOA || qtype == TYPE_ANY) {
                answers.add(rr(TYPE_SOA, soa));
            } else {
                // NODATA: authority section carries the SOA
                return build(q, questionEnd, List.of(), List.of(rr(TYPE_SOA, soa)), 0);
            }
        }
        return build(q, questionEnd, answers, List.of(), 0);
    }

    private byte[] build(byte[] q, int questionEnd, List<byte[]> answers, List<byte[]> authority, int rcode) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(512);
        out.write(q[0]);
        out.write(q[1]);
        int flags = 0x8400 | (q[2] & 0x01) << 8 | rcode; // QR, AA, copy RD, rcode
        out.write(flags >>> 8);
        out.write(flags);
        out.write(0);
        out.write(1);
        out.write(answers.size() >>> 8);
        out.write(answers.size());
        out.write(authority.size() >>> 8);
        out.write(authority.size());
        out.write(0);
        out.write(0);
        out.write(q, 12, questionEnd - 12);
        for (byte[] a : answers) {
            out.writeBytes(a);
        }
        for (byte[] a : authority) {
            out.writeBytes(a);
        }
        return out.toByteArray();
    }

    private byte[] error(byte[] q, int rcode) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(12);
        out.write(q[0]);
        out.write(q[1]);
        int flags = 0x8000 | rcode;
        out.write(flags >>> 8);
        out.write(flags);
        for (int i = 0; i < 8; i++) {
            out.write(0);
        }
        return out.toByteArray();
    }

    /** A resource record whose name is a pointer to the question name (offset 12). */
    private static byte[] rr(int type, byte[] rdata) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(rdata.length + 12);
        out.write(0xc0);
        out.write(0x0c);
        out.write(type >>> 8);
        out.write(type);
        out.write(0);
        out.write(1); // IN
        out.write(0);
        out.write(0);
        out.write(TTL >>> 8);
        out.write(TTL);
        out.write(rdata.length >>> 8);
        out.write(rdata.length);
        out.writeBytes(rdata);
        return out.toByteArray();
    }

    private static byte[] txtRdata(String v) {
        byte[] b = v.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream out = new ByteArrayOutputStream(b.length + 2);
        for (int i = 0; i < b.length; i += 255) {
            int n = Math.min(255, b.length - i);
            out.write(n);
            out.write(b, i, n);
        }
        return out.toByteArray();
    }

    private byte[] soaRdata() {
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        out.writeBytes(encodeName(hubName));
        out.writeBytes(encodeName("hostmaster." + hubName));
        for (int v : new int[] {1, 300, 300, 604800, TTL}) { // serial, refresh, retry, expire, minimum
            out.write(v >>> 24);
            out.write(v >>> 16);
            out.write(v >>> 8);
            out.write(v);
        }
        return out.toByteArray();
    }

    static byte[] encodeName(String name) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(name.length() + 2);
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            out.write(b.length);
            out.writeBytes(b);
        }
        out.write(0);
        return out.toByteArray();
    }

    @Override
    public void close() {
        running = false;
        if (udp != null) {
            udp.close();
        }
        if (tcp != null) {
            try {
                tcp.close();
            } catch (IOException ignored) {
                // closing
            }
        }
    }
}
