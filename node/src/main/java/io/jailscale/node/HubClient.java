package io.jailscale.node;

import io.jailscale.crypto.KeyText;
import io.jailscale.crypto.NoiseException;
import io.jailscale.crypto.NoiseIk;
import io.jailscale.crypto.X25519;
import io.jailscale.proto.control.Codec;
import io.jailscale.proto.control.CodecException;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.mux.NoiseChannel;
import io.jailscale.proto.tls.Tls;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/** The node's side of ARCHITECTURE.md §5: TLS to the hub, {@code /v1/key}, and the {@code /v1/noise} upgrade. */
final class HubClient {

    static final String UPGRADE_PROTOCOL = "jailscale-control-v1";
    static final byte[] PROLOGUE = "jailscale-control-v1".getBytes(StandardCharsets.US_ASCII);
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    static final int IDLE_TIMEOUT_MS = 60_000;

    private HubClient() {}

    record HubKeyInfo(String hubKey, String nextHubKey, Long notAfter) {}

    /** {@code GET /v1/key} over web-PKI TLS: the first-contact trust bootstrap (§5.2). */
    static HubKeyInfo fetchHubKey(String host, String addr, int port, SSLContext ctx, boolean verifyHostname) throws IOException {
        try (SSLSocket s = Tls.connect(ctx, host, addr, port, verifyHostname, CONNECT_TIMEOUT_MS)) {
            Http.writeRequest(s.getOutputStream(), "GET", host, "/v1/key", new Headers().add("Accept", "application/json"), null);
            HttpResponse r = Http.readResponse(s.getInputStream(), 64 * 1024);
            if (r.status() != 200) {
                throw new IOException("GET /v1/key returned " + r.status());
            }
            JsonObject o = Json.parseObject(r.bodyText());
            KeyText.parse(KeyText.HUB, o.string("hubKey")); // validate shape
            return new HubKeyInfo(o.string("hubKey"), o.optString("nextHubKey", null), o.optLong("notAfter"));
        } catch (HttpException e) {
            throw new IOException("bad response from hub: " + e.getMessage(), e);
        }
    }

    /** An established control connection. */
    record Connected(SSLSocket socket, NoiseChannel channel, Message.HelloResponse hello, String usedHubKey) {}

    /** The hub turned this node away during the handshake, with its reason and any explanation. */
    static final class Rejected extends IOException {
        private static final long serialVersionUID = 1L;
        private final transient String reason;

        Rejected(String reason, String detail) {
            super(detail != null ? detail : "hub rejected us: " + reason);
            this.reason = reason;
        }

        String reason() {
            return reason;
        }
    }

    /**
     * Opens TLS, upgrades, and runs the Noise handshake with Hello in message 1. Tries each
     * pinned hub key in order (current, then next during a rotation).
     */
    static Connected connect(String host, String addr, int port, SSLContext ctx, boolean verifyHostname, X25519.Keypair machineKey,
        List<String> hubKeys, Message.Hello hello) throws IOException, NoiseException {
        IOException lastIo = null;
        NoiseException lastNoise = null;
        for (String hk : hubKeys) {
            SSLSocket s = Tls.connect(ctx, host, addr, port, verifyHostname, CONNECT_TIMEOUT_MS);
            try {
                Http.writeRequest(s.getOutputStream(), "POST", host, "/v1/noise",
                    new Headers().add("Connection", "Upgrade").add("Upgrade", UPGRADE_PROTOCOL), new byte[0]);
                HttpResponse r = Http.readResponse(s.getInputStream(), 4096);
                if (r.status() != 101) {
                    throw new IOException("hub refused upgrade: HTTP " + r.status() + " " + r.bodyText().strip());
                }
                NoiseIk hs = NoiseIk.initiator(PROLOGUE, machineKey, KeyText.parse(KeyText.HUB, hk));
                byte[][] payload2 = new byte[1][];
                NoiseChannel ch = initiate(s, hs, Codec.encode(hello), payload2);
                Message m = Codec.decode(payload2[0]);
                if (m instanceof Message.Goodbye g) {
                    ch.close();
                    // A rejection at this point never reaches the session loop, so whatever the
                    // hub took the trouble to explain has to be carried out from here.
                    throw new Rejected(g.reason(), g.detail());
                }
                if (!(m instanceof Message.HelloResponse hr)) {
                    ch.close();
                    throw new IOException("expected HelloResponse, got " + m.type());
                }
                s.setSoTimeout(IDLE_TIMEOUT_MS);
                return new Connected(s, ch, hr, hk);
            } catch (NoiseException e) {
                lastNoise = e; // wrong hub key for this candidate; try the next one
                s.close();
            } catch (java.io.EOFException e) {
                // The hub cannot answer a handshake it failed to decrypt; it just closes. Treat
                // that like a wrong key and try the next candidate (rotation, ARCHITECTURE.md §5.2).
                lastNoise = new NoiseException("hub closed the connection during the handshake (wrong hub key?)");
                s.close();
            } catch (IllegalArgumentException e) {
                s.close();
                throw new NoiseException("invalid hub key: " + e.getMessage(), e);
            } catch (HttpException | CodecException e) {
                s.close();
                throw new IOException("bad response from hub: " + e.getMessage(), e);
            } catch (IOException e) {
                s.close();
                lastIo = e;
                break;
            }
        }
        if (lastIo != null) {
            throw lastIo;
        }
        throw lastNoise != null ? lastNoise : new NoiseException("no hub key to try");
    }

    private static NoiseChannel initiate(SSLSocket s, NoiseIk hs, byte[] payload1, byte[][] payload2Out)
        throws IOException, NoiseException {
        return NoiseChannel.initiate(s.getInputStream(), s.getOutputStream(), hs, payload1, payload2Out);
    }

    static SSLContext clientContext(NodeState st) throws IOException, GeneralSecurityException {
        return Tls.clientContext(st.caFile == null ? null : Path.of(st.caFile), st.tlsInsecure);
    }
}
