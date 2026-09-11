package io.jailscale.hub;

import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.util.Log;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.regex.Pattern;

/**
 * Plain HTTP on port 80 (ARCHITECTURE.md §8.3): answers {@code /.well-known/acme-challenge/<token>}
 * for user domains whose DNS points at the hub, redirects everything else to https.
 */
final class HttpChallengeFront implements AutoCloseable {

    private static final Log LOG = Log.get("http80");
    private static final String PREFIX = "/.well-known/acme-challenge/";
    private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9_-]{1,128}");
    private static final Pattern HOST = Pattern.compile("[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?");
    private static final int TIMEOUT_MS = 10_000;

    private final Hub hub;
    private final ServerSocket server;

    HttpChallengeFront(Hub hub, String host, int port) throws IOException {
        this.hub = hub;
        server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(host, port), 64);
        Thread.ofVirtual().name("http80-accept").start(this::accept);
        LOG.info("plain HTTP on {}:{} for acme-challenge relay", host, port());
    }

    int port() {
        return server.getLocalPort();
    }

    private void accept() {
        while (!server.isClosed()) {
            Socket s;
            try {
                s = server.accept();
            } catch (IOException e) {
                break;
            }
            Thread.ofVirtual().name("http80-" + s.getPort()).start(() -> serve(s));
        }
    }

    private void serve(Socket socket) {
        try (socket) {
            socket.setSoTimeout(TIMEOUT_MS);
            HttpRequest req;
            try {
                req = Http.readRequest(socket.getInputStream(), 0);
            } catch (HttpException e) {
                HttpResponse.text(e.status(), e.getMessage()).writeTo(socket.getOutputStream());
                return;
            } catch (EOFException e) {
                return;
            }
            route(req).writeTo(socket.getOutputStream());
        } catch (IOException e) {
            LOG.debug("http80: {}", e.getMessage());
        }
    }

    HttpResponse route(HttpRequest req) {
        String path = req.path();
        if (path.startsWith(PREFIX)) {
            String token = path.substring(PREFIX.length());
            String answer = TOKEN.matcher(token).matches() ? hub.challenges().answer(token) : null;
            return answer == null ? HttpResponse.text(404, "no such challenge") : HttpResponse.text(200, answer);
        }
        String host = req.headers().get("Host");
        if (host == null || !HOST.matcher(host).matches()) {
            host = hub.config().hostname();
        }
        return new HttpResponse(301).header("Location", "https://" + host + path);
    }

    @Override
    public void close() {
        try {
            server.close();
        } catch (IOException ignored) {
            // closing
        }
    }
}
