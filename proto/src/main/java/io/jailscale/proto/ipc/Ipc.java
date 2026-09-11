package io.jailscale.proto.ipc;

import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonException;
import io.jailscale.proto.json.JsonObject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.function.Consumer;

/**
 * Local IPC between a CLI and its daemon (ARCHITECTURE.md §6.3, §9.4): AF_UNIX socket, one JSON
 * object per line. A request gets either one reply line, or a stream of lines ending with
 * {@code {"done":true,...}}. The socket file's permissions are the authorisation.
 */
public final class Ipc {

    private static final int MAX_LINE = 64 * 1024;

    private Ipc() {}

    /** Handles one request; may write several lines via {@code reply} and must end with a done line. */
    @FunctionalInterface
    public interface Handler {
        void handle(JsonObject request, Reply reply) throws Exception;
    }

    /** Writer for a handler's lines. */
    public interface Reply {
        void line(JsonObject obj) throws IOException;

        /** Progress line for streaming commands: {@code {"msg": "..."}}. */
        default void progress(String msg) throws IOException {
            line(JsonObject.builder().put("msg", msg).build());
        }

        /** Final line. */
        default void done(JsonObject.Builder b) throws IOException {
            line(b.put("done", true).build());
        }

        default void ok() throws IOException {
            done(JsonObject.builder().put("ok", true));
        }

        default void error(String message) throws IOException {
            done(JsonObject.builder().put("ok", false).put("error", message));
        }
    }

    /** Listens on {@code path}, replacing a stale socket file. Each connection gets a virtual thread. */
    public static Server serve(Path path, Handler handler) throws IOException {
        Files.createDirectories(path.getParent());
        Files.deleteIfExists(path);
        ServerSocketChannel ch = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        ch.bind(UnixDomainSocketAddress.of(path));
        try {
            Files.setPosixFilePermissions(path, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException e) {
            // Windows: the directory ACL (current user only) is the authorisation.
        }
        Server s = new Server(ch, path, handler);
        Thread.ofVirtual().name("ipc-accept").start(s::acceptLoop);
        return s;
    }

    public static final class Server implements AutoCloseable {
        private final ServerSocketChannel ch;
        private final Path path;
        private final Handler handler;
        private final Object fileKey;

        Server(ServerSocketChannel ch, Path path, Handler handler) {
            this.ch = ch;
            this.path = path;
            this.handler = handler;
            this.fileKey = fileKey(path);
        }

        private static Object fileKey(Path p) {
            try {
                return Files.readAttributes(p, java.nio.file.attribute.BasicFileAttributes.class).fileKey();
            } catch (IOException e) {
                return null;
            }
        }

        private void acceptLoop() {
            while (ch.isOpen()) {
                SocketChannel c;
                try {
                    c = ch.accept();
                } catch (IOException e) {
                    return;
                }
                Thread.ofVirtual().name("ipc-conn").start(() -> serveOne(c));
            }
        }

        private void serveOne(SocketChannel c) {
            try (c; BufferedReader in = new BufferedReader(new InputStreamReader(Channels.newInputStream(c), StandardCharsets.UTF_8))) {
                OutputStream out = Channels.newOutputStream(c);
                Reply reply = obj -> {
                    out.write(Json.writeUtf8(obj.asMap()));
                    out.write('\n');
                    out.flush();
                };
                String line;
                while ((line = readLine(in)) != null) {
                    JsonObject req;
                    try {
                        req = Json.parseObject(line);
                    } catch (JsonException e) {
                        reply.error("bad request: " + e.getMessage());
                        continue;
                    }
                    try {
                        handler.handle(req, reply);
                    } catch (Exception e) {
                        reply.error(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
                    }
                }
            } catch (IOException ignored) {
                // client went away
            }
        }

        /** Closes the listener and removes the socket file only if it is still ours (a successor may have rebound the path). */
        @Override
        public void close() throws IOException {
            ch.close();
            // Delete only what we can prove is still our file: during a hand-off (ARCHITECTURE.md §13)
            // the successor has already rebound this path, and unlinking its socket strands every
            // admin client. Windows reports no file key, so there we never delete -- harmless,
            // because serve() unlinks a stale socket before binding.
            Object now = fileKey(path);
            if (fileKey != null && fileKey.equals(now)) {
                Files.deleteIfExists(path);
            }
        }
    }

    /** Sends one request and returns its single reply (or the final done line of a stream). */
    public static JsonObject call(Path path, JsonObject request) throws IOException {
        JsonObject[] last = new JsonObject[1];
        stream(path, request, o -> last[0] = o);
        return last[0];
    }

    /** Sends one request and passes every reply line to {@code onLine} until the done line. */
    public static void stream(Path path, JsonObject request, Consumer<JsonObject> onLine) throws IOException {
        try (SocketChannel c = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            c.connect(UnixDomainSocketAddress.of(path));
            OutputStream out = Channels.newOutputStream(c);
            out.write(Json.writeUtf8(request.asMap()));
            out.write('\n');
            out.flush();
            BufferedReader in = new BufferedReader(new InputStreamReader(Channels.newInputStream(c), StandardCharsets.UTF_8));
            String line;
            while ((line = readLine(in)) != null) {
                JsonObject o = Json.parseObject(line);
                onLine.accept(o);
                if (o.optBool("done", false)) {
                    return;
                }
            }
            throw new IOException("daemon closed the connection");
        }
    }

    /** True if something answers on the socket. */
    public static boolean isAlive(Path path) {
        if (!Files.exists(path)) {
            return false;
        }
        try (SocketChannel c = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            c.connect(UnixDomainSocketAddress.of(path));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static String readLine(BufferedReader in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') {
                return sb.toString();
            }
            if (sb.length() >= MAX_LINE) {
                throw new IOException("ipc line too long");
            }
            sb.append((char) c);
        }
        return sb.length() == 0 ? null : sb.toString();
    }
}
