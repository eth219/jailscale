package io.jailscale.hub;

import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Which of the two hubs this one is, and how many promotions it has seen (ARCHITECTURE.md §13.5).
 *
 * <p>Kept in {@code role} in the state directory rather than derived from the command line, so
 * that both hosts can carry the same unit -- each naming the other with {@code --peer} -- and the
 * one that was promoted stays the primary across a restart while the one that came back stands
 * down. The epoch rises by one on every promotion; two primaries that meet compare epochs, and the
 * lower one becomes the standby of the higher. A hub that has no file yet takes the rule from
 * before the file existed: a peer named means standby, none means primary.
 */
final class Role {

    private static final Log LOG = Log.get("role");
    static final String PRIMARY = "primary";
    static final String STANDBY = "standby";

    private final Path file;
    private String role;
    private long epoch;

    Role(Path stateDir, boolean peerNamed) throws IOException {
        this.file = stateDir.resolve("role");
        if (Files.exists(file)) {
            JsonObject o = Json.parseObject(Files.readString(file, StandardCharsets.UTF_8));
            role = o.string("role");
            epoch = o.lng("epoch");
            if (!PRIMARY.equals(role) && !STANDBY.equals(role)) {
                throw new IOException(file + " says role " + role + ", which is neither primary nor standby");
            }
        } else {
            role = peerNamed ? STANDBY : PRIMARY;
            epoch = peerNamed ? 0 : 1;
            write();
        }
    }

    synchronized boolean isPrimary() {
        return PRIMARY.equals(role);
    }

    synchronized String name() {
        return role;
    }

    synchronized long epoch() {
        return epoch;
    }

    /** Becomes the primary at the next epoch. */
    synchronized void promote() throws IOException {
        role = PRIMARY;
        epoch = epoch + 1;
        write();
        LOG.info("role: primary, epoch {}", epoch);
    }

    /** Stands down before a primary at {@code theirs}; the epoch follows so a later promotion here outranks it. */
    synchronized void demote(long theirs) throws IOException {
        role = STANDBY;
        epoch = Math.max(epoch, theirs);
        write();
        LOG.info("role: standby, epoch {}", epoch);
    }

    /**
     * Whether a primary at {@code theirEpoch} with {@code theirAddress} outranks this one: a
     * higher epoch does, and on a tie the lower address, so both sides decide the same way.
     */
    synchronized boolean outrankedBy(long theirEpoch, String theirAddress, String ourAddress) {
        if (theirEpoch != epoch) {
            return theirEpoch > epoch;
        }
        if (theirAddress == null || ourAddress == null) {
            return false;
        }
        return theirAddress.compareTo(ourAddress) < 0;
    }

    private synchronized void write() throws IOException {
        Path tmp = file.resolveSibling("role.tmp");
        Files.writeString(tmp, JsonObject.builder().put("role", role).put("epoch", epoch).toJson(), StandardCharsets.UTF_8);
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
