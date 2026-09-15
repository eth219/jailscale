package io.jailscale.hub;

import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * How much of the recent past this hub was up for, as a number (ARCHITECTURE.md §13.2).
 *
 * <p>A process cannot measure the time it was not running, so this keeps two kinds of record and
 * never adds them together. The first is the process's own: a timestamp rewritten to
 * {@code availability.json} once a minute, and on start the gap between the last stamp and now
 * counted as down. It counts a hub whose 443 is firewalled as up, and says so. The second is what
 * this hub saw of a peer: the intervals its hub-to-hub channel was down while this process was
 * running, which is reachability as a status page means the word.
 *
 * <p>Not the event log: 1,440 events a day would ride the fsync path and trip the snapshot cadence.
 * One small file, replaced atomically, is enough for a number that is read on a status page.
 */
final class Availability {

    private static final Log LOG = Log.get("availability");
    static final long STAMP_EVERY_MS = 60_000;
    /** Nothing older than the longest window is kept. */
    static final long KEEP_MS = 30L * 86_400_000;
    /** A peer that flaps could grow the list without bound; the oldest gaps go first. */
    static final int MAX_GAPS = 5_000;

    /** The windows the status page reports. */
    record Window(String label, long millis) {}

    static final List<Window> WINDOWS = List.of(
        new Window("24h", 86_400_000L),
        new Window("7d", 7 * 86_400_000L),
        new Window("30d", 30 * 86_400_000L));

    record Gap(long from, long to) {}

    private static final class Observed {
        final List<Gap> gaps = new ArrayList<>();
        long downSince; // 0 while up
    }

    private final Path file;
    private long since;
    private long lastStamp;
    private final List<Gap> selfGaps = new ArrayList<>();
    private final Map<String, Observed> peers = new LinkedHashMap<>();

    /** Loads the record and books the time since the last stamp as down. */
    Availability(Path stateDir, long now) throws IOException {
        this.file = stateDir.resolve("availability.json");
        init(now);
    }

    private synchronized void init(long now) throws IOException {
        if (Files.exists(file)) {
            try {
                load(Json.parseObject(Files.readString(file, StandardCharsets.UTF_8)));
            } catch (RuntimeException e) {
                LOG.warn("availability record unreadable, starting over: {}", e.getMessage());
                since = 0;
                lastStamp = 0;
                selfGaps.clear();
                peers.clear();
            }
        }
        if (since == 0) {
            since = now;
        }
        if (lastStamp > 0 && now > lastStamp) {
            selfGaps.add(new Gap(lastStamp, now));
        }
        // A peer that was down when this process last knew anything: that interval ends where the
        // knowledge ended, and a new one starts now, so peer gaps never overlap the process's own
        // and the two records stay separate quantities.
        for (Observed o : peers.values()) {
            if (o.downSince > 0) {
                if (lastStamp > o.downSince) {
                    o.gaps.add(new Gap(o.downSince, lastStamp));
                }
                o.downSince = now;
            }
        }
        lastStamp = now;
        prune(now);
        write();
    }

    /** Called once a minute: this process is still here. */
    synchronized void stamp(long now) {
        lastStamp = now;
        prune(now);
        write();
    }

    /** The peer named {@code name} is reachable from here as of {@code now}. */
    synchronized void peerUp(String name, long now) {
        Observed o = peers.computeIfAbsent(name, k -> new Observed());
        if (o.downSince > 0) {
            if (now > o.downSince) {
                o.gaps.add(new Gap(o.downSince, now));
            }
            o.downSince = 0;
        }
        write();
    }

    /** The peer named {@code name} stopped being reachable at {@code now}. Idempotent while down. */
    synchronized void peerDown(String name, long now) {
        Observed o = peers.computeIfAbsent(name, k -> new Observed());
        if (o.downSince == 0) {
            o.downSince = now;
            write();
        }
    }

    /** Starts the record over from {@code now}: no gaps, for this process or any peer, and {@code since} is now. */
    synchronized void reset(long now) {
        since = now;
        lastStamp = now;
        selfGaps.clear();
        for (Observed o : peers.values()) {
            o.gaps.clear();
            if (o.downSince > 0) {
                o.downSince = now;
            }
        }
        write();
    }

    /** When this record began; a window that reaches further back than this is reported over less. */
    synchronized long since() {
        return since;
    }

    synchronized List<String> peerNames() {
        return new ArrayList<>(peers.keySet());
    }

    /**
     * The fraction of the last {@code windowMillis} this process was running, or null when the
     * record is younger than a second and there is nothing to divide by.
     */
    synchronized Double processFraction(long windowMillis, long now) {
        long start = Math.max(now - windowMillis, since);
        long span = now - start;
        if (span <= 0) {
            return null;
        }
        return 1.0 - (double) overlap(selfGaps, start, now) / span;
    }

    /**
     * Milliseconds this process was down between {@code from} and {@code to}, or -1 when the
     * record does not reach back to {@code from} at all: a bucket before the record began is not
     * a bucket that was up, it is one nobody was counting.
     */
    synchronized long processDownBetween(long from, long to) {
        if (to <= since) {
            return -1;
        }
        return overlap(selfGaps, Math.max(from, since), to);
    }

    /**
     * Milliseconds the channel to {@code name} was down between {@code from} and {@code to},
     * while this process was running to see it; -1 when nothing was observed in that span.
     */
    synchronized long peerDownBetween(String name, long from, long to) {
        Observed o = peers.get(name);
        if (o == null || to <= since) {
            return -1;
        }
        long start = Math.max(from, since);
        if ((to - start) - overlap(selfGaps, start, to) <= 0) {
            return -1;
        }
        List<Gap> gaps = new ArrayList<>(o.gaps);
        if (o.downSince > 0 && to > o.downSince) {
            gaps.add(new Gap(o.downSince, to));
        }
        return overlap(gaps, start, to);
    }

    /**
     * The fraction of the last {@code windowMillis}, counting only the time this process was
     * running, during which {@code name} was reachable; null before anything has been observed.
     */
    synchronized Double peerFraction(String name, long windowMillis, long now) {
        Observed o = peers.get(name);
        if (o == null) {
            return null;
        }
        long start = Math.max(now - windowMillis, since);
        long observing = (now - start) - overlap(selfGaps, start, now);
        if (observing <= 0) {
            return null;
        }
        List<Gap> gaps = new ArrayList<>(o.gaps);
        if (o.downSince > 0 && now > o.downSince) {
            gaps.add(new Gap(o.downSince, now));
        }
        return Math.max(0.0, 1.0 - (double) overlap(gaps, start, now) / observing);
    }

    /** "100%", "99.98%", "97.2%": as many digits as the number has, and no more. */
    static String percent(Double fraction) {
        if (fraction == null) {
            return "n/a";
        }
        double p = fraction * 100;
        if (p >= 99.995) {
            return "100%";
        }
        if (p >= 99) {
            return String.format("%.2f%%", p);
        }
        return String.format("%.1f%%", p);
    }

    private static long overlap(List<Gap> gaps, long from, long to) {
        long total = 0;
        for (Gap g : gaps) {
            long a = Math.max(g.from(), from);
            long b = Math.min(g.to(), to);
            if (b > a) {
                total += b - a;
            }
        }
        return total;
    }

    private void prune(long now) {
        long horizon = now - KEEP_MS;
        prune(selfGaps, horizon);
        for (Observed o : peers.values()) {
            prune(o.gaps, horizon);
        }
        // A peer that has been down for the whole of the longest window is one that is not coming
        // back under that name: a standby that was relabelled (the primary on v0.1.3 named it by
        // hostname, v0.1.4 by address) or replaced. Left in, it would sit on the page at 0% for ever.
        peers.entrySet().removeIf(e -> e.getValue().downSince > 0 && e.getValue().downSince <= horizon
            && e.getValue().gaps.isEmpty());
    }

    private static void prune(List<Gap> gaps, long horizon) {
        gaps.removeIf(g -> g.to() <= horizon);
        for (int i = 0; i < gaps.size(); i++) {
            Gap g = gaps.get(i);
            if (g.from() < horizon) {
                gaps.set(i, new Gap(horizon, g.to()));
            }
        }
        while (gaps.size() > MAX_GAPS) {
            gaps.remove(0);
        }
    }

    private void load(JsonObject o) {
        since = o.has("since") ? o.lng("since") : 0;
        lastStamp = o.has("lastStamp") ? o.lng("lastStamp") : 0;
        if (o.has("gaps")) {
            readGaps(o.array("gaps"), selfGaps);
        }
        if (o.has("peers")) {
            JsonObject ps = o.object("peers");
            for (String name : ps.asMap().keySet()) {
                JsonObject p = ps.object(name);
                Observed ob = new Observed();
                if (p.has("gaps")) {
                    readGaps(p.array("gaps"), ob.gaps);
                }
                ob.downSince = p.has("downSince") ? p.lng("downSince") : 0;
                peers.put(name, ob);
            }
        }
    }

    private static void readGaps(List<Object> arr, List<Gap> into) {
        for (Object e : arr) {
            List<?> pair = (List<?>) e;
            long from = ((Number) pair.get(0)).longValue();
            long to = ((Number) pair.get(1)).longValue();
            if (to > from) {
                into.add(new Gap(from, to));
            }
        }
    }

    private void write() {
        JsonObject.Builder b = JsonObject.builder().put("since", since).put("lastStamp", lastStamp).put("gaps", gapList(selfGaps));
        JsonObject.Builder ps = JsonObject.builder();
        for (Map.Entry<String, Observed> e : peers.entrySet()) {
            JsonObject.Builder p = JsonObject.builder().put("gaps", gapList(e.getValue().gaps));
            if (e.getValue().downSince > 0) {
                p.put("downSince", e.getValue().downSince);
            }
            ps.put(e.getKey(), p.build());
        }
        b.put("peers", ps.build());
        Path tmp = file.resolveSibling("availability.json.tmp");
        try {
            Files.writeString(tmp, b.toJson(), StandardCharsets.UTF_8);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            LOG.warn("could not write availability record: {}", e.getMessage());
        }
    }

    private static List<Object> gapList(List<Gap> gaps) {
        List<Object> l = new ArrayList<>(gaps.size());
        for (Gap g : gaps) {
            l.add(List.of(g.from(), g.to()));
        }
        return l;
    }
}
