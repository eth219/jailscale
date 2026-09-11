package io.jailscale.hub;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * What this process is costing, for the status page (ARCHITECTURE.md §14).
 *
 * <p>Resident set size is read from {@code /proc/self/status}, which exists on Linux and is where
 * a hub normally runs. Everywhere else it is not reported rather than guessed at: the JVM heap is
 * not RSS, and a native image's heap is a small part of what it occupies. Nothing here shells out.
 */
final class Resources {

    private static final Path PROC_STATUS = Path.of("/proc/self/status");
    private static final long STARTED = System.currentTimeMillis();

    private Resources() {
    }

    /** Resident set size in bytes, or -1 where the platform does not expose it cheaply. */
    static long rssBytes() {
        if (!Files.isReadable(PROC_STATUS)) {
            return -1;
        }
        try {
            for (String line : Files.readAllLines(PROC_STATUS, StandardCharsets.UTF_8)) {
                if (line.startsWith("VmRSS:")) {
                    String[] parts = line.split("\\s+");
                    return Long.parseLong(parts[1]) * 1024; // reported in kB
                }
            }
        } catch (IOException | RuntimeException e) {
            return -1;
        }
        return -1;
    }

    static long uptimeMillis() {
        return System.currentTimeMillis() - STARTED;
    }

    /** Heap in use. Under a native image this is a fraction of RSS, so it is labelled as heap. */
    static long heapUsedBytes() {
        Runtime r = Runtime.getRuntime();
        return r.totalMemory() - r.freeMemory();
    }

    /** "1.2 GB", "340 MB", "12 KB". Returns "n/a" for a negative value. */
    static String humanBytes(long bytes) {
        if (bytes < 0) {
            return "n/a";
        }
        if (bytes < 1024) {
            return bytes + " B";
        }
        String[] units = {"KB", "MB", "GB", "TB"};
        double v = bytes / 1024.0;
        int i = 0;
        while (v >= 1024 && i < units.length - 1) {
            v /= 1024;
            i++;
        }
        return (v >= 100 ? String.format("%.0f", v) : String.format("%.1f", v)) + " " + units[i];
    }

    /** "8d 3h", "3h 12m", "12m 5s", "9s". */
    static String humanDuration(long millis) {
        long s = Math.max(0, millis / 1000);
        long d = s / 86400;
        long h = (s % 86400) / 3600;
        long m = (s % 3600) / 60;
        if (d > 0) {
            return d + "d " + h + "h";
        }
        if (h > 0) {
            return h + "h " + m + "m";
        }
        if (m > 0) {
            return m + "m " + (s % 60) + "s";
        }
        return s + "s";
    }
}
