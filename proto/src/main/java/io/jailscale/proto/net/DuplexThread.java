package io.jailscale.proto.net;

import java.util.Locale;

/**
 * Starts the thread that will sit on one direction of a socket while another thread uses the other
 * direction: on Windows a platform thread, everywhere else a virtual one.
 *
 * <p>Windows cannot poll one socket for read and for write at the same time. The JDK gives virtual
 * threads two wepoll handles, one for read readiness and one for write readiness, and parks a
 * thread by adding its socket to the matching handle ({@code sun.nio.ch.WEPollPoller}). When the
 * same socket sits in both, the AFD driver underneath wepoll hands a completion to the wrong one:
 * the read handle is woken for a write event, the write event is never reported to the handle that
 * asked for it, and the thread waiting on it sleeps for good. It is
 * <a href="https://bugs.openjdk.org/browse/JDK-8334574">JDK-8334574</a>, open since 2024 and still
 * open in 26, and upstream in <a href="https://github.com/piscisaureus/wepoll/issues/35">wepoll#35</a>,
 * where the analysis ends at "if we never poll the same socket handle from 2 distinct epoll handles
 * at the same time, the problem doesn't reproduce".
 *
 * <p>So we never do. A platform thread blocks in the OS and enters no poller at all, so putting one
 * side of every concurrently-used socket on one leaves at most a single handle holding that socket
 * and takes the pair the bug needs away. One thread per such socket, on Windows only; every other
 * thread in jailscale stays virtual, and on Linux and macOS nothing changes at all.
 *
 * <p>docs/windows-virtual-thread-stall has the measurements, including which variants stall.
 */
public final class DuplexThread {

    /** Windows is the only platform whose poller has this defect; the check is the JDK's own. */
    private static final boolean PLATFORM_THREADS =
        System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");

    private DuplexThread() {}

    /** True where this one side has to run on a platform thread. */
    public static boolean needed() {
        return PLATFORM_THREADS;
    }

    /** Starts {@code body} on the thread kind this platform can poll. Daemon either way. */
    public static Thread start(String name, Runnable body) {
        Thread.Builder b = PLATFORM_THREADS ? Thread.ofPlatform().daemon(true) : Thread.ofVirtual();
        return b.name(name).start(body);
    }
}
