package io.jailscale.hub;

import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Tells systemd when the hub is actually serving (ARCHITECTURE.md §13). Under {@code Type=simple}
 * the unit is "active" as soon as the process exists, which on a first boot is minutes before there
 * is a certificate; under {@code Type=notify} it is active when this says so, and anything ordered
 * after the unit waits for the real thing.
 *
 * <p><b>Opt-in, and the reference unit does not take it.</b> {@code Hub.start} does not return until
 * a certificate is installed, and issuance retries for as long as it takes: one failed self-check is
 * 60 s and one validation is up to 120 s, so an ordinary first boot is already past systemd's
 * 90-second {@code TimeoutStartSec}. A unit that says {@code Type=notify} without also saying
 * {@code TimeoutStartSec=infinity} therefore kills the hub part-way through getting its first
 * certificate and, with {@code Restart=on-failure}, does it again forever. Turning a hub that would
 * have come up in three minutes into a restart loop is a poor trade for a better `systemctl status`,
 * so the switch belongs to operators who read what it costs.
 *
 * <p><b>Why a subprocess.</b> {@code NOTIFY_SOCKET} is an AF_UNIX <i>datagram</i> socket, and the
 * JDK does not open those: {@code DatagramChannel.open(StandardProtocolFamily.UNIX)} throws
 * {@code UnsupportedOperationException: Protocol family not supported} on 25. Writing the datagram
 * ourselves would mean a foreign-function call and its native-image configuration on five release
 * targets, to save one exec that happens once per process lifetime. The cost of the subprocess is
 * that the notification arrives from a child, so the unit needs {@code NotifyAccess=all}.
 *
 * <p>Nothing here fails the hub. A missing {@code systemd-notify} is a log line, because a hub that
 * refuses to serve over its own readiness reporting has the priority backwards.
 */
final class SystemdNotify {

    private static final Log LOG = Log.get("hub");
    private static final long TIMEOUT_SECONDS = 5;

    private SystemdNotify() {}

    /**
     * Whether systemd asked to be told. Blank counts as no: an empty {@code NOTIFY_SOCKET} is a
     * unit that does not want a notification, and running a subprocess to send one nowhere is a
     * confusing log line on every start.
     */
    static boolean asked(String notifySocket) {
        return notifySocket != null && !notifySocket.isBlank();
    }

    /** Says the hub is up, when systemd asked to be told. A no-op everywhere else. */
    static void ready() {
        if (!asked(System.getenv("NOTIFY_SOCKET"))) {
            return; // not under a Type=notify unit, which is the ordinary case
        }
        try {
            Process p = new ProcessBuilder("systemd-notify", "--ready")
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .start();
            if (!p.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                LOG.warn("systemd-notify did not finish in {}s; systemd will not see this hub as ready", TIMEOUT_SECONDS);
                return;
            }
            if (p.exitValue() != 0) {
                LOG.warn("systemd-notify exited {}; the unit needs NotifyAccess=all for a notification"
                    + " from a child process", p.exitValue());
                return;
            }
            LOG.info("told systemd this hub is ready");
        } catch (IOException e) {
            LOG.warn("could not run systemd-notify ({}), so systemd will wait out TimeoutStartSec"
                + " and call the unit failed. Use Type=simple if this hub has no systemd-notify.", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
