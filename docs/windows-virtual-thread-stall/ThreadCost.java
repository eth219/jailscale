import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;

/**
 * What one blocked thread per socket costs, with nothing else in the process: N loopback socket
 * pairs, then one thread per pair blocked in read(). The working set is sampled with the sockets
 * open but no threads yet, and again once every thread is parked, so the difference is the threads.
 *
 * Usage: ThreadCost <n> <platform|virtual> [stackKB]
 */
public final class ThreadCost {

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 1000;
        boolean platform = args.length > 1 && args[1].equals("platform");
        long stackKB = args.length > 2 ? Long.parseLong(args[2]) : 0;

        List<Socket> socks = new ArrayList<>();
        ServerSocket ss = new ServerSocket(0, 1024, InetAddress.getLoopbackAddress());
        for (int i = 0; i < n; i++) {
            socks.add(new Socket(InetAddress.getLoopbackAddress(), ss.getLocalPort()));
            socks.add(ss.accept());
        }
        System.gc();
        Thread.sleep(500);
        long before = rssKB();

        CountDownLatch parked = new CountDownLatch(n);
        for (int i = 0; i < n; i++) {
            InputStream in = socks.get(i * 2).getInputStream();
            Runnable body = () -> {
                parked.countDown();
                try {
                    in.read();
                } catch (IOException ignored) {
                    // the process is going away
                }
            };
            Thread.Builder b;
            if (platform) {
                Thread.Builder.OfPlatform p = Thread.ofPlatform().daemon(true);
                b = stackKB > 0 ? p.stackSize(stackKB * 1024) : p;
            } else {
                b = Thread.ofVirtual();
            }
            b.name("blocked-" + i).start(body);
        }
        parked.await();
        Thread.sleep(2000);
        System.gc();
        Thread.sleep(500);
        long after = rssKB();

        long heapKB = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024;
        System.out.println("THREADCOST kind=" + (platform ? "platform" : "virtual")
            + " stackKB=" + (stackKB > 0 ? stackKB : "default") + " n=" + n
            + " rssBeforeKB=" + before + " rssAfterKB=" + after + " deltaKB=" + (after - before)
            + " perThreadKB=" + String.format(Locale.ROOT, "%.1f", (after - before) / (double) n)
            + " heapUsedKB=" + heapKB);
    }

    private static long rssKB() throws Exception {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        long pid = ProcessHandle.current().pid();
        if (os.contains("win")) {
            Process p = new ProcessBuilder("powershell", "-NoProfile", "-Command",
                "(Get-Process -Id " + pid + ").WorkingSet64").start();
            return Long.parseLong(new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim()) / 1024;
        }
        if (os.contains("mac")) {
            Process p = new ProcessBuilder("ps", "-o", "rss=", "-p", String.valueOf(pid)).start();
            return Long.parseLong(new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim());
        }
        for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
            if (line.startsWith("VmRSS:")) {
                return Long.parseLong(line.replaceAll("[^0-9]", ""));
            }
        }
        return -1;
    }
}
