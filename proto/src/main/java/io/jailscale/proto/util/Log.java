package io.jailscale.proto.util;

import java.io.PrintStream;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * The whole logging framework (ARCHITECTURE.md §3.1): one line per event on stderr,
 * {@code HH:mm:ss.SSS LEVEL [tag] message}. Level is process-wide.
 */
public final class Log {

    public enum Level { DEBUG, INFO, WARN, ERROR }

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    private static volatile Level level = Level.INFO;
    private static volatile PrintStream out = System.err;

    private final String tag;

    private Log(String tag) {
        this.tag = tag;
    }

    public static Log get(String tag) {
        return new Log(tag);
    }

    public static void setLevel(Level l) {
        level = l;
    }

    public static void setOutput(PrintStream stream) {
        out = stream;
    }

    public void debug(String msg, Object... args) {
        log(Level.DEBUG, msg, args, null);
    }

    public void info(String msg, Object... args) {
        log(Level.INFO, msg, args, null);
    }

    public void warn(String msg, Object... args) {
        log(Level.WARN, msg, args, null);
    }

    public void warn(String msg, Throwable t) {
        log(Level.WARN, msg, new Object[0], t);
    }

    public void error(String msg, Object... args) {
        log(Level.ERROR, msg, args, null);
    }

    public void error(String msg, Throwable t) {
        log(Level.ERROR, msg, new Object[0], t);
    }

    private void log(Level l, String msg, Object[] args, Throwable t) {
        if (l.ordinal() < level.ordinal()) {
            return;
        }
        String text = args.length == 0 ? msg : format(msg, args);
        StringBuilder sb = new StringBuilder(128);
        sb.append(LocalTime.now().format(TIME)).append(' ').append(l).append(" [").append(tag).append("] ").append(text);
        if (t != null) {
            sb.append(": ").append(t.getClass().getSimpleName());
            if (t.getMessage() != null) {
                sb.append(": ").append(t.getMessage());
            }
        }
        out.println(sb);
        if (t != null && level == Level.DEBUG) {
            t.printStackTrace(out);
        }
    }

    /** {@code {}} placeholders, like SLF4J. */
    static String format(String msg, Object[] args) {
        StringBuilder sb = new StringBuilder(msg.length() + 32);
        int a = 0;
        int i = 0;
        while (i < msg.length()) {
            if (a < args.length && msg.startsWith("{}", i)) {
                sb.append(args[a++]);
                i += 2;
            } else {
                sb.append(msg.charAt(i++));
            }
        }
        return sb.toString();
    }
}
