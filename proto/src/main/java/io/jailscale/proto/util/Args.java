package io.jailscale.proto.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Command-line parsing for both binaries: {@code --key value}, {@code --key=value}, boolean
 * {@code --flag}, and positional words. Repeated options keep the last value.
 */
public final class Args {

    private final Map<String, String> options = new LinkedHashMap<>();
    private final List<String> positional = new ArrayList<>();

    private Args() {}

    /** {@code flags} are options that take no value. */
    public static Args parse(String[] argv, String... flags) {
        Args a = new Args();
        List<String> flagList = List.of(flags);
        for (int i = 0; i < argv.length; i++) {
            String s = argv[i];
            if (s.equals("--")) {
                for (int j = i + 1; j < argv.length; j++) {
                    a.positional.add(argv[j]);
                }
                break;
            }
            if (s.startsWith("--")) {
                String key = s.substring(2);
                int eq = key.indexOf('=');
                if (eq >= 0) {
                    a.options.put(key.substring(0, eq), key.substring(eq + 1));
                } else if (flagList.contains(key) || i + 1 >= argv.length || argv[i + 1].startsWith("--")) {
                    // Declared flags, and any option followed by another option (or nothing), take no value.
                    a.options.put(key, "true");
                } else {
                    a.options.put(key, argv[++i]);
                }
            } else {
                a.positional.add(s);
            }
        }
        return a;
    }

    public String get(String key) {
        return options.get(key);
    }

    public String get(String key, String dflt) {
        return options.getOrDefault(key, dflt);
    }

    public String require(String key) {
        String v = options.get(key);
        if (v == null) {
            throw new IllegalArgumentException("--" + key + " is required");
        }
        return v;
    }

    public boolean flag(String key) {
        return "true".equals(options.get(key));
    }

    public boolean has(String key) {
        return options.containsKey(key);
    }

    public int integer(String key, int dflt) {
        String v = options.get(key);
        if (v == null) {
            return dflt;
        }
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("--" + key + " must be a number");
        }
    }

    /** Durations like {@code 90s}, {@code 10m}, {@code 24h}, {@code 7d}; plain numbers are seconds. */
    public long seconds(String key, long dflt) {
        String v = options.get(key);
        return v == null ? dflt : parseSeconds(v);
    }

    public static long parseSeconds(String v) {
        String s = v.trim();
        if (s.isEmpty()) {
            // `--ttl=` reaches here as "". Without this the parser leaves through charAt(-1), and a
            // StringIndexOutOfBoundsException is not an IllegalArgumentException: both binaries fall
            // past the handler that prints "error: ..." and exits 2.
            throw new IllegalArgumentException("bad duration " + v);
        }
        long mult = 1;
        char last = s.charAt(s.length() - 1);
        if (Character.isLetter(last)) {
            mult = switch (Character.toLowerCase(last)) {
                case 's' -> 1;
                case 'm' -> 60;
                case 'h' -> 3600;
                case 'd' -> 86400;
                default -> throw new IllegalArgumentException("bad duration " + v);
            };
            s = s.substring(0, s.length() - 1);
        }
        try {
            return Long.parseLong(s) * mult;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("bad duration " + v);
        }
    }

    public List<String> positional() {
        return positional;
    }

    public String positional(int i) {
        return i < positional.size() ? positional.get(i) : null;
    }
}
