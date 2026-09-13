package io.jailscale.hub;

import io.jailscale.proto.mux.FlowBudget;
import io.jailscale.proto.mux.MuxSession;
import java.util.concurrent.atomic.LongAdder;

/**
 * What the hub has done since it started, for {@code /metrics} and {@code /v1/status}
 * (ARCHITECTURE.md §6.3). Counters only here; everything else the endpoints report is current state
 * read from the hub itself, which needs no counting.
 *
 * <p>Static, because a jailhub process runs one hub, and the alternative is threading an instance
 * through {@link Relay}'s copy loop for a pair of adds. {@link LongAdder} rather than an atomic:
 * these are written from every visitor thread at once and read once a scrape.
 *
 * <p><b>Nothing here names anything.</b> No link, no node, no address appears in a metric, so a
 * scrape says how much the hub is doing and never who is doing it -- unlike the page, which lists
 * the links, and unlike a trace, which would record each visit. Labels would be the easy way to
 * lose that, so there are none.
 */
final class Metrics {

    /** Visitor connections handed to a node. */
    static final LongAdder VISITORS = new LongAdder();
    /** Visitor connections dropped before that: no SNI, an unknown name, or a cap reached. */
    static final LongAdder VISITORS_REFUSED = new LongAdder();
    /** Signatures issued over the wildcard key, and requests refused by the four conditions (§9.2). */
    static final LongAdder SIGNATURES = new LongAdder();
    static final LongAdder SIGNATURES_REFUSED = new LongAdder();
    /** Control connections that completed the Noise handshake. */
    static final LongAdder NODE_SESSIONS = new LongAdder();
    /** Bytes copied between a visitor and a node, both directions. */
    static final LongAdder RELAY_BYTES = new LongAdder();

    private Metrics() {
    }

    /** The Prometheus text exposition format, which is plain text and needs nothing to produce. */
    static String prometheus(Hub hub) {
        StringBuilder b = new StringBuilder(1024);
        String binary = Build.executableSha256();
        b.append("# HELP jailhub_build_info The version and binary this process is running.\n")
            .append("# TYPE jailhub_build_info gauge\n")
            .append("jailhub_build_info{version=\"").append(label(Hub.version()))
            .append("\",binary=\"").append(binary == null ? "" : "sha256:" + binary).append("\"} 1\n");
        counter(b, "jailhub_visitors_total", "Visitor connections routed to a node.", VISITORS.sum());
        counter(b, "jailhub_visitors_refused_total",
            "Visitor connections dropped before routing: no SNI, unknown name, or a cap reached.", VISITORS_REFUSED.sum());
        counter(b, "jailhub_signatures_total", "Handshake signatures issued over the wildcard key.", SIGNATURES.sum());
        counter(b, "jailhub_signatures_refused_total", "Signature requests refused.", SIGNATURES_REFUSED.sum());
        counter(b, "jailhub_node_sessions_total", "Control connections that completed the handshake.", NODE_SESSIONS.sum());
        counter(b, "jailhub_relay_bytes_total", "Bytes copied between visitors and nodes.", RELAY_BYTES.sum());
        gauge(b, "jailhub_nodes_registered", "Nodes with a registration on this hub.", hub.store().nodes().size());
        gauge(b, "jailhub_nodes_online", "Nodes with a control connection right now.", hub.registry().size());
        gauge(b, "jailhub_links_open", "Links open right now.", hub.links().all().size());
        gauge(b, "jailhub_visitors_in_flight", "Visitors being relayed to a node right now.",
            hub.router().visitorsInFlight());
        gauge(b, "jailhub_uptime_seconds", "Seconds since this process started.", Resources.uptimeMillis() / 1000);
        // Where the time goes admitting a visitor (§6.3). The point of having all five is the
        // comparison: first_byte running ahead of peek+resolve+open+reply is time spent in no stage
        // at all -- scheduling, queueing or a pause -- which no single stage's timer can show.
        counter(b, "jailhub_visitor_admissions_total",
            "Visitors that reached their first relayed byte, the denominator for the sums below.",
            RelayStages.OBSERVED.sum());
        stage(b, "peek", "reading the ClientHello off the visitor's socket", RelayStages.PEEK);
        stage(b, "resolve", "finding which link and node serve the name", RelayStages.RESOLVE);
        stage(b, "open", "opening a mux stream on the node's session", RelayStages.OPEN);
        stage(b, "reply", "waiting for the node's first byte", RelayStages.REPLY);
        stage(b, "first_byte", "accept to the visitor's first byte, end to end", RelayStages.FIRST_BYTE);
        // The multiplexer's own three (§5.3). A frame waiting for the writer and a write that takes
        // seconds are different faults with the same symptom, and neither is visible from the stages
        // above: those stop at the hub's own edge.
        mux(b, "queue_wait", "waiting for the session writer to take a frame", MuxSession.QUEUE_WAIT);
        mux(b, "socket_write", "encrypting and writing one frame, where a congested peer shows",
            MuxSession.SOCKET_WRITE);
        mux(b, "open_dispatch", "handing a peer-opened stream to its listener", MuxSession.OPEN_DISPATCH);
        // The receive budget (§5.3). Queued against limit is the one to alert on: it reaching the
        // limit is the hub shedding visitor streams to stay alive, and reclaimed says how many.
        FlowBudget budget = hub.flowBudget();
        counter(b, "jailhub_streams_reclaimed_total",
            "Visitor streams reset because the receive budget was full.", budget.reclaimedStreams());
        gauge(b, "jailhub_receive_budget_bytes",
            "Bytes this hub allows to sit in multiplexer receive queues at once.", budget.limitBytes());
        gauge(b, "jailhub_receive_queued_bytes", "Bytes in multiplexer receive queues right now.",
            budget.usedBytes());
        gauge(b, "jailhub_receive_queued_peak_bytes",
            "The most that has sat in multiplexer receive queues since this process started.", budget.peakBytes());
        if (hub.tls().isLoaded()) {
            gauge(b, "jailhub_certificate_not_after_seconds", "When the wildcard certificate expires, unix time.",
                hub.tls().leaf().getNotAfter().getTime() / 1000);
        }
        long rss = Resources.rssBytes();
        if (rss >= 0) {
            gauge(b, "jailhub_resident_bytes", "Resident set size.", rss);
        }
        gauge(b, "jailhub_heap_used_bytes", "Heap in use, a fraction of resident size under a native image.",
            Resources.heapUsedBytes());
        return b.toString();
    }

    private static void mux(StringBuilder b, String name, String what, MuxSession.Timing t) {
        counter(b, "jailhub_mux_" + name + "_total", "Frames measured " + what + ".", t.observations());
        seconds(b, "jailhub_mux_" + name + "_seconds_total", "counter",
            "Total seconds " + what + ".", t.totalSeconds());
        seconds(b, "jailhub_mux_" + name + "_seconds_max", "gauge",
            "The longest single wait " + what + " since this process started.", t.maxSeconds());
    }

    /** A stage's total and high-water mark. Two label-free series, because no metric here has labels. */
    private static void stage(StringBuilder b, String name, String what, RelayStages.Stage s) {
        seconds(b, "jailhub_visitor_" + name + "_seconds_total", "counter",
            "Total seconds spent " + what + ", over jailhub_visitor_admissions_total.", s.totalSeconds());
        seconds(b, "jailhub_visitor_" + name + "_seconds_max", "gauge",
            "The longest single wait spent " + what + " since this process started.", s.maxSeconds());
    }

    private static void seconds(StringBuilder b, String name, String type, String help, double value) {
        b.append("# HELP ").append(name).append(' ').append(help).append("\n# TYPE ").append(name)
            .append(' ').append(type).append('\n').append(name).append(' ')
            .append(String.format(java.util.Locale.ROOT, "%.6f", value)).append('\n');
    }

    private static void counter(StringBuilder b, String name, String help, long value) {
        b.append("# HELP ").append(name).append(' ').append(help).append("\n# TYPE ").append(name)
            .append(" counter\n").append(name).append(' ').append(value).append('\n');
    }

    private static void gauge(StringBuilder b, String name, String help, long value) {
        b.append("# HELP ").append(name).append(' ').append(help).append("\n# TYPE ").append(name)
            .append(" gauge\n").append(name).append(' ').append(value).append('\n');
    }

    /** A label value cannot carry a backslash, a quote or a newline unescaped. */
    private static String label(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
