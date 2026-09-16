package io.jailscale.node;

import io.jailscale.proto.json.JsonObject;

/**
 * What one self-probe of one name concluded, and when (ARCHITECTURE.md §11.3). Lives on the link
 * it describes rather than in a map of its own, so closing or losing the link drops it and a name
 * reopened later starts with no verdict instead of the last one's.
 */
record ProbeResult(String name, boolean ok, String verdict, long at) {

    /**
     * The verdict for a name this node is not serving through the hub right now -- closed, revoked
     * (§11.4), or not open on this hub session. Named because two places have to agree on it: the
     * one that decides it, and the exit status that does not count it.
     */
    static final String NOT_OPEN = "link not open";

    /**
     * Whether the check reached a conclusion about who terminated the TLS, which is the only thing
     * the exit status of {@code jailscale verify} is about.
     *
     * <p>False for exactly one verdict. `jailscale down` and then `jailscale verify` is an ordinary
     * pair of commands, and it left every name reporting a failed verification and the command
     * exiting 1 -- which for anything scripting §11.3 is the alarm for a compromised hub, raised by
     * a node being off. An unreachable name still counts: something was tried and did not answer.
     */
    boolean checked() {
        return !NOT_OPEN.equals(verdict);
    }

    JsonObject json() {
        return JsonObject.builder().put("name", name).put("ok", ok).put("verdict", verdict).put("at", at / 1000).build();
    }
}
