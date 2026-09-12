package io.jailscale.node;

import io.jailscale.proto.json.JsonObject;

/**
 * What one self-probe of one name concluded, and when (ARCHITECTURE.md §11.3). Lives on the link
 * it describes rather than in a map of its own, so closing or losing the link drops it and a name
 * reopened later starts with no verdict instead of the last one's.
 */
record ProbeResult(String name, boolean ok, String verdict, long at) {

    JsonObject json() {
        return JsonObject.builder().put("name", name).put("ok", ok).put("verdict", verdict).put("at", at / 1000).build();
    }
}
