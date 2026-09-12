# Profiles

`hub.iprof.gz` and `node.iprof.gz` are the profile-guided-optimization profiles the release builds
against (`-Ppgo`, ARCHITECTURE.md §14). `native.sh` unpacks them; `native-image` reads the plain
`.iprof`, which is why the unpacked files are ignored by git.

They are JSON and compress about six to one, so a refresh costs the repository about a megabyte
rather than six.

## What they are worth

Every PGO build measured comes out about 7 MiB smaller with a fifth less idle RSS, on linux and
macOS alike. The CPU gain is less certain: four builds of the same source gave 1,225, 1,756, 2,094
and 2,244 µs of hub CPU per handshake against a plain 2,225 to 2,369, and two builds from the
identical recipe gave 1,756 and 2,094 -- so the same recipe does not produce the same profile twice.
§14 has the numbers.

## Refreshing them

These were collected on linux-amd64 and merged from three runs, which is deliberate: a single run's
profile is what varies. The profile must cover the *kinds* of work that matter -- one collected
without the load phase, meaning without visitors arriving, gave no handshake gain at all -- while
the particular throughput shape does not matter, since profiles from warm requests only, handshakes
only, and both landed within 1% of each other.

```sh
./mvnw -B -ntp -Pnative,pgo-instrument package -DskipTests

for r in 1 2 3; do
  HUB_OPTS=-XX:ProfilesDumpFile=/tmp/prof/hub-$r.iprof \
  JAILSCALE_DAEMON_OPTS=-XX:ProfilesDumpFile=/tmp/prof/node-$r.iprof \
    LOAD=500 RATE=8 RATE_HANDSHAKES=200 IDLE=5 ./measure.sh
done

# Merge: any native-image build that loads several profiles can dump the result.
for who in hub node; do
  native-image --pgo=/tmp/prof/$who-1.iprof,/tmp/prof/$who-2.iprof,/tmp/prof/$who-3.iprof \
    -H:PGODumpLoadedIprofPath=/tmp/prof/$who.iprof -o /tmp/m-$who SomeTinyClass
  gzip -9 -c /tmp/prof/$who.iprof > profiles/$who.iprof.gz
done
```

A profile from your own traffic is better than this one for your own build; see §14 for how to do
that with `-Ppgo-instrument` against a node you actually use.
