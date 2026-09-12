# Profiles

`hub.iprof.gz` and `node.iprof.gz` are profile-guided-optimization profiles for `jailhub` and
`jailscale`, collected on linux-amd64. They are **not** what the release builds against: releases
are plain builds on GraalVM CE 25.3 (ARCHITECTURE.md §3.2). These are here so that anyone who wants a
smaller, lighter binary than the release can have one in a single command.

```sh
./native.sh -DskipTests -Ppgo
```

That needs Oracle GraalVM for JDK 25 -- PGO is not in the Community Edition --
and `native.sh` will say so and tell you how to install it. Installing it means agreeing to the
[GraalVM Free Terms and Conditions](https://www.oracle.com/downloads/licenses/graal-free-license.html).
`native.sh` unpacks the `.gz` for you; `native-image` reads the plain `.iprof`, which is why the
unpacked files are git-ignored. They are JSON and compress about six to one, so a refresh costs the
repository about a megabyte rather than six.

## What they are worth, and why the release does not use them

These were measured against plain **Oracle GraalVM 25.0.4**, which is the toolchain that can use
them. That is not the toolchain the release ships, so the last column is the interesting comparison:

| | plain, Oracle 25.0.4 | with these profiles | plain, **what ships** (CE 25.3) |
|---|---|---|---|
| Binary, linux-amd64 | 31.8, 32.0 MiB | **21.9, 21.9** | 26.1, 26.2 |
| Idle RSS, linux-amd64 | 39.4, 38.6 MB | **32.4, 32.0** | 35.1, 34.4 |
| Warm requests a second, linux-amd64 | 8,419 | **19,169** | 13,700 to 17,600 |
| Warm requests a second, arm64 macOS | 34,563 | 28,976 | **37,800** |

Size and memory improve on every platform. CPU improves **only on the platform the profile was
collected on**: the same profiles on macOS cost 11% more CPU per handshake and 16% of the warm
request rate. Per-platform profiles were collected and measured too, and were no better. §14 has
the full numbers, including the finding that made the CPU figure untrustworthy as a release
argument: two builds from the identical recipe gave 1,756 and 2,094 µs of hub CPU per handshake,
with the measured runs inside each build within 1% of each other, so the same recipe does not
produce the same profile twice.

Against what actually ships, the honest summary is: **these buy about 4 MiB of binary and 3 MB of
idle RSS on linux-amd64, and nothing else.** The throughput the middle column shows is what the 25.3
line already gives for free, and on any platform other than linux-amd64 these profiles cost CPU
rather than saving it. Use them if a smaller, lighter linux binary is worth building yourself for;
they were not worth putting the GraalVM Free Terms and Conditions on every released binary.

## A profile from your own traffic

Better than this one, for your own build, because it profiles the work you actually do. Instrument,
run your own node or hub under its normal load for a while, then rebuild against what it dumped:

```sh
./native.sh -DskipTests -Ppgo-instrument
JAILSCALE_DAEMON_OPTS=-XX:ProfilesDumpFile=$PWD/mine.iprof ./node/target/jailscale up ...
# ... use it, then stop it cleanly so the profile is written ...
./native.sh -DskipTests -Ppgo -Dpgo.profile=$PWD/mine.iprof
```

An instrumented binary is slower and larger; do not serve anything you care about with it for long.

## Refreshing the committed ones

These were merged from three runs, which is deliberate: a single run's profile is what varies. The
profile must cover the *kinds* of work that matter -- one collected without the load phase, meaning
without visitors arriving, gave no handshake gain at all -- while the particular throughput shape
does not matter, since profiles from warm requests only, handshakes only, and both landed within 1%
of each other.

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
