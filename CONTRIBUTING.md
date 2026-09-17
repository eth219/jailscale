# Contributing

This is one person's project with a public hub behind it, so the useful thing to know first is what
it is trying to be: a tunnel with **zero third-party runtime dependencies**, four native targets, and
signed releases people install with `sudo install`. Those three constraints decide most answers here.

## Reporting a security problem

**Not as a public issue.** [SECURITY.md](SECURITY.md) says where, what to expect, which versions get
fixes, and how to tell a finding from a limit ARCHITECTURE.md §15 already states.

## Filing an issue

Issues here are longer than most projects'. That is deliberate — the ones worth having say what the
problem costs, what the options are, and **what a measurement does not cover**, so that the next
person can act on it without rediscovering it. The templates ask for that shape.

Every issue carries three label axes: one **type**, one or more **areas**, exactly one **status**.
A pull request carries the type and area of the issue it closes, and no status.
[docs/issue-workflow.md](docs/issue-workflow.md) defines them, and also defines how a session says
it is working on something.

`status:parked` means open and deliberately not being worked on. It is not `wontfix` — parked issues
stay open so the same limitation is not rediscovered from the docs and filed again.

## Building

You need a JDK 25, and it must not be **25.0.0 to 25.0.2**: moving virtual-thread timed park onto
ForkJoinPool delayed tasks (JDK-8351927) makes cancelling a delayed task corrupt the scheduler heap,
which this project's hand-off path hits directly ([ARCHITECTURE.md §3.2](docs/ARCHITECTURE.md)).

```sh
./mvnw package                            # the JARs, and the tests
./mvnw -Panalyze verify -DskipTests       # SpotBugs
./mvnw -Pcoverage verify                  # a report, gated on nothing (§3.2 says why)
./native.sh -DskipTests                   # the native binaries, GraalVM CE 25.3
```

Building from source needs nothing but a JDK. That is why SpotBugs and JaCoCo live behind profiles:
they are the only third parties in the build, and keeping them off `package` is the point.

### Moving the JDK or GraalVM pin

A toolchain bump is not a version-number change here. Delegated signing works by **predicting the
bytes JSSE writes** for its ServerHello and EncryptedExtensions, because JSSE never shows them
([§9.2](docs/ARCHITECTURE.md)), and a JDK that writes the same handshake some other way takes every
hub-signed handshake down until the prediction is updated. It cannot forge anything — the hub
recomputes the hash itself — but it is an outage that arrives on somebody else's release schedule.
So before the pin moves, on the new toolchain:

```sh
./mvnw -pl node -am test -Dtest=TranscriptTest -Dsurefire.failIfNoSpecifiedTests=false
```

and paste the `Tests run:` line for `TranscriptTest` into the PR along with the build. **`BUILD
SUCCESS` is not the evidence.** `-Dsurefire.failIfNoSpecifiedTests=false` is load-bearing — `-am`
pulls in `crypto` and `proto`, which have no `TranscriptTest` and would otherwise fail the run — but
it suppresses the same error in `node` too, so a mistyped or renamed class prints `BUILD SUCCESS`
having run nothing at all, and a reviewer cannot tell that from a pass. The pins are `native.sh` and the
`graalvm/setup-graalvm` steps in `.github/workflows/{ci,images,release}.yml`, alongside the
`setup-java` steps that fix what the `test` job runs on; the JDK floor is the paragraph above.

**A green pull request does not do this for you.** `test` runs the suite on Liberica rather than on
the GraalVM pin, and `analyze` skips tests. The two jobs that do run the suite on the pin are
`budget`, which a pull request runs only when it carries the `ci:full` label, and `release`, which runs on a tag — so a reconstruction
this bump broke is found on main at the earliest and in a release at the latest. The run has to be
yours, and naming the build is what tells a reviewer it happened on the new toolchain and not the
old one. `TranscriptTest` is the whole safety net here, which is why its javadoc argues against
simplifying it away.

## Before a pull request

```sh
./mvnw package
./mvnw -Panalyze verify -DskipTests
tools/self-test.sh
```

**A green local build is not the gate.** CI runs the suite on ubuntu, macOS and Windows and SpotBugs
on its own, and two more jobs that **pull requests do not run** — and one axis no pull-request job
covers at all, because `test` runs on Liberica rather than on the pinned toolchain:

| Job | What it does | Run it yourself when your change touches |
|---|---|---|
| `budget` | `./native.sh -DskipTests && LOAD=1000 SLOW=1000 ./measure.sh --check` | the multiplexer, the relay, the visitor path, anything per-connection |
| `load` | `./mvnw -pl hub -am test -Dgroups=load -Dtest.excludedGroups=` | the hub's admission or fan-out |
| none, before `budget` on main | `./mvnw -pl node -am test -Dtest=TranscriptTest -Dsurefire.failIfNoSpecifiedTests=false` on the new toolchain, pasting the `Tests run:` line | the JDK or GraalVM pin — [Moving the JDK or GraalVM pin](#moving-the-jdk-or-graalvm-pin) says why, and why `BUILD SUCCESS` is not the evidence |

Say in the PR body which of those you ran. A PR that is silent about the budget is one a reviewer has
to assume was not measured.

## What a change should look like

- **English everywhere** — code, comments, docs, commit messages, CLI output.
- **A test that can fail in the direction it claims.** A suite asserting only the negative case
  passes just as well when the feature is dead. That is a real open issue here (#80).
- **A new dependency is a design change**, not an implementation detail, and needs its own argument.
- **A number in a document says where it came from**, on which platform, and what it does not cover.
  `docs/jsse-idle-cost/README.md` and `docs/name-starvation/README.md` are the precedent: each ends
  with a section on exactly that.
- **A change that makes a document untrue fixes the document.** The sentence being written is
  covered by the bullet above; the sentence that was already there and stops being right is not, and
  it is the one nobody is looking at. `ARCHITECTURE.md` §15 is where this costs the most — it is
  what `CLAUDE.md` points a reader at to find out what the system cannot do, and seven of its
  entries are limits that name the issue which would remove them (#63, #65, #70, #71, #72, #74,
  #75). Building one and leaving §15 stating it is how that document becomes fiction a paragraph at
  a time, and §14 is the same for a number. Nothing can check this — no test can tell that a
  sentence became false — which is why it is asked for at the pull request and not by CI.
- **A timing a test needs to move goes on the config record, not in a static and not in a new
  constructor parameter.** `HubConfig.Tuning` and `NodeConfig.Tuning` are where they live, both
  reachable with `withTuning(...)`. The two idioms this replaced are worth knowing, because both
  read as reasonable: a `static volatile` field set in a `@BeforeEach` is correct only for as long
  as surefire runs one test at a time, and a forgotten restore leaks into every later test in the
  JVM with nothing to say so; a constructor parameter per knob cost the node side three `Daemon`
  constructors for two knobs, and a third knob would have cost a fourth. A record costs neither, and it is the seam an
  operator-facing flag would need if one of these ever becomes one. #61 is the decision.
- **An exclusion carries its reason.** `spotbugs-exclude.xml` is the precedent: an exclusion with no
  reason and a finding nobody answered look identical six months later.

Commits end with a `Co-Authored-By:` line when a tool wrote part of them. Much of this repository was
written that way and the history says so.
