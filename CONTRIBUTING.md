# Contributing

This is one person's project with a public hub behind it, so the useful thing to know first is what
it is trying to be: a tunnel with **zero third-party runtime dependencies**, four native targets, and
signed releases people install with `sudo install`. Those three constraints decide most answers here.

## Reporting a security problem

**Do not open a public issue with the details.** Use the **Report a vulnerability** button under
[Security](https://github.com/eth219/jailscale/security/advisories), which opens a private advisory
that only you and the maintainer can read.

This is one person's project. An honest expectation is a first reply within a few days and a fix in
the next release, not a published SLA; the releases that get fixes are the latest one and whatever
the live hub is running. #62 is open to write that down properly in a `SECURITY.md`.

Before reporting, check [ARCHITECTURE.md §15](docs/ARCHITECTURE.md): it lists what this project
cannot do, at length and on purpose. That a compromised hub can impersonate every name under its
domain is a stated property, not a finding.

## Filing an issue

Issues here are longer than most projects'. That is deliberate — the ones worth having say what the
problem costs, what the options are, and **what a measurement does not cover**, so that the next
person can act on it without rediscovering it. The templates ask for that shape.

Every issue carries three label axes: one **type**, one or more **areas**, exactly one **status**.
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

## Before a pull request

```sh
./mvnw package
./mvnw -Panalyze verify -DskipTests
```

**A green local build is not the gate.** CI runs the suite on ubuntu, macOS and Windows and SpotBugs
on its own, and two more jobs that **pull requests do not run**:

| Job | What it does | Run it yourself when your change touches |
|---|---|---|
| `budget` | `./native.sh -DskipTests && LOAD=1000 SLOW=1000 ./measure.sh --check` | the multiplexer, the relay, the visitor path, anything per-connection |
| `load` | `./mvnw -pl hub -am test -Dgroups=load -Dtest.excludedGroups=` | the hub's admission or fan-out |

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
- **An exclusion carries its reason.** `spotbugs-exclude.xml` is the precedent: an exclusion with no
  reason and a finding nobody answered look identical six months later.

Commits end with a `Co-Authored-By:` line when a tool wrote part of them. Much of this repository was
written that way and the history says so.
