# Working on jailscale

A tunnel: a hub holds a wildcard certificate and routes by SNI, nodes dial out and relay to a local
port. Zero third-party runtime dependencies, four native targets, signed releases.
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) is the whole design; §15 is what it cannot do.

## This project is in maintenance

Since v0.2.0 (#274). That is a scope rule, not a mood:

- **Fixes and security work are in scope.** A defect in what is here, a test that cannot fail in
  the direction it claims, a dependency or toolchain that moved, a doc that says something untrue.
- **New features are not**, including bringing back one the cut removed — a second hub, raw TCP and
  UDP ports, user domains, the metrics endpoint, `service install`, the PROXY protocol. Each has a
  section in ARCHITECTURE.md saying what it was and what removing it costs, and a row in §1.3. If
  one is genuinely wanted again, that is a decision issue for the maintainer, not work to start.
- **Deleting is the cheapest change available here**, and it is still a change: it needs the same
  issue, the same tests-can-fail rule and the same commit message saying why it was worth doing.
- The three §1.2 rows are what is left of "decided, and not built". They stay decided; nothing says
  they are next.

## Before you start on an issue

Read [docs/issue-workflow.md](docs/issue-workflow.md). It is short and it is the procedure, not a
suggestion. The part that cannot be skipped:

- Work on `status:ready` (or `status:needs-measurement`, if you are taking the measurement), and
  **claim it first** — a `🤖 CLAIM` comment carrying a session name and a four-hour expiry, then
  the `status:claimed` label. Several sessions read this tracker at once and an agent session has
  no GitHub account, so the assignee field cannot do this job.
- Read the issue's comments before claiming. The label goes stale; the newest CLAIM is what is true.
- `needs:hardware` means what is left to close it is a machine. When it is one you have not got,
  walk past it — no claim, no comment — and say at the end which ones you skipped. The issue is
  still `status:ready`, because a person with the machine can start it. If the body says otherwise —
  a missing label, or a part you *can* reach — put the label right and say why; that is work, not a
  walk-past.
- A decision that is not yours to make (which approach, whether a cost is worth paying): leave the
  question on the issue, comment `🤖 RELEASE`, move it to `status:needs-decision`, and go do
  something else. Do not hold a claim while waiting.
- A different problem found along the way: file it with all three label axes, plus `needs:hardware`
  if what would close it is a machine, and link it both ways. Do not widen the change to cover it.
- A pull request carries the issue's type and area labels and no status. Several issues in one
  session with nobody between claim and merge is "Running the loop unattended" in the same doc,
  and it is open: a session is started with how many issues to take, and the rule for a red `main`
  is re-run once, revert on the second.

## Build and test

```sh
./mvnw package                            # the tests. JDK 25, but NOT 25.0.0-25.0.2 (§3.2)
./mvnw -Panalyze verify -DskipTests       # SpotBugs. Its own CI job, so it is easy to forget
tools/self-test.sh                        # the self-tests in tools/, and which scripts have none
./native.sh -DskipTests                   # the native binaries, GraalVM CE 25.3
LOAD=1000 SLOW=1000 ./measure.sh --check  # the §14 budget, against binaries native.sh just built.
                                          # Without LOAD and SLOW it skips the two axes that matter
```

## Five rules that were learned the expensive way

1. **English everywhere in the repository** — code, comments, docs, commit messages, CLI output,
   issues. Korean is for chat only.
2. **Build in a worktree.** Several sessions share this checkout. Never bare `git stash` — the stack
   is shared too; make a WIP commit instead.
3. **A green local build is not the CI gate.** CI adds SpotBugs and ubuntu/macOS/Windows, and two
   more jobs a pull request runs only if it asks, with the `ci:full` label (`load`, `budget`, in
   `ci-full.yml`). This has been mistaken for the
   gate twice.
4. **Measure against the native binaries.** A figure from the JVM is a figure about the JVM. The
   header of `measure.sh` lists the conclusions this harness has produced that were plausible and
   wrong; read it before believing a surprising number.
5. **A test has to be able to fail in the direction it claims.** A suite that only asserts the
   negative case passes just as well when the feature is dead — that was #80, the clipboard copy
   whose tests could only show it not happening, and the feature went before the test did.

## Where things are

| | |
|---|---|
| `hub/` `node/` `proto/` `crypto/` | the modules; `proto` is the wire, `crypto` the primitives |
| `docs/ARCHITECTURE.md` | the design. §14 characteristics, §15 limits |
| `docs/*/README.md` | the experiments and the design notes; a measurement says what it does **not** cover |
| `tools/` | release signing, the release index, verification |
| `measure.sh` `native.sh` | the budget harness and the release toolchain |

Commit messages say what changed and why it was worth changing. A commit a tool wrote part of ends
with a `Co-Authored-By:` trailer naming the model that wrote it — keep the one your harness
supplies rather than rewriting it.
