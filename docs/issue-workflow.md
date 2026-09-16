# Labels, and how a session says it is working on something

Several sessions — people and agents — read this tracker at once, and more than one of them shares
a checkout ([§3.2](ARCHITECTURE.md) is not where that is written down; it is a fact of how this
project is worked on). Two of them starting the same issue costs a wasted branch and a merge
nobody wanted. GitHub's own answer is the assignee field, which needs a GitHub account per worker,
and an agent session does not have one. So the claim is a comment, plus a label that indexes it.

## The three axes

An issue carries **one type**, **one or more areas**, and — while it is open — **exactly one
status**. A closed issue carries none: the status axis says where something is in the process,
and a closed issue is not in it. Step 8 is where that comes off.

A pull request carries the **type and area of the issue it closes** — copied at
`gh pr create --label` — and no status. Its own state is its status: draft, open, checks, merged.
The issue it closes already carries `status:in-review`, and a second copy of that on the pull
request is a second thing to go stale, which is what step 8 is about. The one exception is
`status:needs-decision`, which a pull request carries only while a question raised after it was
opened is waiting on a person; step 7 says when.

**Type** — what kind of work it is. `bug`, `enhancement`, `documentation`, `question`, plus:

| Label | Means |
|---|---|
| `test-gap` | The code path exists and nothing verifies it. Not a defect; a defect nobody would notice. |
| `risk` | Something outside this repository can break it without warning — a JDK change, an upstream bug, a CA. |
| `security` | Touches the trust boundary, the keys, or a control that defends one. Sits alongside a type rather than replacing it. |

**Area** — where in the system. `area:hub`, `area:node`, `area:cli`, `area:proto`, `area:tls`,
`area:dns`, `area:ha`, `area:release`, `area:build`, `area:platform`. More than one is normal:
delegated signing is `area:tls` and `area:node` both.

**Status** — where it is in the process. One at a time, and moving it is how work is announced.

| Label | Means | Who may start work |
|---|---|---|
| `status:triage` | Filed, not classified yet | Nobody — classify it first |
| `status:needs-decision` | The *approach* is a choice a person has to make | Nobody — answer the question in the issue |
| `status:needs-measurement` | A number has to exist before the approach can be chosen or sized | Whoever takes the measurement |
| `status:ready` | Scoped well enough to start without asking | Anyone, by claiming it |
| `status:claimed` | A session is on it **now** | Only the claimant |
| `status:in-review` | A pull request is open and linked | Only the claimant |
| `status:blocked` | Waiting on another issue, or on something outside this repository | Nobody |
| `status:parked` | Open, and deliberately not being worked on | Nobody, until it is moved back |

`status:parked` is not `wontfix`. Parked issues stay open because the alternative is that the
same limitation is rediscovered from the docs every few months and filed again.

## Claiming

A claim is a comment, and a label that indexes it. The comment is what is true; the
`status:claimed` label, replacing whatever status was there, is what lets
`gh issue list --label status:claimed` find it without reading every thread. Post the comment
first: it carries its own expiry, so a session that dies between the two steps leaves something
that expires rather than a bare label. The comment is in exactly this form, so it can be found by
grep and read by a machine:

```
🤖 CLAIM
session: <a name that identifies this session>
branch: <the branch or worktree the work is on>
started: <ISO-8601 UTC>
expires: <ISO-8601 UTC, started + 4h>
```

```sh
fmt=%Y-%m-%dT%H:%M:%SZ
expires=$(date -u -d '+4 hours' +$fmt 2>/dev/null || date -u -v+4H +$fmt)   # GNU date, then BSD
gh issue comment 42 --body "$(printf '🤖 CLAIM\nsession: %s\nbranch: %s\nstarted: %s\nexpires: %s\n' \
  "<session name>" "$(git branch --show-current)" "$(date -u +$fmt)" "$expires")"
gh issue edit 42 --add-label status:claimed --remove-label \
  "$(gh issue view 42 --json labels --jq '[.labels[].name | select(startswith("status:"))] | join(",")')"
```

The `expires` line must not be empty — check the comment after posting. `date -v` is BSD-only and
`date -d` is GNU-only, which is why the snippet tries both. The last line removes whatever status
the issue carried, not a guessed one, so claiming a `status:needs-measurement` issue leaves one
status and not two. `git branch --show-current` prints nothing on a detached HEAD; write the
worktree path in that case.

**Read the comments before you claim.** The label can be stale; the newest CLAIM comment is what
is true.

**The expiry is the point.** A session dies without cleaning up — a window closed, a context
exhausted, a machine asleep — and a claim with no expiry is a permanent lock held by nobody. Four
hours is long enough for real work and short enough that a dead session does not hold an issue
overnight. Renew by posting a fresh CLAIM from the same `session:`; that is a renewal, not a
takeover, and needs no TAKEOVER block. There is no other renewal.

## Releasing, and taking over

Finished, or a pull request is open: move to `status:in-review` and link the PR. The PR closing
the issue is what ends the claim, so no comment is needed.

Giving up, for any reason: comment `🤖 RELEASE` with one line on how far you got and, if a
question stopped you, the question. Then set the status to what is true now — `status:ready` if
the work can simply continue, `status:needs-decision` if it found a choice, `status:blocked` if it
found a wall. Every later step that says "release" means exactly this.

Taking over an expired claim: check that `expires` has passed. An open PR linking the issue means
the claimant skipped step 7 — move it to `status:in-review` instead of taking over. Otherwise
comment

```
🤖 TAKEOVER
superseding: <the started: value of the claim you are replacing>
```

followed by your own CLAIM block. Naming what you superseded is what makes a mistaken takeover
visible afterwards rather than silent.

## Filing one

`.github/ISSUE_TEMPLATE/` has four forms — defect, verification gap, work, decision — and each sets
its own type label and a starting status. They ask for the shape the issues here already have: what
it costs, what was considered and rejected, and what a measurement does **not** cover.

**`gh issue create` bypasses them entirely**, which is how most issues here are filed. So a session
filing one is responsible for the three axes itself:

```sh
gh issue create --title "..." --body-file /tmp/issue.md \
  --label bug --label area:node --label status:needs-measurement
```

An issue filed with no status is invisible to everything above. `status:triage` is the honest one
when you do not yet know.

## The loop

One issue, start to finish. Each step says what it is protecting, because a step whose reason is
not written down is a step somebody skips the first time it is inconvenient.

### 1. Pick

`status:ready`, or `status:needs-measurement` when you are the one taking the measurement.
`status:needs-decision` is not ready by definition, `status:blocked` and `status:parked` are waiting
on something that is not you, and `status:triage` has not been classified yet — classifying it is
itself a small piece of work, and a worthwhile one.

### 2. Claim

The comment and then the label, as above — and the existing comments first.

### 3. Work, and not in the shared checkout

Several sessions edit the same clone. Build in a worktree of your own so that a `package` run does
not compile someone else's half-finished edit, and so that a failure is yours.

Stay inside the issue. The scope in the issue is the deliverable; a change that grows past it is
harder to review, harder to revert, and it is the shape a PR gets stuck in.

A document the change makes untrue is inside the issue, not past it. Fixing behaviour that
`ARCHITECTURE.md` §15 lists as a limit, or moving a number §14 states, leaves that section
asserting something this branch just falsified — and §15 is what `CLAUDE.md` points a reader at
to find out what the system cannot do. CONTRIBUTING.md's "What a change should look like" says the
same thing from the other end, and the pull request template asks which sentence you checked.

### 4. When a decision turns up that is not yours to make

Some things are not the session's call: which of three approaches, whether a control is worth its
cost, whether a limit is accepted. **Do not guess and do not hold the issue.**

Leave the question on the issue in the form the reader needs — what the options are, what each
costs, what tips it — and release to `status:needs-decision`. Then go and do something else.

Holding `status:claimed` while waiting looks like progress and is not: the decision may take days,
the claim expires in four hours, and in between the issue is neither being worked on nor available.
Releasing costs re-reading the issue later; holding costs everyone else.

### 5. When work uncovers a different problem

File it. Title, the three axes, and a link both ways. An observation that stays in a branch is an
observation nobody else has.

Then choose, honestly:

- **It does not block this issue.** File it, link it, keep going. Widening the change to cover it is
  the most common way a small PR becomes unreviewable.
- **It blocks this issue.** Link the new one and release to `status:blocked`. The new issue is now
  the work.

### 6. The gate, before any pull request

In this order, and the order matters — a review of code that does not compile wastes the review.

```sh
./mvnw package                            # the tests, on this platform
./mvnw -Panalyze verify -DskipTests       # SpotBugs; its own job in CI, so it is easy to forget
```

Then `/code-review`, and answer what it finds. "Answer" includes deciding a finding is wrong and
saying why — an unanswered finding and an excluded one look identical six months later, which is the
argument `spotbugs-exclude.xml` already makes about its own entries.

If the review changes code — `--fix` does — the two commands above ran on code that no longer
exists, so they run again on what the review left, and the gate is whatever ran last. Read the
review's diff against the issue before that: `--fix` applies findings it did not ask you about, and
a fix outside the issue's scope is step 3's widening in a different coat. Revert it and file it
(step 5) rather than keep it.

**A green local build is not the gate, and has twice been mistaken for it.** CI adds SpotBugs and
runs the suite on ubuntu, macOS and Windows; a pull request does not run everything main runs. Two
jobs are skipped on pull requests, and the toolchain a pull request runs on is not the pinned one,
so each of these finds your change on main instead:

| If the change touches | Run before the PR | Because a pull request will not |
|---|---|---|
| the multiplexer, the relay, the visitor path, anything per-connection | `./native.sh -DskipTests && LOAD=1000 SLOW=1000 ./measure.sh --check` | `budget` runs on main only — it needs a native build; the step in `ci.yml` is the definition, if the two ever differ |
| the hub's admission or fan-out | `./mvnw -pl hub -am test -Dgroups=load -Dtest.excludedGroups=` | `load` runs on main only — it holds a thousand sockets open |
| the JDK or GraalVM pin | `./mvnw -pl node -am test -Dtest=TranscriptTest -Dsurefire.failIfNoSpecifiedTests=false`, on the new toolchain, pasting the `Tests run:` line — that flag means a mistyped class prints `BUILD SUCCESS` and runs nothing | `test` runs on Liberica, not on the pin, and the job that does (`budget`) is one of the two above. Delegated signing predicts the bytes JSSE writes (§9.2); a JDK that writes them otherwise takes every hub-signed handshake down. CONTRIBUTING.md has the long form |

Read the header of `measure.sh` before trusting a surprising number from it. It carries a list of
the conclusions this harness has produced that were confident, plausible and wrong.

### 7. Open the pull request

`Closes #N` in the body, so the merge closes the issue and ends the claim. Move the issue to
`status:in-review`. Say in the body which of the gates above you ran and which you did not — a PR
that is silent about the budget run is one the reviewer has to assume was not measured. Give the
pull request the issue's type and area labels, and nothing from the status axis.

A decision that turns up now — a review finding that is a choice, a red check whose fix is one of
two approaches — is step 4 with a pull request attached. Mark the PR a draft, put the question in a
comment on it, and add `status:needs-decision` to it: `gh pr list --label status:needs-decision` is
then the list of pull requests a person owes an answer. Release the issue as in step 4. When the
answer comes, the label comes off, the draft is undrafted, and whoever continues claims the issue
again.

### 8. Merged

The issue closes itself. If the PR was merged without closing it, or was abandoned, release by
hand, as above.

Then take the status label off — `gh issue edit N --remove-label status:in-review`. `Closes #N`
closes the issue and leaves its labels alone, so nothing does this for you, and nothing did: on
2026-09-16 sixteen closed issues were carrying `status:in-review`, and seventy minutes after those
were swept there were eight more.

What it costs is not the query a reviewer runs — `gh issue list` is `--state open` unless told
otherwise, so a stale label is invisible there. It is everything that spans both states: the label's
own page on GitHub, its count, and any `--state all` or `--state closed` search. A label that says
`in-review` about something merged in June is a label that has to be checked against the issue
before it can be believed, which is the whole of what the axis was for.

Two invariants, and the one command that checks them both:

```sh
gh issue list --state all --limit 300 --json number,state,labels --jq '
  [.[] | select((.state == "CLOSED") == ([.labels[].name] | any(startswith("status:"))))
   | .number] | "wrong: \(.)"'      # closed with a status, or open without one
```

If the work needs looking at again, reopen the issue — that is what asks for the process again, and
it starts at step 1.

## Running the loop unattended

One session, one issue after another, with no person reading the diff between the claim and the
merge. It is the loop above with a pick rule, a merge rule, and a rule for `main` afterwards. **It is
not open yet**: #184 is the survey of what the suite can and cannot fail without a person, and it is
blocked on the three things that survey decided are the gate (#187, #188, #183). Until #184 is
closed a session runs the loop as far as step 7 and stops there, however many issues it takes in a
row.

The session is started with a **count**: how many issues to take before stopping, and one if
nothing is said. It is a ceiling, not a target — every stop below fires first — and it is what lets
a person say "three, then I will look" instead of finding out in the morning how far it got.

### Pick

The oldest `status:ready` whose newest CLAIM has expired or does not exist. There is no priority
axis, so age is the one rule a reader can check afterwards. Skip — do not even claim — anything
carrying `security`, `area:proto` or `area:release`; the merge rule below says why.

### Each issue

1. **A fresh worktree from the current `main`.** Reusing the last one means the second pull request
   is based on a `main` that has moved, and the merge is what finds out.
2. Steps 2 to 5 exactly as above.
3. `/code-review xhigh --fix`, then the review's diff read against the issue, then the gate — step 6
   with the table's row if the change touches it — on the code the review left.
4. Step 7, labels included.
5. **Merge** when all of these are true and none of them is a judgement: every check green, every
   review finding answered in the pull request, no `status:needs-decision`, base is the current
   `main`. Squash — that is what the history is made of. Then step 8, and the invariant command.
6. **Watch `main`.** `load` and `budget` run only now (§6), so this is the first native run of the
   change. A red job is re-run once. Red again: revert the merge (`gh pr revert`, or
   `git revert -m 1`), reopen the issue with the failing job's output in a comment, set it
   `status:ready`, and stop. Fixing forward is not the default because the next issue's pull request
   would then be based on a red `main`, and two changes would own one failure.
7. A problem seen anywhere in this is step 5: filed with all three axes and linked both ways. That
   is how the tracker grows from the loop, and it is the only way it may.

### What is never merged unattended

A pull request carrying `security`, `area:proto` or `area:release`: the trust boundary, the wire
(a wire change is a flag day for the live hub and its nodes), and the signing key. These stop at
step 7 with `status:in-review` and wait for a person. The pick rule keeps the session off them from
the start; the merge rule is for the label that was added on the way.

### Stop

- The count is reached.
- Nothing left that the pick rule allows.
- The gate failed twice on the same issue: `🤖 RELEASE`, `status:ready`, and the failure in the
  comment.
- A revert on `main`.
- The context was summarised. What the session knows about the issue in hand is now a summary of
  it; finish that issue and stop rather than start the next on a summary.

Every stop leaves the tracker true — nothing claimed, every pull request merged, `status:in-review`
or `status:needs-decision` — because the next session starts by reading it.

## What this does not do

It is advisory. Nothing enforces it, two sessions that both ignore it collide exactly as before,
and a session that claims an issue and works on something else is invisible to it. It is worth
having anyway for the same reason the exclusions in `spotbugs-exclude.xml` carry reasons: the cost
is one comment, and the failure it prevents is discovered late and expensive.

It is a loop for one issue at a time, and the unattended form runs them in series, not in
parallel. Nothing here describes two sessions deliberately splitting one issue, because nothing here
can keep two branches from diverging; split the issue first, and then it is two claims.
