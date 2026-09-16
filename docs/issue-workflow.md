# Labels, and how a session says it is working on something

Several sessions — people and agents — read this tracker at once, and more than one of them shares
a checkout ([§3.2](ARCHITECTURE.md) is not where that is written down; it is a fact of how this
project is worked on). Two of them starting the same issue costs a wasted branch and a merge
nobody wanted. GitHub's own answer is the assignee field, which needs a GitHub account per worker,
and an agent session does not have one. So the claim is a label plus a comment.

## The three axes

An issue carries **one type**, **one or more areas**, and **exactly one status**.

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
| `status:blocked` | Waiting on something outside this repository | Nobody |
| `status:parked` | Open, and deliberately not being worked on | Nobody, until it is moved back |

`status:parked` is not `wontfix`. Parked issues stay open because the alternative is that the
same limitation is rediscovered from the docs every few months and filed again.

## Claiming

A claim is two things, and neither alone counts:

1. the `status:claimed` label, replacing whatever status was there, and
2. a comment in exactly this form, so it can be found by grep and read by a machine:

```
🤖 CLAIM
session: <a name that identifies this session>
branch: <the branch or worktree the work is on>
started: <ISO-8601 UTC>
expires: <ISO-8601 UTC, started + 4h>
```

```sh
gh issue edit 42 --remove-label status:ready --add-label status:claimed
gh issue comment 42 --body "$(printf '🤖 CLAIM\nsession: %s\nbranch: %s\nstarted: %s\nexpires: %s\n' \
  "bridge-cse_019PN" "$(git branch --show-current)" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u -v+4H +%Y-%m-%dT%H:%M:%SZ)")"
```

**Read the comments before you claim.** The label can be stale; the newest CLAIM comment is what
is true.

**The expiry is the point.** A session dies without cleaning up — a window closed, a context
exhausted, a machine asleep — and a claim with no expiry is a permanent lock held by nobody. Four
hours is long enough for real work and short enough that a dead session does not hold an issue
overnight. Renew by posting a fresh CLAIM; there is no other renewal.

## Releasing, and taking over

Finished, or a pull request is open: move to `status:in-review` and link the PR. The PR closing
the issue is what ends the claim, so no comment is needed.

Giving up: comment `🤖 RELEASE` with one line on how far you got, and move the status back to
whatever it should be now — often `status:ready`, sometimes `status:needs-decision` because the
work found a question.

Taking over an expired claim: check that `expires` has passed **and** that no open PR links the
issue, then comment

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

Only `status:ready`. `status:needs-decision` and `status:needs-measurement` are not ready by
definition, `status:blocked` and `status:parked` are waiting on something that is not you, and
`status:triage` has not been classified yet — classifying it is itself a small piece of work, and a
worthwhile one.

### 2. Claim

The label and the comment, as above. **Read the existing comments first**: the label can be stale
and the newest CLAIM is what is true.

### 3. Work, and not in the shared checkout

Several sessions edit the same clone. Build in a worktree of your own so that a `package` run does
not compile someone else's half-finished edit, and so that a failure is yours.

Stay inside the issue. The scope in the issue is the deliverable; a change that grows past it is
harder to review, harder to revert, and it is the shape a PR gets stuck in.

### 4. When a decision turns up that is not yours to make

Some things are not the session's call: which of three approaches, whether a control is worth its
cost, whether a limit is accepted. **Do not guess and do not hold the issue.**

Leave the question on the issue in the form the reader needs — what the options are, what each
costs, what tips it — comment `🤖 RELEASE` naming the question, and move the status to
`status:needs-decision`. Then go and do something else.

Holding `status:claimed` while waiting looks like progress and is not: the decision may take days,
the claim expires in four hours, and in between the issue is neither being worked on nor available.
Releasing costs re-reading the issue later; holding costs everyone else.

### 5. When work uncovers a different problem

File it. Title, the three axes, and a link both ways — this is exactly how #66 through #86 came to
exist, and an observation that stays in a branch is an observation nobody else has.

Then choose, honestly:

- **It does not block this issue.** File it, link it, keep going. Widening the change to cover it is
  the most common way a small PR becomes unreviewable.
- **It blocks this issue.** Move the issue you hold to `status:blocked`, link the new one, comment
  `🤖 RELEASE`. The new issue is now the work.

### 6. The gate, before any pull request

In this order, and the order matters — a review of code that does not compile wastes the review.

```sh
./mvnw package                            # the tests, on this platform
./mvnw -Panalyze verify -DskipTests       # SpotBugs; its own job in CI, so it is easy to forget
```

Then `/code-review`, and answer what it finds. "Answer" includes deciding a finding is wrong and
saying why — an unanswered finding and an excluded one look identical six months later, which is the
argument `spotbugs-exclude.xml` already makes about its own entries.

**A green local build is not the gate, and has twice been mistaken for it.** CI adds SpotBugs and
runs the suite on ubuntu, macOS and Windows; a pull request does not run everything main runs. Two
jobs are skipped on pull requests and will find your change on main instead:

| If the change touches | Run before the PR | Because CI runs it only on main |
|---|---|---|
| the multiplexer, the relay, the visitor path, anything per-connection | `./native.sh -DskipTests && LOAD=1000 SLOW=1000 ./measure.sh --check` | `budget` — it needs a native build |
| the hub's admission or fan-out | `./mvnw -pl hub -am test -Dgroups=load -Dtest.excludedGroups=` | `load` — it holds a thousand sockets open |

Read the header of `measure.sh` before trusting a surprising number from it. It carries a list of
the conclusions this harness has produced that were confident, plausible and wrong.

### 7. Open the pull request

`Closes #N` in the body, so the merge closes the issue and ends the claim. Move the issue to
`status:in-review`. Say in the body which of the gates above you ran and which you did not — a PR
that is silent about the budget run is one the reviewer has to assume was not measured.

### 8. Merged

The issue closes itself. If the PR was merged without closing it, or was abandoned, release the
claim by hand: `🤖 RELEASE` and a status that reflects what is true now.

## What this does not do

It is advisory. Nothing enforces it, two sessions that both ignore it collide exactly as before,
and a session that claims an issue and works on something else is invisible to it. It is worth
having anyway for the same reason the exclusions in `spotbugs-exclude.xml` carry reasons: the cost
is one comment, and the failure it prevents is discovered late and expensive.

It is also a loop for one issue at a time. Nothing here describes two sessions deliberately
splitting one issue, because nothing here can keep two branches from diverging; split the issue
first, and then it is two claims.
