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

## What this does not do

It is advisory. Nothing enforces it, two sessions that both ignore it collide exactly as before,
and a session that claims an issue and works on something else is invisible to it. It is worth
having anyway for the same reason the exclusions in `spotbugs-exclude.xml` carry reasons: the cost
is one comment, and the failure it prevents is discovered late and expensive.
