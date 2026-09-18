# Labels, and how a session says it is working on something

Several sessions — people and agents — read this tracker at once, and more than one of them shares
a checkout ([§3.2](ARCHITECTURE.md) is not where that is written down; it is a fact of how this
project is worked on). Two of them starting the same issue costs a wasted branch and a merge
nobody wanted. GitHub's own answer is the assignee field, which needs a GitHub account per worker,
and an agent session does not have one. So the claim is a comment, plus a label that indexes it.

## The three axes

An issue carries **one type**, **one or more areas**, and — while it is open — **exactly one
status**, and beside those it may carry `needs:hardware`. A closed issue carries no status: that
axis says where something is in the process, and a closed issue is not in it. Step 8 is where that
comes off.

A pull request carries the **type and area of the issue it closes** — copied at
`gh pr create --label` — and no status, and not `needs:hardware` either: that label says what
closing the *issue* needs, and nobody needs a machine to read a diff. A pull request's own state is
its status: draft, open, checks, merged.
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

**Beside the axes** — `needs:hardware`. What is left to close the issue is a machine or a device,
so a session without one cannot finish it however well it is scoped. It is not a status: the issue
stays `status:ready`, because a person with the machine can start it today and nothing is waiting on
a decision. It sits beside the three the way `security` sits beside a type, and it is the reason an
issue can carry four labels and still satisfy the sentence at the top of this section.

**What is left** is the whole of it. #80 needs a real Windows console, because the feature only runs
when `isTerminal()` is true. #81 needs a Windows machine for `schtasks`, a reboot and a logon —
which is a machine and specifically not a console — and a `linux-amd64` box for the architecture its
run did not cover; the Linux half that was reachable was done first, and while it was reachable this
label would have been wrong on it. So the label is about the remainder, and it comes off when a
reachable part appears, the same way any label that disagrees with its body comes off.

What it costs is that its absence is invisible. The first issue that needs it and has not got it is
found by a session spending a cycle on it, which is what #80 cost three runs before this label
existed. Set it when filing, and correct it — on or off — when a body says something the label does
not.

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

And `needs:hardware` if what would close it is a machine — a console on a particular OS, a box of a
particular architecture, a device. It is the one label a filer is better placed to set than anyone
afterwards: whoever writes "what would close it" already knows whether the answer names a machine.
Step 5 and step 7 of the loop below file issues too, and the same applies there.

## The loop

One issue, start to finish. Each step says what it is protecting, because a step whose reason is
not written down is a step somebody skips the first time it is inconvenient.

### 1. Pick

`status:ready`, or `status:needs-measurement` when you are the one taking the measurement.
`status:needs-decision` is not ready by definition, `status:blocked` and `status:parked` are waiting
on something that is not you, and `status:triage` has not been classified yet — classifying it is
itself a small piece of work, and a worthwhile one. `needs:hardware` is not a status and does not
stop a person, but it stops you when the machine the issue needs is one you have not got. The label
does not say which machine — that was the `env:` axis #223 turned down — so the body does.

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

File it. Title, the three axes, `needs:hardware` if what would close it is a machine, and a link
both ways. An observation that stays in a branch is an observation nobody else has.

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
tools/self-test.sh                        # only if the change touches tools/; its own job as well
```

Then `/code-review`, and answer what it finds. "Answer" includes deciding a finding is wrong and
saying why — an unanswered finding and an excluded one look identical six months later, which is the
argument `spotbugs-exclude.xml` already makes about its own entries.

**Not `--fix`, and especially not unattended.** It applies findings after the review's own
filtering, which is real — but the level decides what survives that filter, and `high` upwards
takes uncertain findings on purpose. Answering them is work the loop does either way, since every
finding has to be answered in the pull request; the only thing `--fix` changes is that the code is
already different when you read them. Deciding whether to keep somebody else's edit is harder than
deciding whether to write your own, and a fix outside the issue's scope is step 3's widening in a
different coat.

Two of this project's own reviews argued from a premise that did not hold, and reproducing them is
what separated those from the ones that did: one predicted that a skipped required check reports as
success, and the measurement said the opposite — the pull request went `BLOCKED` and stayed there.
A finding worth acting on survives being checked. Check it, then write the fix.

If a review does change code, for whatever reason, the two commands above ran on code that no
longer exists. Run them again; the gate is whatever ran last.

**A green local build is not the gate, and has twice been mistaken for it.** CI adds SpotBugs and
runs the suite on ubuntu, macOS and Windows; a pull request does not run everything main runs. Two
jobs are skipped on pull requests, and the toolchain a pull request runs on is not the pinned one,
so each of these finds your change on main instead:

**`ci:full` on the pull request runs the first two of these there instead.** The label makes `load`
and `budget` run on the pull request head, on the runners and with the arguments `main` uses — they
live in `ci-full.yml` and that file is the one definition, so a pull request and `main` cannot
measure different things. Add the label and the run starts; it needs no push. That is better
evidence than the local column below, which measures your laptop, and waiting for it costs you
nothing but the wait. The local commands stay in the table because a seven-minute round trip is a
poor way to iterate, and because `measure.sh` prints figures the gate only checks.

The two jobs are not in the ruleset's required checks, so a green merge box does not mean they
finished. Wait for them by name.

| If the change touches | Run before the PR | Because a pull request will not, unless labelled |
|---|---|---|
| the multiplexer, the relay, the visitor path, anything per-connection | `ci:full`, or `./native.sh -DskipTests && LOAD=1000 SLOW=1000 ./measure.sh --check` | `budget` needs a native build, seven minutes, so it is off a pull request by default |
| the hub's admission or fan-out | `ci:full`, or `./mvnw -pl hub -am test -Dgroups=load -Dtest.excludedGroups=` | `load` holds a thousand sockets open, so it is off a pull request by default |
| the JDK or GraalVM pin | `./mvnw -pl node -am test -Dtest=TranscriptTest -Dsurefire.failIfNoSpecifiedTests=false`, on the new toolchain, pasting the `Tests run:` line — that flag means a mistyped class prints `BUILD SUCCESS` and runs nothing | `test` runs on Liberica, not on the pin. `ci:full` covers half of this row and not the half you might think: `budget` pins GraalVM in `ci-full.yml`, so a pull request moving that pin does run `-Pnative package` — tests included — on the new one. The JDK the `test` matrix uses is not the pin, and no label changes that. Delegated signing predicts the bytes JSSE writes (§9.2); a JDK that writes them otherwise takes every hub-signed handshake down. CONTRIBUTING.md has the long form |

Read the header of `measure.sh` before trusting a surprising number from it. It carries a list of
the conclusions this harness has produced that were confident, plausible and wrong.

### 7. Open the pull request

`Closes #N` in the body, so the merge closes the issue and ends the claim. Move the issue to
`status:in-review`.

**And nowhere else in the body may one of GitHub's keywords stand next to an issue number.** The
parser matches `close #N` and does not read a `not` in front of it, so the sentence a "What this
does not do" section invites — *it does not close #N* — closes that issue on merge. `closes`,
`closed`, `fixes`, `fixed`, `resolves` and `resolved` are the same keyword.

This is not a corner. It happened three times in one afternoon (#207): twice in bodies saying the
opposite of what they did, and once in the body of the pull request **documenting the trap**, which
quoted the bad sentence with a real number in it and so did the thing it was describing. An example
in a pull request body has to carry a placeholder — `#N`, as above — and not a number.

Two phrasings that mean the same and are not keywords: **#N stays open**, and **#N is parked, not
fixed**. Step 8's invariant command is what catches the damage afterwards, and all three times it
did. Say in the body which of the gates above you ran and which you did not — a PR
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
merge. It is the loop above with a pick rule, a merge rule, and a rule for `main` afterwards.

It was shut until #184 said what the suite can and cannot fail without a person, and it opened on
2026-09-17 when the three things that survey named were done: `tools/flake-rate.sh` (#187), the
`ci:full` label (#188), and a measured answer for the `load` flake (#183). What that gate was
asking for, in the end, was one number — how often a red job is red for no reason — because the
revert rule below rests on it and nothing said what it was.

The session is started with a **count**: how many issues to take before stopping, and one if
nothing is said. It is a ceiling, not a target — every stop below fires first — and it is what lets
a person say "three, then I will look" instead of finding out in the morning how far it got.

**An issue spends the count when it produces the thing it asked for** — a pull request, or the
comment that is the whole deliverable on an issue asking for a measurement. One that is claimed and
released on a first real read, the body disagreeing with the label or the work turning out to be a
decision, was taken and produced nothing; counting that would let a run of three end with three
released issues and nothing to show. The two readings have the same words and very different
mornings. The session names the released ones when it stops, with a line each on why, because a
release is invisible from `gh issue list`: the label is back to what it was, and only the comment on
the issue says a session was ever there.

### Pick

The oldest `status:ready` whose newest CLAIM has expired or does not exist. There is no priority
axis, so age is the one rule a reader can check afterwards. Skip — do not even claim — anything
carrying `security`, `area:proto` or `area:release`, for the reason the merge rule below gives, or
`needs:hardware`, for the reason the axes section gives: the session cannot finish it, and no amount
of scoping changes that.

**The label is a claim about the body, not a reading of it, and the first run found two that
disagreed with their own.** #71 was `status:ready` under a heading reading "Why this is a decision
and not a task", #72 under "Parked, deliberately". So the body is read before the CLAIM comment goes
up — step 2 already says to read the comments, and this is the same reflex one field over — and when
the two disagree, the label the body asks for is what the issue gets, with a line saying why. That
relabelling is the work, it is worth doing, and it does not spend the count.

**Ready means scoped, not reachable**, and `needs:hardware` is what says so. Three runs paid for
that reading before the label existed, and each paid differently: the first read #80 and #81, walked
past both, and filed #215, which put the cost at four issues' worth of reading; the second walked
past both again and filed #223, asking what to do about it; the third claimed #80, found the wall,
released it a minute later, and filed an issue #223 already was.
Walk past a `needs:hardware` issue the way the three labels above are walked past — no claim, no
comment — and name it at the stop, so a person reading the session's output sees what was skipped.

That silence is for an issue the label fits. A label that disagrees with its body is the case the
paragraph above governs, and it is the work rather than a walk-past: the reading is the same body
that paragraph already asks for, the label goes on or comes off, and the line saying why goes with
it. The third run is the worked example in both directions. #80's remainder is a machine and the
label belongs on it; #81's did not become one until the half that was reachable had been done and
merged, and a session that had walked past #81 in silence would have left that work undone.

### Each issue

1. **A fresh worktree from the current `main`.** Reusing the last one means the second pull request
   is based on a `main` that has moved, and the merge is what finds out.
2. Steps 2 to 5 exactly as above.
3. `/code-review xhigh`, without `--fix` (step 6 says why), then every finding answered — written
   or refused with a reason — and then the gate, step 6 with the table's row if the change touches
   it, on whatever the answers left.
4. Step 7, labels included, and `ci:full` as well when the change touches a row of that table. Then
   wait for `load` and `budget` by name before merging — they are not required checks, so the merge
   box goes green without them and `gh pr merge --auto` would not wait. That wait is the whole
   difference between finding a budget regression here and finding it on `main` afterwards.
5. **Merge** when all of these are true and none of them is a judgement: every check green, every
   review finding answered in the pull request, no `status:needs-decision`, base is the current
   `main`. Squash — that is what the history is made of. Then step 8, and the invariant command.
6. **Watch `main`.** Unless the pull request carried `ci:full`, this is the first time `load` and
   `budget` see the change, and so the first native run of it. A red job is re-run once. Red
   again: revert the merge (`gh pr revert`, or `git revert -m 1`), reopen the issue with the
   failing job's output in a comment, set it `status:ready`, and stop. Fixing forward is not the
   default because the next issue's pull request would then be based on a red `main`, and two
   changes would own one failure.

   **The revert is a pull request, and it is exposed to exactly what it is recovering from.** On
   the first real run the revert's own Windows job went red — `DnsResponderTest`, `Address already
   in use`, #196's family, and nothing to do with either change — and passed when it was re-run. So
   it gets the same one re-run as any other red, and if it still cannot land the session stops
   there and says so on the issue it reopened: a revert retried until it passes is a session
   deciding on its own that a red is a flake, which is the judgement this whole rule exists to take
   away from it. That stop is the one below that cannot leave the tracker tidy — `main` is red and
   a pull request is open — and saying which job, on which run, is the whole of what it can do.

   The rule rests on a number, and the number is smaller than the one a reader reaches for.
   `tools/flake-rate.sh` prints it: for each job on `main` it counts the reds, and sorts them into
   red-then-re-run-green, red-then-re-run-red, and never resolved. What the rule is exposed to is
   the middle one — a false revert is a flake that repeats — and what a red rate measures is
   mostly the first and the third.

   The sharpest reading is of `load`, because it was measured on purpose rather than gathered:
   twenty dispatches of that job alone on one commit, after the race behind #201 was fixed, gave
   **one red in twenty**. A false revert needs two in a row, so it is about **one in four hundred**.
   That is the arithmetic the rule stands on, and #183 holds the working. The one red is the test's
   own thirty-second connect deadline being met on a runner ten times slower than usual; it is
   parked at that rate deliberately, because raising the deadline buys a green run by removing the
   only signal that says the run was slow.

   Across every job, from `tools/flake-rate.sh 50` on 2026-09-17, the last 50 pushes to `main` —
   102 runs, every workflow that answered them, `ci` and `ci-full` and `images`:

   | | |
   |---|---|
   | reds | 13 — twelve in `ci`, at 4.4% to 8.9% a job, and one in `ci-full`. `images` clean over all 50 |
   | re-run on the same commit | 5, of which 5 went green and 0 were red again |
   | never resolved | 8 — nobody re-ran them, so a flake and a regression look identical |

   The eight unresolved reds are why that table is weaker than the twenty dispatches above, and
   they are why the report prints them as their own column rather than folding them into a rate.
   Four tests account for all thirteen:
   `VisitorStallTest` six, fixed by #150; `LoadTest` four, which is #183; `AutoPromoteTest` two and
   `RawPortTest` one, the port race fixed by #171. Read the per-job rates and not `ci-full`'s 50%:
   that job has two runs in this window, because the file is two pushes old. At this pace fifty
   pushes is under two days, so re-run the script rather than trusting the table above; `tools/flake-rate.sh --self-test` is what a change to the
   script itself has to pass; the `tools` job runs it, and every other self-test in `tools/`,
   through `tools/self-test.sh`.

7. A problem seen anywhere in this is step 5: filed with all three axes, `needs:hardware` where it
   applies, and linked both ways. That is how the tracker grows from the loop, and it is the only
   way it may.

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
or `status:needs-decision` — because the next session starts by reading it, and the one stop above
that cannot say so says which job on which run beat it. The session's own last word carries what a
label carries only half of: `gh issue list --label needs:hardware` says which issues no session can
finish, and the stop says which of them *this* run reached and skipped, and which it claimed and
released without work. Both are what the next session would otherwise pay to discover again.

## What this does not do

It is advisory. Nothing enforces it, two sessions that both ignore it collide exactly as before,
and a session that claims an issue and works on something else is invisible to it. It is worth
having anyway for the same reason the exclusions in `spotbugs-exclude.xml` carry reasons: the cost
is one comment, and the failure it prevents is discovered late and expensive.

It is a loop for one issue at a time, and the unattended form runs them in series, not in
parallel. Nothing here describes two sessions deliberately splitting one issue, because nothing here
can keep two branches from diverging; split the issue first, and then it is two claims.
