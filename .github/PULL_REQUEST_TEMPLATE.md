Closes #

<!-- Labels: the type and area labels of the issue above, and none from the status axis — the
     issue carries that. `status:needs-decision` on a PR means a question is waiting on a person;
     docs/issue-workflow.md step 7 says when. -->

## What changed, and why it was worth changing

<!-- The problem first. A reviewer who has to infer the problem from the diff is reviewing the
     wrong thing. -->

## What this does not do

<!-- The scope you deliberately did not take, and anything the change leaves open. If it needs a
     follow-up issue, file it and link it here rather than leaving it in this paragraph.

     Do not write "does not close #N" here, or fix/resolve either: GitHub matches the keyword and
     ignores the "not", so the sentence closes the issue it says it is leaving open. "#N stays
     open" says the same thing and does not. This applies to an example as much as to a claim --
     quoting the bad sentence with a real number in it does the same damage. -->

## Gates

<!-- Tick what you ran. A PR silent about the budget is one a reviewer has to assume was not
     measured. CI runs `package` and `-Panalyze` on every pull request; the budget and load gates
     are off by default, so an unticked box for one of those is a failure that finds main instead
     of you. The `ci:full` label runs both of them here, on this head, which is better evidence
     than a local run — but they are not required checks, so nothing stops a merge from beating
     them. Wait for them by name. -->

- [ ] `./mvnw package`
- [ ] `./mvnw -Panalyze verify -DskipTests`
- [ ] A review pass over the diff (`/code-review` if you have it), and every finding answered — including the ones answered with "no, and here is why"
- [ ] The `ci:full` label, or `./native.sh -DskipTests && LOAD=1000 SLOW=1000 ./measure.sh --check` — required if this touches the multiplexer, the relay, the visitor path, or anything per-connection
- [ ] The `ci:full` label, or `./mvnw -pl hub -am test -Dgroups=load -Dtest.excludedGroups=` — required if this touches the hub's admission or fan-out
- [ ] `./mvnw -pl node -am test -Dtest=TranscriptTest -Dsurefire.failIfNoSpecifiedTests=false` **on the new toolchain** — required if this moves the JDK or GraalVM pin. Paste the `Tests run:` line and name the build; `BUILD SUCCESS` alone does not tell a typo from a pass (CONTRIBUTING.md says why)
- [ ] Not applicable, because: <!-- say so rather than leaving boxes unticked -->

## Documents this change makes untrue

<!-- Name them, or write "none". `ARCHITECTURE.md` §15 is what a reader is pointed at to find out
     what this system cannot do and §14 is where its numbers are, so a change that removes a limit
     or moves a figure and leaves those sections alone has left them wrong. "None" is the usual
     answer and is worth writing, because "none" says the sections were looked at and a blank says
     nothing at all. Nothing in CI can check this: no test can tell that a sentence stopped being
     true. -->

## Tests

<!-- What each new test can fail. A test that cannot fail in the direction it claims passes just as
     well when the feature is dead — that is #80. -->

## Numbers

<!-- Any figure this changes or claims: on which platform, from which build (native or JVM), and
     what it does not cover. Delete this section if the change moves no number. -->
