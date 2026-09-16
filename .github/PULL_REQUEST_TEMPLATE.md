Closes #

## What changed, and why it was worth changing

<!-- The problem first. A reviewer who has to infer the problem from the diff is reviewing the
     wrong thing. -->

## What this does not do

<!-- The scope you deliberately did not take, and anything the change leaves open. If it needs a
     follow-up issue, file it and link it here rather than leaving it in this paragraph. -->

## Gates

<!-- Tick what you ran. A PR silent about the budget is one a reviewer has to assume was not
     measured. CI runs the first two on every pull request; it runs the last two only on main, so
     an unticked box below is a failure that finds main instead of you. -->

- [ ] `./mvnw package`
- [ ] `./mvnw -Panalyze verify -DskipTests`
- [ ] A review pass over the diff (`/code-review` if you have it), and every finding answered — including the ones answered with "no, and here is why"
- [ ] `./native.sh -DskipTests && LOAD=1000 SLOW=1000 ./measure.sh --check` — required if this touches the multiplexer, the relay, the visitor path, or anything per-connection
- [ ] `./mvnw -pl hub -am test -Dgroups=load -Dtest.excludedGroups=` — required if this touches the hub's admission or fan-out
- [ ] Not applicable, because: <!-- say so rather than leaving boxes unticked -->

## Tests

<!-- What each new test can fail. A test that cannot fail in the direction it claims passes just as
     well when the feature is dead — that is #80. -->

## Numbers

<!-- Any figure this changes or claims: on which platform, from which build (native or JVM), and
     what it does not cover. Delete this section if the change moves no number. -->
