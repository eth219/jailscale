#!/usr/bin/env sh
# How often main goes red for no reason. docs/issue-workflow.md, "Running the loop unattended",
# re-runs a red job on main once and reverts the merge on the second red; that rule is only as
# good as the chance that a flake repeats, and until this existed nothing said what that chance
# was (#187, from the survey in #184).
#
#   tools/flake-rate.sh [N]          the last N push runs of ci.yml on main (default 50, max 100)
#   tools/flake-rate.sh --self-test  the classification, against a fixture that must fail if it is wrong
#
# A job's reds are sorted into three outcomes, and the difference between them is the whole point:
#
#   flaked      red, re-run on the same commit, green. Nothing changed but the clock.
#   red again   red, re-run, red again. This is what the revert rule acts on.
#   unresolved  red and never resolved -- nobody re-ran it, or the re-run did not finish.
#               A regression and a flake look identical here, so these are the reds the report
#               cannot classify, and on this repository they are usually the majority.
#
# So the printed red rate counts every red and is an upper bound on noise, while `flaked` alone is
# a lower bound. The number the revert rule actually needs is neither: it is `red again` over the
# reds that were re-run, and the summary line prints it.
#
# A re-run lists every job again, including the ones it did not re-run, which keep their earlier
# conclusion AND their earlier started_at. Executions are therefore deduplicated by
# started_at in the classifier, so a job carried into a later attempt is not a second red -- which
# is a shape the fixture below carries, because getting it wrong turns every red that happened to
# sit beside a re-run into a false "red again", and that is what the revert rule acts on.
#
# For every red the failing test classes are read out of that job's log, so the report names
# LoadTest rather than `load`. A log that cannot be read says so rather than reading as "no test
# failed" -- the two mean different things and the report has been wrong about it.
#
# Needs gh (authenticated), jq and awk.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
command -v gh >/dev/null 2>&1 || { echo "this needs the gh CLI." >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "this needs jq." >&2; exit 1; }
# The sibling scripts' convention: the repository comes from this checkout, so a fork reports on
# itself rather than silently on eth219/jailscale.
repo=$(cd "$root" && gh repo view --json nameWithOwner --jq .nameWithOwner) \
    || { echo "cannot tell which GitHub repository $root is; is the origin remote set?" >&2; exit 1; }
workflow=${WORKFLOW:-ci.yml}
branch=${BRANCH:-main}
tab=$(printf '\t')

# The classification. Input: an array of executions, one per (run, job, started):
#   {run, sha, job, attempt, conclusion, started, tests}
# Output: the whole report. Kept in one jq program so --self-test and the live path share it.
classify='
  def pct: (. * 1000 | round) as $n | "\($n / 10 | floor).\($n % 10)%";
  ( group_by([.run, .job, .started]) | map(max_by(.attempt))
    | group_by([.run, .job])
    | map( sort_by(.attempt) as $e
           | ($e | map(select(.conclusion == "failure"))) as $red
           | $e[-1] as $last
           | { run: $e[0].run, sha: $e[0].sha, job: $e[0].job,
               ran: ($e | any(.conclusion == "success" or .conclusion == "failure")),
               outcome: (if ($red | length) == 0 then null
                         elif $last.conclusion == "success" then "flaked"
                         elif $last.conclusion == "failure" and ($e | length) > 1 then "red again"
                         else "unresolved" end),
               tests: ($red[-1].tests // "-") } )
  ) as $rj
  | ( $rj | group_by(.job)
      | map( { job: .[0].job,
               runs: (map(select(.ran)) | length),
               flaked: (map(select(.outcome == "flaked")) | length),
               again: (map(select(.outcome == "red again")) | length),
               unresolved: (map(select(.outcome == "unresolved")) | length) }
             | .red = (.flaked + .again + .unresolved) )
      | map(select(.runs > 0)) | sort_by(.job) ) as $table
  | ( $rj | map(select(.outcome != null)) | sort_by(.run, .job) ) as $reds
  | ( $reds | map(select(.outcome == "flaked")) | length ) as $g
  | ( $reds | map(select(.outcome == "red again")) | length ) as $b
  | ( $reds | map(select(.outcome == "unresolved")) | length ) as $u
  | ( ["job", "runs", "red", "flaked", "red again", "unresolved", "red rate"] | @tsv ),
    ( $table[] | [ .job, .runs, .red, .flaked, .again, .unresolved,
                   (if .runs == 0 then "-" else (.red / .runs | pct) end) ] | @tsv ),
    "",
    ( if ($reds | length) == 0 then "no red job in these runs"
      else "of \($g + $b + $u) reds, \($g + $b) were re-run on the same commit: \($g) green, "
           + "\($b) red again. \($u) were never resolved, so whether those were flakes is not known "
           + "from here. The re-run-once rule reverts when a flake repeats, which happened in "
           + (if ($g + $b) == 0 then "none of them, there being no re-run here."
              else "\($b) of \($g + $b) re-runs." end)
      end ),
    "",
    ( if ($reds | length) == 0 then empty
      else "red jobs (run, commit, job, outcome, what failed):",
           ( $reds[] | "  \(.run)\t\(.sha[0:7])\t\(.job)\t\(.outcome)\t\(.tests)" )
      end )
'

# Pads the tab-separated lines into columns. awk rather than `column`, which is not POSIX and is
# missing from minimal images -- and which, being the last command of a pipeline, used to take the
# rest of the report down with it.
pad() {
    awk -F'\t' '
      { line[NR] = $0; nf[NR] = NF; for (i = 1; i <= NF; i++) cell[NR, i] = $i }
      END {
        # Widths are computed per block of adjacent tabbed lines, so the two tables size themselves
        # independently and a prose paragraph between them is not measured as a column.
        r = 1
        while (r <= NR) {
          if (nf[r] < 2) { print line[r]; r++; continue }
          s = r; while (r <= NR && nf[r] >= 2) r++
          for (i in w) delete w[i]
          for (k = s; k < r; k++)
            for (i = 1; i <= nf[k]; i++) if (length(cell[k, i]) > w[i]) w[i] = length(cell[k, i])
          for (k = s; k < r; k++) {
            out = ""
            for (i = 1; i <= nf[k]; i++) out = out sprintf("%-" w[i] "s  ", cell[k, i])
            sub(/ +$/, "", out); print out } } }'
}

if [ "${1:-}" = "--self-test" ]; then
    # Nine runs, each shape the classifier has to tell apart. Run 5 is the one the live API forced:
    # a re-run lists the jobs it did not re-run again, with the same started_at, and counting that
    # as a second red would turn every red beside a re-run into a false "red again".
    fixture='[
      {"run":1,"sha":"aaaaaaa","job":"load","attempt":1,"conclusion":"failure","started":"t1","tests":"LoadTest"},
      {"run":1,"sha":"aaaaaaa","job":"load","attempt":2,"conclusion":"success","started":"t2"},
      {"run":1,"sha":"aaaaaaa","job":"budget","attempt":1,"conclusion":"success","started":"t1"},
      {"run":1,"sha":"aaaaaaa","job":"budget","attempt":2,"conclusion":"success","started":"t1"},
      {"run":2,"sha":"bbbbbbb","job":"load","attempt":1,"conclusion":"success","started":"t1"},
      {"run":2,"sha":"bbbbbbb","job":"budget","attempt":1,"conclusion":"failure","started":"t1","tests":"VisitorStallTest"},
      {"run":3,"sha":"ccccccc","job":"load","attempt":1,"conclusion":"success","started":"t1"},
      {"run":3,"sha":"ccccccc","job":"budget","attempt":1,"conclusion":"success","started":"t1"},
      {"run":4,"sha":"ddddddd","job":"test","attempt":1,"conclusion":"failure","started":"t1","tests":"DnsQueryTest"},
      {"run":4,"sha":"ddddddd","job":"test","attempt":2,"conclusion":"failure","started":"t2","tests":"DnsQueryTest"},
      {"run":4,"sha":"ddddddd","job":"index","attempt":2,"conclusion":"skipped","started":"t1"},
      {"run":5,"sha":"eeeeeee","job":"load","attempt":1,"conclusion":"failure","started":"t1","tests":"LoadTest"},
      {"run":5,"sha":"eeeeeee","job":"load","attempt":2,"conclusion":"failure","started":"t1","tests":"LoadTest"},
      {"run":5,"sha":"eeeeeee","job":"budget","attempt":1,"conclusion":"failure","started":"t1","tests":"RawPortTest"},
      {"run":5,"sha":"eeeeeee","job":"budget","attempt":2,"conclusion":"success","started":"t2"},
      {"run":6,"sha":"fffffff","job":"load","attempt":1,"conclusion":"failure","started":"t1","tests":"LoadTest"},
      {"run":6,"sha":"fffffff","job":"load","attempt":2,"conclusion":"cancelled","started":"t2"},
      {"run":7,"sha":"ggggggg","job":"load","attempt":1,"conclusion":"failure","started":"t1","tests":"(log unavailable)"},
      {"run":8,"sha":"hhhhhhh","job":"load","attempt":1,"conclusion":"success","started":"t1"},
      {"run":9,"sha":"iiiiiii","job":"load","attempt":1,"conclusion":"success","started":"t1"}
    ]'
    # The expected report, whole. Comparing it entire is what makes the red-jobs half of the
    # classifier able to fail: asserting only the table let the list be blanked, inverted, or
    # stripped of its test classes and still pass (CLAUDE.md rule 5).
    expected=$(cat <<'EXPECT'
job|runs|red|flaked|red again|unresolved|red rate
budget|4|2|1|0|1|50.0%
load|8|4|1|0|3|50.0%
test|1|1|0|1|0|100.0%

of 7 reds, 3 were re-run on the same commit: 2 green, 1 red again. 4 were never resolved, so whether those were flakes is not known from here. The re-run-once rule reverts when a flake repeats, which happened in 1 of 3 re-runs.

red jobs (run, commit, job, outcome, what failed):
  1|aaaaaaa|load|flaked|LoadTest
  2|bbbbbbb|budget|unresolved|VisitorStallTest
  4|ddddddd|test|red again|DnsQueryTest
  5|eeeeeee|budget|flaked|RawPortTest
  5|eeeeeee|load|unresolved|LoadTest
  6|fffffff|load|unresolved|LoadTest
  7|ggggggg|load|unresolved|(log unavailable)
EXPECT
)
    got=$(printf '%s' "$fixture" | jq -r "$classify" | tr '\t' '|')
    # pad() is the other half of the report and the classifier's output does not reach a reader
    # without it. Two blocks around a prose line, which is the shape that broke: the paragraph's
    # length was taken for a column width and the first column came out 180 characters wide.
    # Three columns, so that a middle column wider than the first is visible: padding every
    # column to one width looks identical whenever the difference falls in the last one.
    padded=$(printf 'a\tb\tc\ndd\tbbbb\tee\na sentence, untabbed and long enough to matter\ne\tf\n' | pad)
    want=$(printf 'a   b     c\ndd  bbbb  ee\na sentence, untabbed and long enough to matter\ne  f\n')
    if [ "$padded" != "$want" ]; then
        echo "self-test: pad() does not line the columns up." >&2
        printf 'expected:\n%s\n\ngot:\n%s\n' "$want" "$padded" >&2
        exit 1
    fi
    if [ "$got" = "$expected" ]; then echo "self-test: ok"; exit 0; fi
    echo "self-test: the classifier does not say what it claims." >&2
    printf 'expected:\n%s\n\ngot:\n%s\n' "$expected" "$got" >&2
    exit 1
fi

n=${1:-50}
case $n in ''|*[!0-9]*) echo "usage: tools/flake-rate.sh [N] | --self-test" >&2; exit 2 ;; esac
# GitHub clips per_page to 100 and reads 0 as "use the default 30", either of which would make the
# report quietly about a different window than the one asked for.
{ [ "$n" -ge 1 ] && [ "$n" -le 100 ]; } || { echo "N must be between 1 and 100." >&2; exit 2; }

runs=$(gh api "repos/$repo/actions/workflows/$workflow/runs?branch=$branch&event=push&per_page=$n" \
       --jq '.workflow_runs[] | select(.status == "completed")
             | [.id, (.conclusion // "-"), .head_sha, .created_at] | @tsv')
[ -n "$runs" ] || { echo "no completed push runs of $workflow on $branch." >&2; exit 1; }

eval "$(printf '%s\n' "$runs" | awk -F'\t' '
  NR == 1 { last = $4 } $2 == "cancelled" { c++ } { first = $4 }
  END { printf "total=%d cancelled=%d first=%s last=%s\n", NR, c + 0, first, last }')"

# One TSV line per execution. The jobs call is made once per run: filter=all returns every
# attempt's jobs, each carrying its own run_attempt, so there is no attempt loop to get wrong.
# `jobs=$(...)` rather than a pipeline, so that a failed call exits here instead of being
# swallowed and leaving a report that looks complete.
rows=$(printf '%s\n' "$runs" | awk -F'\t' '$2 != "cancelled"' | while IFS="$tab" read -r id conclusion sha created; do
    jobs=$(gh api "repos/$repo/actions/runs/$id/jobs?filter=all&per_page=100" \
           --jq '[.jobs[] | {id, name, conclusion: (.conclusion // "-"), attempt: .run_attempt, started: (.started_at // "-")}]
                 | .[] | [.id, .attempt, .conclusion, .started, .name] | @tsv')
    printf '%s\n' "$jobs" | while IFS="$tab" read -r jid attempt jc started name; do
        [ -n "$jid" ] || continue
        tests=
        if [ "$jc" = failure ]; then
            if log=$(gh api --allow-escape-sequences "repos/$repo/actions/jobs/$jid/logs" 2>/dev/null); then
                # -a because a Windows job writes its failure messages in the console codepage, and
                # one non-UTF-8 byte makes grep treat the whole log as binary and print nothing.
                tests=$(printf '%s' "$log" | grep -aoE '<<< (FAILURE|ERROR)! -- in [A-Za-z0-9_.]+' \
                        | sed 's/.* -- in //' | sort -u | paste -sd, - || true)
                [ -n "$tests" ] || tests='(no test failure in the log)'
            else
                tests='(log unavailable)'
            fi
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$sha" "$attempt" "$jc" "$started" "$tests" "$name"
    done
done)

events=$(printf '%s\n' "$rows" | jq -Rn '[ inputs | select(length > 0) | split("\t")
  | { run: (.[0] | tonumber), sha: .[1], attempt: (.[2] | tonumber), conclusion: .[3],
      started: .[4], tests: (.[5] | if . == "" then null else . end), job: .[6] } ]')

echo "$workflow on $branch, the last $total push runs ($first .. $last), $cancelled cancelled and not counted"
echo
printf '%s' "$events" | jq -r "$classify" | pad
