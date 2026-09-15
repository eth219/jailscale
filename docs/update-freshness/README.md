# Signed freshness: what says which release is current

A design. It closes the gap [ARCHITECTURE.md §15](../ARCHITECTURE.md) records as **"nothing signed
says which release is current"**, which is the piece §9.4 calls "that part of an update framework
this design does not have". It changes what `jailscale update` believes, not what it installs: the
three-link chain over a download ([§9.4](../ARCHITECTURE.md), and
[docs/release-verification.md](../release-verification.md) for the same chain by hand) is untouched.

**All five steps below are built**, and the first pointer went up on 2026-09-15 (seq 1, naming
v0.1.10). The release tooling signs, publishes and re-issues the pointer; `update` takes the
announcement from it instead of from an unsigned release index; a node refuses a pointer whose
sequence is below the highest it has recorded; and both the node and the nightly CI run say so
before it expires. What the design does not close is **first contact** -- see the last section.

**Ordering, which mattered once step 2 was in a binary, and is now settled.** A build that reads the
pointer needs one to read, so the first pointer had to be published before any release carrying the
client half. It was: `tools/refresh-index.sh --first v0.1.10` on 2026-09-15, before the client half
reached `main`.

It is written first because the two ergonomic steps queued behind it -- `update --install` doing the
replacement where the privilege is already there, and restarting the service after it -- each make
the answer to "which release is current" carry more weight. Today a person reads a version number
and types a command, and that person is the last thing standing between an index and a running
binary. Automating that step is worth doing; doing it while the index is unsigned is not.

## The gap, stated exactly

`Updates.check` asks `api.github.com/repos/eth219/jailscale/releases/latest` for a `tag_name` and
compares it with the running version. Nothing signs that answer. `--download` then verifies
everything about the bytes it fetches -- an Ed25519 signature over `RELEASE.txt`, which names its
own tag, then `SHA256SUMS.txt` against the digest in it, then the asset against that list -- so the
question the signature answers is *"are these the bytes of the release I asked for"*, and the
question nobody answers is *"is the release I asked for the one I should have asked for"*.

What an adversary who can publish to the repository can therefore do: **keep a node on an older
release, for as long as they keep the index naming it.** Every check the node makes passes, because
the old release is genuinely signed. What the same adversary cannot do is put a node *below* what it
runs -- `fetch` re-derives "is this an upgrade" from the tag inside the signed manifest and refuses
anything not strictly above the running version -- or substitute bytes for a tag, which is what the
signature is for.

So this is a freshness gap, not an integrity gap, and it wants a freshness answer. Stating it that
way matters, because it rules out the reflex fix: signing the index response would only move the
same question to "which signed index response is the current one".

## What TUF calls this, and the part worth taking

The Update Framework splits exactly this out as the **timestamp role**: a small, frequently re-signed
document whose only job is to say what is current right now, separate from the documents that say
what a release contains. Its key is online, because something has to re-sign it on a short clock.

Here an online signing key is the one thing that must not exist. The release key is in Cloud KMS and
called from the maintainer's own machine, deliberately unreachable from the release workflow
([§9.4](../ARCHITECTURE.md)), and the entire value of the signature is that the pipeline cannot make
it. Adding a key the pipeline *can* use, to sign the document that decides which release every node
installs, would hand back most of what the arrangement bought.

So take the two properties and not the machinery:

- a **sequence number** that a client refuses to go backwards on, and
- an **expiry**, so that a document that has stopped being re-issued stops being believed.

Both are satisfied by one small file signed with the release key already in use, re-issued by the
same person, from the same machine, on a clock measured in months rather than minutes. The cost of
that choice is the ritual, and it is named in full below.

## Two properties doing two different jobs

This is the decision the rest of the design follows from, so it is worth being blunt about it.

**The sequence number prevents.** With a floor -- the highest sequence this node has seen, and the
version it is running -- an adversary who can publish cannot walk a node backwards, and cannot pin
one that has already seen a newer pointer.

**The expiry detects.** An expired pointer does not mean the bytes are bad; it means nobody can say
whether there is something newer. That is exactly the state a node is in *today*, permanently.

Which is why **an expired pointer must not block a download.** Fail-closed there would be strictly
worse than the behaviour it replaces: the properties protecting the binary -- the signature, the tag
binding, never-below-running, the sequence floor -- all still hold when the pointer is stale, so
refusing would forbid a genuine upgrade in order to avert a risk the refusal does not reduce. An
expired pointer changes what the node *claims*: `update` reports that it cannot tell whether this is
current, and says since when, instead of reporting "you are up to date". The withholding attack goes
from silent to visible, which is the whole of what freshness buys, and it is enough.

## The document

`latest.txt`, signed as `latest.txt.sig`, in the same shape as `RELEASE.txt` for the same reasons:

```
jailscale-index 1
seq: 7
tag: v0.1.10
issued: 2026-09-15T04:00:00Z
expires: 2026-12-14T04:00:00Z
```

**Text, one field per line, format line first.** An unknown field is ignored and an unknown format
line is refused -- §5.4's additive rule, as `RELEASE.txt` already applies it. It also means the
by-hand path in [release-verification.md](../release-verification.md) gains a paragraph rather than a
new procedure: the same `openssl pkeyutl -verify` against the same key.

**It does not carry the digest of that release's `RELEASE.txt`.** It could, and it would buy
nothing: `RELEASE.txt` is signed and names its own tag, so the tag here already pins the whole chain.
What it would add is a second place that has to be updated together with a release, and the failure
mode of forgetting is a fleet that refuses every upgrade.

**Signed with the release key list, not a key of its own.** A separate key is TUF's answer because
TUF's timestamp key is online and has a different exposure; this one has the same exposure, the same
holder and the same rotation problem, so a second key would be a second thing to protect and rotate
for no separation. Rotation follows the rule already written in `ReleaseKey`: during a two-release
rotation the pointer is signed with the old key until the release signed with the new one is out.

## Where it lives

A **fixed release tag**, `release-index`, carrying `latest.txt` and `latest.txt.sig`, re-uploaded
with `gh release upload --clobber`. The URL is `DOWNLOADS + "release-index/latest.txt"` -- the
constant the client already has, with no new host, no new credential, and no second publishing path
to secure. Marked a pre-release so it never becomes what `releases/latest` points at.

Rejected: **GitHub Pages**, which is a new publishing path with its own write surface, for a file
that must be written by the same hand as the release. **An asset of each release**, which cannot
work -- finding the newest release's asset is the question being asked.

**A cached asset is a real failure mode and a harmless one.** Clobbering an asset keeps the URL and
changes the object behind it, so a CDN can serve the previous pointer for a while. That is
indistinguishable from withholding, and it is treated identically: the sequence floor means a stale
copy can never move a node backwards, and the worst it does is delay an upgrade by the cache's life.
It is one more reason the expiry is measured in months.

## What the client does

In order, every step fatal, and none of it reachable from the hub or a flag ([§11.2](../ARCHITECTURE.md)):

1. Fetch `latest.txt` and `latest.txt.sig`; verify against `ReleaseKey.PUBLIC_KEYS`.
2. Parse: format line, `seq`, `tag`, `issued`, `expires`. A missing field is an error, not a default.
3. `seq` must be at least the highest this node has recorded. Below it, the check fails with what it
   saw and what it expected -- this is the one condition worth being loud about, because a
   well-formed signed pointer that went backwards is not a mistake anybody makes by accident.
4. `tag` is what `check` compares with the running version, replacing `tag_name`. The announcement
   is now made from authenticated bytes, which §9.4 notes it is not today.
5. `issued` more than a few minutes in the future, or `expires` past: the result is **"cannot tell"**
   -- an error like any other failed check, with the date -- and not "up to date". `--download`
   proceeds and says it could not establish freshness.
6. Record `seq` when, and only when, every step above passed.

**Where the floor is kept.** `update.json` beside `node.json` in the state directory, written by
atomic rename, holding `{seq, tag, checkedAt}`. Not in `node.json`: `update` runs in the CLI process
precisely so that it answers while the daemon is down ([§9.4](../ARCHITECTURE.md)), and two writers
on the file that holds the MachineKey is not a race worth introducing for a counter.

**A node with no writable state directory keeps the weaker floor**, which is the running version --
the anti-rollback property that exists today. It is the right degradation: `jailscale update` on a
machine with no node at all is a question about a binary, not about a node's history.

**A build carrying no release key cannot check at all**, and says so, where today it checks and only
refuses to download. That is the same rule `--download` already applies -- a check that cannot be
made is not quietly skipped -- and for a fork with no key of its own, a version comparison against
this project's releases was never an answer to anything.

**The GitHub API index is retired**, not kept as a fallback. A fallback to the unsigned answer is the
check being skipped by default, which is the shape this design exists to remove. Losing it also
drops the unauthenticated 60-per-hour rate limit and a JSON dependency from the path.

**The clock is the node's, and it is allowed to be wrong.** A fresh VM with no NTP will find
everything expired and report "cannot tell", which is a false alarm and not an outage -- which is
only true because of the decision above not to gate downloads on the expiry.

## What the maintainer does

`tools/sign-release.sh` gains a last step, after the release is published: fetch the current pointer,
verify it, write the next one with `seq + 1` and the new tag, sign, upload, verify what was uploaded.
**A fetch that fails aborts**, and the script never starts a sequence at 1 on its own -- a pointer
that silently restarts the count is the sequence rule deleted.

`tools/refresh-index.sh` re-issues the same tag with a new `seq`, `issued` and `expires` and nothing
else changed, for the months with no release in them. It is the whole of the recurring ritual: one
command, one KMS call, one upload.

`tools/verify-release.sh` gains a mode that checks the pointer, so `published.yml` can fail the same
way it already does for an unsigned release.

**Ninety days, and a warning at fourteen.** `update` and the daemon's daily check warn while the
pointer is still valid, so the maintainer's own nodes are the reminder. There is no calendar to
depend on and nothing to run in a pipeline -- which is the point, since the thing that could run it
in a pipeline is the thing the key is being kept away from.

## The cost, named

**This puts a recurring manual task on a one-person project, and the failure mode is not neutral.**
If the maintainer stops re-issuing -- busy, or gone -- every node in the field eventually reports
that it cannot tell whether it is current, forever. The design above is bent around making that
outcome survivable rather than unlikely: stale means a different sentence and a warning, upgrades
still work, downloads still verify, and nothing needs the maintainer in order to keep running. The
bet being made is that a permanent "cannot tell", which is honest, is better than today's permanent
"up to date", which is not.

A shorter expiry would detect withholding sooner and raise the ritual proportionally. Ninety days is
chosen against how often this project releases, and it is a number to revisit with evidence, not a
constant with a reason behind it.

## What this does not close

- **A compromised signing key.** Everything here is signed with it. What bounds that is where the key
  lives, the KMS audit log, and the key list being a rotation path ([§9.4](../ARCHITECTURE.md)).
- **A malicious new release.** Freshness says which release is current, never that it is good. The
  boundary there is source review and the maintainer's own clone, which `sign-release.sh` already
  makes a check rather than an assumption.
- **Targeted non-delivery.** An adversary who controls delivery can serve everyone else a fresh
  pointer and this node nothing at all, and a node that fetches nothing cannot tell that from a
  network failure. Expiry turns it into a visible condition eventually; nothing here turns it into
  an immediate one.
- **One channel.** The pointer, the release and the binary all come from the same host. That is a
  deliberate carry-over -- the URLs are compiled in and never come from the hub -- and a second
  channel would be a second thing to publish to and keep honest.

## Steps, each of which leaves a working client

1. **Publish the pointer.** *(built)* `sign-release.sh` writes and uploads it; `refresh-index.sh`
   exists; `verify-release.sh --index` checks it. No client reads it. Nothing in the field changes.
2. **Read it for the announcement.** *(built)* `check` takes the tag from the pointer, `--download`
   is untouched. `status` carries `expiresAt` and whether the pointer is stale.
3. **The sequence floor.** *(built)* `update.json`, the refusal, and the loud message.
4. **Retire the API index** and the `LATEST` constant with it. *(built, with step 2: once the
   pointer is what `check` reads, leaving the unsigned call in place would be dead code that a
   later edit could make load-bearing again -- and the design's own rule is that there is no
   falling back to it.)*
5. **Warnings**: *(built)* fourteen days out in `update` (on stderr, leaving the answer and the exit
   status alone) and once a day in the daemon's log, independent of what the check concluded --
   a pointer can name an upgrade *and* be about to expire, and the second is the one nobody else
   notices. `status` carries `expiresAt`, `stale` and the outcome, so the stale line is there for
   anything reading the JSON. The nightly `index` job in ci.yml checks the published pointer from
   outside -- the reminder that does not depend on anyone running a node -- annotating the run at
   the same fourteen days and failing it once the pointer has expired or stops verifying. The
   fortnight is an annotation rather than a failure because a nightly that is red for fourteen days
   running is one people stop reading.

Steps 1 and 2 are what make the withholding attack visible; 3 is what makes it un-repeatable against
a node that has already seen better. 4 removes the unsigned path that would otherwise be a fallback,
and 5 is what keeps the whole thing from lapsing quietly.

## What is left, and it is not a step

**First contact.** The floor is built from what a node has been told, so a fresh install has nothing
to compare with: it can be handed any genuinely signed, unexpired pointer and started on an older
release, and kept there until that pointer expires. Nothing here closes that, and §15 says so rather
than implying the gap is gone. Closing it needs a floor that ships *in* the binary -- a minimum
sequence compiled in beside `ReleaseKey.PUBLIC_KEYS` and bumped by the same signing ritual -- which
is a different change with its own cost: a release that is never installed leaves every node it
would have raised the floor for exactly where it was.

## What building step 3 settled

- **A node that has never seen a higher sequence can still be given an old pointer.** The floor is
  built from what this node has been told, so first contact has nothing to compare with: a fresh
  install can be handed any genuinely signed, unexpired pointer, and what bounds that is the expiry
  and never-below-running, not the sequence. The floor makes withholding *un-repeatable against a
  node that has already seen better*, which is a different claim from making it impossible.
- **A floor that cannot be read rebuilds itself.** Whoever can corrupt `update.json` is already on
  the machine as that user; refusing to check for updates ever again would be a worse answer than
  taking the next pointer that verifies. An unwritable home is the same story: the check succeeds,
  the floor does not advance, and nothing is raised.
- **The write re-reads first.** The daemon's daily check and a `jailscale update` in a terminal are
  two processes on one file, and the later writer must not carry an older read back over a higher
  number.
- **A refused pointer is not one this node has seen.** The floor is written only after every check
  above it has passed, so a pointer nobody accepted cannot raise the bar for the ones that follow.
- **A sequence starts at 1, in both readers.** A stored zero means "no floor at all", so a pointer
  at zero would be one a node accepted and then remembered as never having seen; `Index.parse` and
  `index_verify` both refuse it rather than leaving the two of them to disagree.
- **A floor that is missing is silent and a floor that is unusable is not.** The first check a node
  ever makes has no file to read, which is normal; a file that is there and cannot be read or
  written is the protection off or frozen, and that is a warning, because nobody would otherwise
  find out. The daemon says a refusal out loud once a day for the same reason -- `status` carries it,
  but nobody runs `status` daily.

## What a review of the whole of it changed

- **A check answers with an outcome, not with two nullable fields.** `Result` carries one of
  current / newer / stale / cannot-tell / refused / unreachable, because both consumers were
  inferring the category and both got it wrong: the daemon read "a sequence went backwards" out of
  `seq > 0` and so warned daily about a `dev` build's "cannot compare", while never saying anything
  about an expired pointer — the one thing the expiry exists to surface. The CLI derived its stream
  and exit status the same way and exited 1 while announcing an upgrade.
- **A clock that disagrees says "cannot tell".** Both documents promised that and the code did the
  opposite: a slow clock produced a hard error. It is the same answer an expiry gives, and the
  upgrade the pointer names is still offered — a clock is not evidence about a release.
- **A release-index that exists and carries no pointer is its own state.** `gh release upload
  --clobber` deletes an asset before it uploads the replacement and loses it if the upload fails, so
  "no assets at all" is a state the publishing step can produce — and reading it as "there is no
  pointer" is what would let `--first` restart the sequence over a fleet that has seen higher. Only
  a release that does not exist authorises a first sequence now; the recovery for the other state is
  to re-issue above what the fleet has seen, or to delete the release on purpose.
- **A pointer needs a key on both lists.** Signing a release is checked against the list the
  *previous* release compiled in, because only older binaries verify it. A pointer is read by nodes
  at every version, including the one it names, so a key only the older list carries publishes a
  pointer every node on the named release refuses. Both lists are checked now, and the fallback for
  a previous release that predates signing — which sign-release.sh always had — is here too.
- **A sequence has one spelling.** `09` is nine to both readers and then kills the next `$(( ))` in
  the shell, after the release it was signing is already out. Both readers refuse it instead.
- **Something runs the expiry check.** The fourteen-day warning was reachable only by a human typing
  a command nobody had a reason to type, which for a scheme whose whole cost is a recurring manual
  act is the wrong place to keep the reminder. The nightly CI run checks the published pointer,
  annotating two weeks out and failing once it has expired.

## What building step 2 settled

- **An expired pointer is reported on stderr and exits 1 when there is nothing newer**, so a script
  can tell "up to date" from "could not tell" the way §9.4 already promises for a check that failed.
  With something newer to fetch, `--download` runs and the caveat rides along on stderr: the exit
  status follows the work that was asked for, not the freshness of the pointer that named it.
- **A future `issued` is an error, not a stale pointer.** Both end in "cannot tell", but they are
  different facts and the message says which one happened -- a clock that is wrong is the node's
  problem to fix, and an expiry that has passed is the maintainer's.
- **`Index.parse` takes the last of a repeated field**, matching `Manifest.parse` and the shell
  tooling, and `UpdateIndexTest` pins both parsers to that in one test. A tool and a node reading
  one signed document differently is the failure worth ruling out.
- **The tag rule is written once.** `Updates.tagOk` is what refuses a tag before it is pasted into a
  URL, and the pointer's tag goes through it too: a name refused in one place and used in the other
  is the gap worth not having.

## What building step 1 settled that the design above did not

- **There is a first pointer, and making it is a separate command.** `refresh-index.sh --first
  vX.Y.Z` is the only way a sequence ever starts, it refuses to run while a pointer exists, and a
  fetch that *fails* is not an absent pointer -- both scripts stop rather than write. "Never starts
  a sequence on its own" is the rule; a bootstrap that a person types is not the script doing it.
- **Only `refresh-index.sh --tag` can move the pointer backwards, and it says what that means
  first.** Signing an older patch after a newer release is out is a thing that happens, and
  `sign-release.sh` leaves the pointer alone in that case rather than quietly un-announcing the
  newer release. Pointing back is safe and sometimes wanted -- a client takes the higher sequence
  and then compares the tag with what it *runs*, so nodes already on the newer release stay there --
  but it is a deliberate act, so it asks.
- **Drafts and pre-releases are refused as targets.** `releases/latest` skips pre-releases and nodes
  only ever followed that, so the pointer must not be the thing that starts steering a fleet onto an
  rc. A draft has no assets to install.
- **The signing key is checked against what the field accepts**, the same rule and the same reader
  as signing a release: the key list the release *before* the named one compiled in, never the named
  one's, which may already carry the next key of a rotation no deployed binary has heard of.
- **`published.yml` skips `release-index`.** Creating that pre-release fires the published-release
  check, which would find no `RELEASE.txt`, take it back into draft, and make the pointer
  unreachable. The guard is one line and the reason is worth the four beside it.
- **`verify-release.sh --index` fails on an expired pointer**, which is the opposite of what the
  client will do, and deliberately: this is the tool a person runs to find out whether the thing
  they maintain needs re-issuing, and there the answer "it expired" is a failure to fix. In a node,
  the same fact changes a sentence and blocks nothing.

## What has to be tested, and what each test has to be able to fail

Following the project's rule that a test has to be able to fail for the reason it exists:

- A pointer with a **lower `seq`** than the recorded one is refused -- and the test fails if the
  comparison is removed, which means the fixture's tag must otherwise be a perfectly good upgrade.
- A pointer whose **signature is over different bytes** is refused, including one genuinely signed
  for a different `seq` (re-signing an old pointer's bytes is the attack).
- An **expired** pointer yields "cannot tell", *and* a download after it still succeeds. The second
  half is the one that catches a well-meaning change to fail closed.
- A pointer for a tag whose `RELEASE.txt` names a **different tag** is still refused by `fetch`'s
  existing check -- the pointer must not become a way around it.
- **No `update.json`** and an unwritable state directory both fall back to the running-version floor
  rather than to no floor.
- The maintainer's script **refuses to start a sequence** when the current pointer cannot be read.
