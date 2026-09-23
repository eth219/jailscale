# Reporting a security problem

**Do not open a public issue with the details.** Use the **Report a vulnerability** button under
[Security](https://github.com/gosuda/jailscale/security/advisories/new). It opens a private advisory
that only you and the maintainer can read, and it needs no account beyond the GitHub one you already
have.

## What to expect

This is one person's project. An honest expectation is a first reply within a few days and a fix
in the next release, not a published SLA. If you have heard nothing in two weeks, the advisory was
missed rather than ignored: open a public issue that says only "I have filed an advisory", with no
details.

## Which versions get fixes

The **latest release**, and **whatever the live hub at `jailscale.sinabro.io` is running** if that
is older. There is no support matrix behind that sentence; saying so is more useful than implying
one. `docs/release-verification.md` says how to tell which release you have and that it is the one
that was signed.

## What is already known, and is not a finding

[ARCHITECTURE.md §15](docs/ARCHITECTURE.md) lists, at length and on purpose, what this project
cannot do, and [§11](docs/ARCHITECTURE.md) is the security model it lists them against. Read §15
before reporting: a stated limit is a property, not a vulnerability. Two that come up:

- **A compromised hub can impersonate every name under its domain** (§11.2). The hub is the TLS
  authority for its domain, so this is not preventable, only detectable (§11.3). Names that need
  more are user domains, whose keys never reach the hub.
- **Raw TCP and UDP links are not end to end** unless the application encrypts itself (§8.4).

A way to *defeat* one of the controls §11 describes — the self-probe, name revocation, the rate
limits, delegated signing's binding to the visitor's handshake — is very much a finding. So is
anything that touches the release signing chain in `docs/release-verification.md`.

## How a fix travels

GitHub attaches a temporary private fork to an advisory so a fix can be developed unseen. **Actions
do not run in that fork**, so a fix made there gets none of the gate this project relies on for
correctness: the suite on three platforms, SpotBugs, the §14 budget, the load-tagged tests
(ARCHITECTURE.md §3.2 is largely about what each of those exists to catch). The changes with the
least room for a regression would be the ones verified least.

So a fix takes one of two routes, and the report is where that is decided:

1. **Fix in the private fork, then run the full gate on `main` the moment the advisory is
   published**, before or alongside the release that carries it. This is the default. The window
   in which an unverified fix is in the field is real, but short and bounded.
2. **Fix as an ordinary public pull request** when disclosure does not make the flaw materially
   worse — a missing bound, a crash, something §15 already half-states. Most findings against a
   project this size are of that kind, and the private route buys little against the verification
   it costs.

That Actions do not run in the private fork has not yet been confirmed on a real advisory. If they
do, this section collapses to one sentence, and the first real report is when that gets checked.
