# SAFETY

This repository is a **defensive test corpus**: a machine-readable collection of
publicly-disclosed terminal-emulator attack payloads, used to check whether a
terminal is vulnerable to a known class. It is built so that **reading the repo is
safe** and **running a payload is contained**. Read this file before anything else.

## 1. Payloads are stored ENCODED at rest (read-safe)

A terminal attack IS a stream of bytes that, when a terminal renders it, does
something. If we stored those bytes raw, then `cat`, `grep`, `git diff`, or a
GitHub file view would *feed the attack to your terminal* -- the repository itself
would be the weapon.

So every payload is stored **hex-encoded** in a `payload.hex` file (whitespace and
`#` comments ignored). Nothing in this repo, when displayed, emits an escape
sequence or control byte. The only place a payload is ever decoded to live bytes is
the sandbox harness, at run time, inside a disposable VM.

**Never** decode a payload and pipe it to a real terminal. Never `printf` or `echo`
the decoded bytes outside the harness.

## 2. Payloads are CANARY-FORKED (payload-safe)

A raw proof-of-concept often does something destructive to prove code execution
(`rm`, open a calculator, exfiltrate a file). We do not keep those actions. Every
runnable payload is rewritten so that **if the terminal executes the injected
content, it performs one safe, unique, detectable action** -- it writes a marker
token to a file the harness named -- instead of anything harmful.

That is what makes this a *test suite* and not a *weapon*: an entry proves a
vulnerability without being able to cause harm. A payload adapted this way is
marked `modified: true` in its `meta.yaml`, with `original_ref` pointing at the
unmodified upstream description (kept for provenance, never executed).

Each forked payload is reviewed (see the project's `ai-review` gate) to confirm it
**cannot harm a tester** before it is added.

## 3. Payloads run in a SANDBOX VM ONLY (run-safe)

The harness (`harness/run.py`) refuses to run unless it detects it is inside the
project sandbox VM, or an explicit override is set. It decodes a payload, feeds it
to the terminal-under-test running a shell, and checks whether the **canary marker
file** was written. Keep and run payloads in the sandbox VM only.

## 4. The harness self-checks (the machinery cannot silently do nothing)

A secure terminal never lets output inject input, so it never fires the canary --
which is indistinguishable from a *broken harness* that fires nothing and would
therefore call every terminal "secure" (fail-open). To close that gap, the harness
must first run an **always-firing positive control** (EICAR-style): a target known
to fire the canary. If the positive control is not observed, the harness is broken
and the run **fails loud** -- no "not vulnerable" verdict is trusted. `secure-terminal
--test-canary` is one such positive control.

## 5. Scope: public disclosures only

Only publicly-disclosed issues (CVEs, published write-ups) are collected, each with
a source link, a web-archive link, and author attribution. No 0-days.

## In one line

Encoded at rest, canary-forked, sandbox-only, self-checking, public-only.
