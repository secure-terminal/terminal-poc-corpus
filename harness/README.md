# harness

`run.py` is the **sandbox-only** runner. Read [../SAFETY.md](../SAFETY.md) first.

## What it does

1. **Refuses to run outside the sandbox VM.** It decodes payloads to live terminal
   bytes, so it requires `POC_CORPUS_IN_SANDBOX=1` (or the project's
   `DIST_AI_IN_SANDBOX=1`); `POC_CORPUS_ALLOW_HOST=1` is a documented override.
2. **Runs an always-firing positive control first** (EICAR-style) and fails loud if
   the canary machinery is not observed -- so a "not vulnerable" result is never a
   false green from a broken harness.
3. For each PoC: decodes `payload.hex`, feeds it to the terminal-under-test via a
   `--feed-template`, and checks whether the canary marker file was written.

## The canary contract

The harness exports two variables into the shell it launches:

- `POC_CANARY` -- the marker file path a fired (canary-forked) payload writes.
- `POC_CANARY_TOKEN` -- the token to write (`POC-CORPUS-CANARY-FIRED`).

A payload is "fired" (the terminal is vulnerable) iff that marker file ends up
containing the token.

## Usage

Self-test the machinery only (no PoCs):

```
POC_CORPUS_IN_SANDBOX=1 ./run.py --self-test
```

Run PoCs against a terminal-under-test. The `--feed-template` is
**terminal-specific** -- it is a shell command with a `{payload}` placeholder (the
path to the decoded payload) that makes the terminal render the payload while a
shell is at a prompt. For example, conceptually:

```
POC_CORPUS_IN_SANDBOX=1 ./run.py \
    --feed-template 'xterm -e sh -c "cat {payload}; read _"' \
    ../poc/title-report-echoback-2003
```

With no PoC arguments it runs the whole `poc/` tree. Exit is informational; the
per-PoC verdict (`VULNERABLE` / `not-vulnerable`) is printed per line.

## Positive control against secure-terminal

`secure-terminal --test-canary` is a ready-made positive control: it deliberately
fires the safe canary, so it can validate a harness end to end before the harness
is trusted to report other terminals "not vulnerable".
