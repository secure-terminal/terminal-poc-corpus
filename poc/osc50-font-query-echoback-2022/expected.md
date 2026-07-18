# Expected behaviour: osc50-font-query-echoback-2022

## Class

OSC 50 font set-then-query echoback. CVE-2022-45063 (xterm < 375),
CVE-2023-39726 (mintty < 3.6.5). David Leadbeater, 2023.

## What the payload does

1. Sets the terminal font to an attacker-chosen string, using an OSC 50 "set font"
   sequence.
2. Queries the font back, using OSC 50 with `?`.

On a **vulnerable** terminal, step 2 reports the font name into the terminal's input
stream. At a shell prompt -- notably xterm with zsh vi-mode list-expand
(CVE-2022-45063) -- the reflected value plus a newline runs as a command. A terminal
that does not report the font, or strips control characters and newlines from the
report, injects nothing.

## Canary-forked (safe) behaviour

The font string this corpus sets is **not** harmful. It is:

```
printf %s "$POC_CANARY_TOKEN" > "$POC_CANARY"
```

So if the terminal is vulnerable and the injection executes, the only effect is that
the **canary marker file** (`$POC_CANARY`) is written with the token
`POC-CORPUS-CANARY-FIRED`. Nothing is deleted, opened, or exfiltrated.

## Verdict

- **VULNERABLE**: the canary marker file was written (the reported font was injected
  into the shell and executed).
- **not-vulnerable**: the marker was not written.

The harness runs an always-firing positive control first, so a `not-vulnerable`
verdict is only trusted when the canary machinery is proven to work.

## Reference

David Leadbeater, "ANSI Terminal security in 2023 and finding 10 CVEs" (2023):
`https://dgl.cx/2023/09/ansi-terminal-security`
(archive: `http://web.archive.org/web/20260617084902/https://dgl.cx/2023/09/ansi-terminal-security`)
