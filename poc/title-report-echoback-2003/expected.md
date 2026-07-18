# Expected behaviour: title-report-echoback-2003

## Class

Title set-then-report echoback (the original 2003 terminal-emulator command
injection, HD Moore). CVE-2003-0063 (xterm) and siblings.

## What the payload does

1. Sets the terminal's window title to a command string, using an OSC "set window
   title" sequence.
2. Asks the terminal to **report** its window title back, using a "report window
   title" control sequence.

On a **vulnerable** terminal, step 2 writes the title into the terminal's input
stream (as if the user had typed it). At a shell prompt, the injected text plus a
newline runs as a command. On a terminal that never reports the title, or that
strips control characters and newlines from the reported value, nothing is injected.

## Canary-forked (safe) behaviour

The command this corpus sets as the title is **not** harmful. It is:

```
printf %s "$POC_CANARY_TOKEN" > "$POC_CANARY"
```

So if the terminal is vulnerable and the injection executes, the only effect is
that the **canary marker file** (`$POC_CANARY`) is written with the token
`POC-CORPUS-CANARY-FIRED`. Nothing is deleted, opened, or exfiltrated.

## Verdict

- **VULNERABLE**: the canary marker file was written (the reported title was
  injected into the shell and executed).
- **not-vulnerable**: the marker was not written.

The harness runs an always-firing positive control first, so a `not-vulnerable`
verdict is only trusted when the canary machinery is proven to work.

## Reference

HD Moore, "Terminal Emulator Security Issues" (2003):
`https://hdm.io/writing/termulation.txt`
(archive: `http://web.archive.org/web/20260617084903/https://hdm.io/writing/termulation.txt`)
