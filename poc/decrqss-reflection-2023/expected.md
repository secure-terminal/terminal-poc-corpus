# Expected behaviour: decrqss-reflection-2023

## Class

DECRQSS (Request Status String) response reflection -- David Leadbeater's 2023
echoback primitive. CVE-2022-45872 (iTerm2), CVE-2022-47583 (mintty),
CVE-2022-23465 (SwiftTerm).

## What the payload does

Sends a DECRQSS status request (`ESC P $ q <text> ESC \`). On a **vulnerable**
terminal the response echoes the request content back into the terminal's input
stream, near-verbatim -- giving near-arbitrary input injection. At a shell prompt,
the injected text plus a newline runs as a command. A terminal that does not reflect
the request, or that sanitizes control characters and newlines from the response,
injects nothing.

## Canary-forked (safe) behaviour

The `<text>` this corpus places in the request is **not** harmful. It is:

```
printf %s "$POC_CANARY_TOKEN" > "$POC_CANARY"
```

So if the terminal is vulnerable and the injection executes, the only effect is that
the **canary marker file** (`$POC_CANARY`) is written with the token
`POC-CORPUS-CANARY-FIRED`. Nothing is deleted, opened, or exfiltrated.

## Verdict

- **VULNERABLE**: the canary marker file was written (the DECRQSS response was
  injected into the shell and executed).
- **not-vulnerable**: the marker was not written.

The harness runs an always-firing positive control first, so a `not-vulnerable`
verdict is only trusted when the canary machinery is proven to work.

## Reference

David Leadbeater, "ANSI Terminal security in 2023 and finding 10 CVEs" (2023):
`https://dgl.cx/2023/09/ansi-terminal-security`
(archive: `http://web.archive.org/web/20260617084902/https://dgl.cx/2023/09/ansi-terminal-security`)
