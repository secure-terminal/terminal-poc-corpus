# Expected behaviour: mouse-tracking-reflection

## Class

mouse-tracking-reflection (xterm mouse reporting; publicly documented class, no
dedicated CVE).

## What the payload does

Program output enables xterm mouse tracking (DECSET ?1003h any-event + ?1006h SGR
extended). Reporting a REAL user mouse event is a standard feature: xterm, konsole
and secure-terminal all answer a program's tracking request with an ESC[<...M/m
report when the user actually clicks, drags or scrolls. That is the user's own
action reaching the program that asked for it, not injection.

The vuln this class guards is OUTPUT fabricating input -- a write-back caused by the
enable sequence ITSELF, with no user action.

## Verification (mouse-tracking-reflection)

Oracle: feed the DECSET mouse-enable payload to the offscreen widget and spy _write
with NO pointer event posted. A hit = any write-back caused by output alone.

secure-terminal writes nothing from the enable sequence by itself, so output cannot
inject. (Reporting a genuine user event is the intended feature, and Shift keeps an
event local -- both are checked in secure-terminal's own test suite, not this
cross-terminal detector.)

## Reference

https://secure-terminal.github.io
