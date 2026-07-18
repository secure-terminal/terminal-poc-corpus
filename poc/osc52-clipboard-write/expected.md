# Expected behaviour: osc52-clipboard-write

## Class

OSC 52 silent clipboard overwrite (paste hijack).
(publicly documented class, no dedicated CVE).

## What the payload does

OSC 52 lets program output SET the system clipboard. A program can silently overwrite your clipboard so your next paste inserts text you did not copy (paste-hijack). This corpus sets it to the BENIGN canary token, so a hit only puts a harmless marker on the clipboard.

## Verification (clipboard-exfil)

Detect a hit via: POC-CORPUS-CANARY-FIRED.

secure-terminal neutralizes this class, so the deception/exfil does not occur.

## Reference

https://secure-terminal.github.io
