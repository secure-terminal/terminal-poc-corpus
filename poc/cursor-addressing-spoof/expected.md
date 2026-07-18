# Expected behaviour: cursor-addressing-spoof

## Class

cursor-addressing-spoof -- documented class

## What the payload does

Cursor addressing (cursor-up + erase-line + rewrite) overwrites earlier output, hiding what was shown. The payload prints the canary token, then repositions and overwrites it with a benign-looking line; on a terminal honouring the controls in line mode, the token is hidden.

## Verification (cursor-spoof)

secure-terminal neutralizes this class; the harness detects a hit via the cursor-spoof mode.

## Reference

https://secure-terminal.github.io
